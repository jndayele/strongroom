#![forbid(unsafe_code)]

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions, PgPool};
use std::str::FromStr;
use std::time::Duration;

/// Maximum number of concurrent connections in the application database pool.
pub const POOL_MAX_CONNECTIONS: u32 = 10;

/// Minimum number of idle connections maintained by the pool.
pub const POOL_MIN_CONNECTIONS: u32 = 1;

/// Maximum time to wait when acquiring a connection from the pool.
pub const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time an unused connection may remain idle before being closed.
pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum total lifetime of any pooled database connection.
pub const POOL_MAX_LIFETIME: Duration = Duration::from_secs(1800);

/// Input payload for creating a new user record.
/// All byte fields must already be client-side ciphertext, wrapped keys, or hashes.
/// `email_enc` is `None` at initial OPAQUE signup and populated later during email verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    pub email_hash: Vec<u8>,
    pub email_enc: Option<Vec<u8>>,
    pub opaque_record: Vec<u8>,
    pub wrapped_km: Vec<u8>,
    pub wrapped_ks_master: Vec<u8>,
    pub kdf_params: Vec<u8>,
    pub key_version: i32,
}

/// Stored user row returned from the `users` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    pub id: String,
    pub email_hash: Vec<u8>,
    pub email_enc: Option<Vec<u8>>,
    pub opaque_record: Vec<u8>,
    pub wrapped_km: Vec<u8>,
    pub wrapped_ks_master: Vec<u8>,
    pub kdf_params: Vec<u8>,
    pub key_version: i32,
    pub created_at: String,
}

/// Input payload for inserting a new encrypted vault item.
/// Both `meta_blob` and `secret_blob` must be client-encrypted envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewItem {
    pub user_id: String,
    pub meta_blob: Vec<u8>,
    pub secret_blob: Vec<u8>,
    pub wrapped_item_key_m: Vec<u8>,
    pub wrapped_item_key_s: Vec<u8>,
    pub version: i32,
    pub padded_size: i32,
}

/// Stored vault item row returned from the `items` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRecord {
    pub id: String,
    pub user_id: String,
    pub meta_blob: Vec<u8>,
    pub secret_blob: Vec<u8>,
    pub wrapped_item_key_m: Vec<u8>,
    pub wrapped_item_key_s: Vec<u8>,
    pub version: i32,
    pub padded_size: i32,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

/// Creates a PostgreSQL connection pool configured with connection limits, timeouts, and
/// SQLx statement logging disabled (`log_statements` / `log_slow_statements` set to `Off`)
/// so per-query row counts (`rows_returned`) never leak account existence into logs.
/// In normal operation, `database_url` connects as the least-privilege `vault_app` role.
pub async fn connect_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let connect_options = PgConnectOptions::from_str(database_url)?.disable_statement_logging();

    PgPoolOptions::new()
        .max_connections(POOL_MAX_CONNECTIONS)
        .min_connections(POOL_MIN_CONNECTIONS)
        .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
        .idle_timeout(POOL_IDLE_TIMEOUT)
        .max_lifetime(POOL_MAX_LIFETIME)
        .connect_with(connect_options)
        .await
}

/// Inserts a new user record and returns the stored row.
pub async fn create_user(pool: &PgPool, input: &NewUser) -> Result<UserRecord, sqlx::Error> {
    sqlx::query_as!(
        UserRecord,
        r#"
        INSERT INTO users (
            email_hash,
            email_enc,
            opaque_record,
            wrapped_km,
            wrapped_ks_master,
            kdf_params,
            key_version
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING
            id::text AS "id!",
            email_hash,
            email_enc,
            opaque_record,
            wrapped_km,
            wrapped_ks_master,
            kdf_params,
            key_version,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!"
        "#,
        &input.email_hash,
        input.email_enc.as_deref(),
        &input.opaque_record,
        &input.wrapped_km,
        &input.wrapped_ks_master,
        &input.kdf_params,
        input.key_version,
    )
    .fetch_one(pool)
    .await
}

/// Inserts a new user record if `email_hash` does not already exist.
///
/// Uses `ON CONFLICT (email_hash) DO NOTHING` so an existing account is never overwritten or
/// modified, and both new and duplicate signups execute the exact same database path.
pub async fn create_user_on_conflict_do_nothing(
    pool: &PgPool,
    input: &NewUser,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO users (
            email_hash,
            email_enc,
            opaque_record,
            wrapped_km,
            wrapped_ks_master,
            kdf_params,
            key_version
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (email_hash) DO NOTHING
        "#,
        &input.email_hash,
        input.email_enc.as_deref(),
        &input.opaque_record,
        &input.wrapped_km,
        &input.wrapped_ks_master,
        &input.kdf_params,
        input.key_version,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Looks up a user by `email_hash`. Returns `Ok(None)` if no matching user exists.
pub async fn get_user_by_email_hash(
    pool: &PgPool,
    email_hash: &[u8],
) -> Result<Option<UserRecord>, sqlx::Error> {
    sqlx::query_as!(
        UserRecord,
        r#"
        SELECT
            id::text AS "id!",
            email_hash,
            email_enc,
            opaque_record,
            wrapped_km,
            wrapped_ks_master,
            kdf_params,
            key_version,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!"
        FROM users
        WHERE email_hash = $1
        "#,
        email_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Inserts a new encrypted item belonging to `input.user_id` and returns the stored row.
pub async fn insert_item(pool: &PgPool, input: &NewItem) -> Result<ItemRecord, sqlx::Error> {
    sqlx::query_as!(
        ItemRecord,
        r#"
        INSERT INTO items (
            user_id,
            meta_blob,
            secret_blob,
            wrapped_item_key_m,
            wrapped_item_key_s,
            version,
            padded_size
        )
        VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
        RETURNING
            id::text AS "id!",
            user_id::text AS "user_id!",
            meta_blob,
            secret_blob,
            wrapped_item_key_m,
            wrapped_item_key_s,
            version,
            padded_size,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!",
            to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "updated_at!",
            to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "deleted_at"
        "#,
        &input.user_id,
        &input.meta_blob,
        &input.secret_blob,
        &input.wrapped_item_key_m,
        &input.wrapped_item_key_s,
        input.version,
        input.padded_size,
    )
    .fetch_one(pool)
    .await
}

/// Fetches a single active (non-deleted) item by both `user_id` and `item_id`.
/// Enforces ownership in SQL (`WHERE user_id = $1 AND id = $2 AND deleted_at IS NULL`).
pub async fn get_item(
    pool: &PgPool,
    user_id: &str,
    item_id: &str,
) -> Result<Option<ItemRecord>, sqlx::Error> {
    sqlx::query_as!(
        ItemRecord,
        r#"
        SELECT
            id::text AS "id!",
            user_id::text AS "user_id!",
            meta_blob,
            secret_blob,
            wrapped_item_key_m,
            wrapped_item_key_s,
            version,
            padded_size,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!",
            to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "updated_at!",
            to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "deleted_at"
        FROM items
        WHERE user_id = $1::text::uuid
          AND id = $2::text::uuid
          AND deleted_at IS NULL
        "#,
        user_id,
        item_id,
    )
    .fetch_optional(pool)
    .await
}

/// Lists all active (non-deleted) items owned by `user_id`.
/// Enforces ownership in SQL (`WHERE user_id = $1 AND deleted_at IS NULL`).
pub async fn list_items(pool: &PgPool, user_id: &str) -> Result<Vec<ItemRecord>, sqlx::Error> {
    sqlx::query_as!(
        ItemRecord,
        r#"
        SELECT
            id::text AS "id!",
            user_id::text AS "user_id!",
            meta_blob,
            secret_blob,
            wrapped_item_key_m,
            wrapped_item_key_s,
            version,
            padded_size,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!",
            to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "updated_at!",
            to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "deleted_at"
        FROM items
        WHERE user_id = $1::text::uuid
          AND deleted_at IS NULL
        ORDER BY created_at DESC, id DESC
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

/// Soft-deletes an active item owned by `user_id` by setting `deleted_at = now()`.
/// Enforces ownership in SQL (`WHERE user_id = $1 AND id = $2 AND deleted_at IS NULL`).
/// Returns `Ok(true)` if a row was soft-deleted, or `Ok(false)` if not found / not owned / already deleted.
pub async fn soft_delete_item(
    pool: &PgPool,
    user_id: &str,
    item_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        UPDATE items
        SET deleted_at = now(),
            updated_at = now()
        WHERE user_id = $1::text::uuid
          AND id = $2::text::uuid
          AND deleted_at IS NULL
        "#,
        user_id,
        item_id,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() == 1)
}
