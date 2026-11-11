#![forbid(unsafe_code)]

use sqlx::Row;
use std::env;
use std::error::Error;
use strongroom_api::db::{
    connect_pool, create_user, get_item, get_user_by_email_hash, insert_item, list_items,
    soft_delete_item, NewItem, NewUser,
};

fn app_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| {
        String::from("postgres://vault_app:local_app_password_only@127.0.0.1:5432/vault_dev")
    })
}

fn migrator_database_url() -> String {
    env::var("MIGRATOR_DATABASE_URL").unwrap_or_else(|_| {
        String::from(
            "postgres://vault_migrator:local_migrator_password_only@127.0.0.1:5432/vault_dev",
        )
    })
}

async fn setup_pools() -> Result<sqlx::PgPool, Box<dyn Error>> {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env("MIGRATOR_DATABASE_URL", migrator_database_url())
        .status()?;

    if !status.success() {
        return Err(format!("migrate binary failed with status: {status}").into());
    }

    let app_pool = connect_pool(&app_database_url()).await?;
    Ok(app_pool)
}

fn unique_email_hash(tag: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let mut bytes = Vec::with_capacity(32);
    bytes.push(tag);
    bytes.extend_from_slice(&nanos.to_le_bytes());
    while bytes.len() < 32 {
        bytes.push(tag.wrapping_add(bytes.len() as u8));
    }
    Ok(bytes)
}

fn sample_new_user(email_hash: Vec<u8>) -> NewUser {
    NewUser {
        email_hash,
        email_enc: Some(vec![0xAA, 0xBB, 0xCC, 0xDD, 0x01, 0x02]),
        opaque_record: vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60],
        wrapped_km: vec![0x71, 0x72, 0x73, 0x74, 0x75, 0x76],
        wrapped_ks_master: vec![0x81, 0x82, 0x83, 0x84, 0x85, 0x86],
        kdf_params: vec![0x91, 0x92, 0x93, 0x94],
        key_version: 1,
    }
}

fn sample_new_item(user_id: &str, marker: u8) -> NewItem {
    NewItem {
        user_id: String::from(user_id),
        meta_blob: vec![marker, 0xDE, 0xAD, 0xBE, 0xEF, 0x01],
        secret_blob: vec![marker, 0xCA, 0xFE, 0xBA, 0xBE, 0x02],
        wrapped_item_key_m: vec![marker, 0x11, 0x22, 0x33, 0x44],
        wrapped_item_key_s: vec![marker, 0x55, 0x66, 0x77, 0x88],
        version: 1,
        padded_size: 256,
    }
}

#[tokio::test]
async fn cross_user_item_access_is_impossible() -> Result<(), Box<dyn Error>> {
    let app_pool = setup_pools().await?;

    let hash_a = unique_email_hash(0xA1)?;
    let hash_b = unique_email_hash(0xB2)?;

    let user_a = create_user(&app_pool, &sample_new_user(hash_a.clone())).await?;
    let user_b = create_user(&app_pool, &sample_new_user(hash_b.clone())).await?;

    let fetched_a = get_user_by_email_hash(&app_pool, &hash_a)
        .await?
        .ok_or("expected user_a to be found by email_hash")?;
    assert_eq!(fetched_a.id, user_a.id);

    let item_b = insert_item(&app_pool, &sample_new_item(&user_b.id, 0xBB)).await?;

    // 1. User A cannot read User B's item via get_item.
    let cross_get = get_item(&app_pool, &user_a.id, &item_b.id).await?;
    assert_eq!(cross_get, None);

    // 2. User A cannot see User B's item via list_items.
    let user_a_items = list_items(&app_pool, &user_a.id).await?;
    assert!(!user_a_items.iter().any(|item| item.id == item_b.id));

    // 3. User A cannot soft-delete User B's item via soft_delete_item.
    let cross_deleted = soft_delete_item(&app_pool, &user_a.id, &item_b.id).await?;
    assert!(!cross_deleted);

    // Verify User B's item is still intact and readable by User B.
    let owner_get = get_item(&app_pool, &user_b.id, &item_b.id)
        .await?
        .ok_or("expected User B's item to remain intact")?;
    assert_eq!(owner_get.id, item_b.id);
    assert_eq!(owner_get.user_id, user_b.id);
    assert_eq!(owner_get.deleted_at, None);

    let user_b_items = list_items(&app_pool, &user_b.id).await?;
    assert!(user_b_items.iter().any(|item| item.id == item_b.id));

    // Verify User B can soft-delete their own item, and that it is excluded afterwards.
    let owner_deleted = soft_delete_item(&app_pool, &user_b.id, &item_b.id).await?;
    assert!(owner_deleted);
    assert_eq!(get_item(&app_pool, &user_b.id, &item_b.id).await?, None);

    // Verify the soft-deleted row still exists in the table with a non-null deleted_at.
    let deleted_at_present: Option<String> = sqlx::query_scalar(
        "SELECT deleted_at::text FROM items WHERE id = $1::text::uuid AND user_id = $2::text::uuid",
    )
    .bind(&item_b.id)
    .bind(&user_b.id)
    .fetch_one(&app_pool)
    .await?;
    assert!(deleted_at_present.is_some());

    Ok(())
}

#[tokio::test]
async fn vault_app_role_cannot_execute_ddl() -> Result<(), Box<dyn Error>> {
    let app_pool = setup_pools().await?;

    // 1. CREATE TABLE must fail for vault_app.
    let create_res = sqlx::query("CREATE TABLE unauthorized_test_table (id UUID PRIMARY KEY)")
        .execute(&app_pool)
        .await;
    assert!(
        create_res.is_err(),
        "expected vault_app CREATE TABLE to be rejected by PostgreSQL permissions"
    );

    // 2. ALTER TABLE must fail for vault_app.
    let alter_res = sqlx::query("ALTER TABLE items ADD COLUMN unauthorized_col TEXT")
        .execute(&app_pool)
        .await;
    assert!(
        alter_res.is_err(),
        "expected vault_app ALTER TABLE to be rejected by PostgreSQL permissions"
    );

    // 3. DROP TABLE must fail for vault_app.
    let drop_res = sqlx::query("DROP TABLE items").execute(&app_pool).await;
    assert!(
        drop_res.is_err(),
        "expected vault_app DROP TABLE to be rejected by PostgreSQL permissions"
    );

    // 4. The migrate binary must refuse to run under the vault_app role.
    let migrate_as_app = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env("MIGRATOR_DATABASE_URL", app_database_url())
        .output()?;
    assert!(
        !migrate_as_app.status.success(),
        "expected migrate binary to refuse running as vault_app"
    );

    Ok(())
}

#[tokio::test]
async fn vault_app_role_cannot_update_or_delete_audit_events() -> Result<(), Box<dyn Error>> {
    let app_pool = setup_pools().await?;

    let user = create_user(&app_pool, &sample_new_user(unique_email_hash(0xC3)?)).await?;
    let ip_hash: Vec<u8> = vec![0x5A; 32];

    // vault_app is allowed to INSERT and SELECT on audit_events.
    let event_id: String = sqlx::query_scalar(
        r#"
        INSERT INTO audit_events (user_id, type, ip_hash)
        VALUES ($1::text::uuid, 'login_succeeded', $2)
        RETURNING id::text
        "#,
    )
    .bind(&user.id)
    .bind(&ip_hash)
    .fetch_one(&app_pool)
    .await?;

    let selected_type: String =
        sqlx::query_scalar("SELECT type FROM audit_events WHERE id = $1::text::uuid")
            .bind(&event_id)
            .fetch_one(&app_pool)
            .await?;
    assert_eq!(selected_type, "login_succeeded");

    // 1. UPDATE on audit_events must fail for vault_app.
    let update_res =
        sqlx::query("UPDATE audit_events SET type = 'tampered_event' WHERE id = $1::text::uuid")
            .bind(&event_id)
            .execute(&app_pool)
            .await;
    assert!(
        update_res.is_err(),
        "expected vault_app UPDATE on audit_events to be rejected"
    );

    // 2. DELETE on audit_events must fail for vault_app.
    let delete_res = sqlx::query("DELETE FROM audit_events WHERE id = $1::text::uuid")
        .bind(&event_id)
        .execute(&app_pool)
        .await;
    assert!(
        delete_res.is_err(),
        "expected vault_app DELETE on audit_events to be rejected"
    );

    // 3. Deleting the user cascades to user-owned data, but audit_events survives with user_id = NULL.
    sqlx::query("DELETE FROM users WHERE id = $1::text::uuid")
        .bind(&user.id)
        .execute(&app_pool)
        .await?;

    let surviving_user_id: Option<String> =
        sqlx::query_scalar("SELECT user_id::text FROM audit_events WHERE id = $1::text::uuid")
            .bind(&event_id)
            .fetch_one(&app_pool)
            .await?;
    assert_eq!(surviving_user_id, None);

    Ok(())
}

#[tokio::test]
async fn database_stores_only_opaque_bytes_and_no_plaintext() -> Result<(), Box<dyn Error>> {
    let app_pool = setup_pools().await?;

    // Simulated plaintext values that exist ONLY in the browser before encryption/hashing.
    // None of these strings (or their hex encodings) are ever passed to the server or DB.
    let forbidden_plaintexts = [
        "alice.zero.knowledge@example.com",
        "CorrectHorseBatteryStaple!2026",
        "A3-7K9M2P-4X8Q1W-9Z2C6V",
        "Production Bank Vault Login",
        "https://bank.example.com/login",
        "alice_bank_username",
        "super-secret-item-password-987654321",
        "JBSWY3DPEHPK3PXP",
    ];

    // Pre-encrypted / pre-hashed opaque bytes supplied to the database layer.
    let opaque_email_hash = unique_email_hash(0xD4)?;
    let opaque_email_enc = vec![0xE1, 0x04, 0x99, 0xAC, 0x3B, 0x7F, 0x12, 0x8E];
    let opaque_record = vec![0x02, 0xF0, 0x8A, 0x19, 0x4C, 0x6D, 0x7E, 0x33];
    let opaque_wrapped_km = vec![0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17];
    let opaque_wrapped_ks = vec![0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F];
    let opaque_kdf_params = vec![0x01, 0x00, 0x10, 0x00, 0x03, 0x01];

    let user = create_user(
        &app_pool,
        &NewUser {
            email_hash: opaque_email_hash.clone(),
            email_enc: Some(opaque_email_enc.clone()),
            opaque_record: opaque_record.clone(),
            wrapped_km: opaque_wrapped_km.clone(),
            wrapped_ks_master: opaque_wrapped_ks.clone(),
            kdf_params: opaque_kdf_params.clone(),
            key_version: 1,
        },
    )
    .await?;

    let opaque_meta_blob = vec![0x9A, 0xBC, 0xDE, 0xF0, 0x13, 0x57, 0x24, 0x68];
    let opaque_secret_blob = vec![0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
    let opaque_item_key_m = vec![0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93];
    let opaque_item_key_s = vec![0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45];

    let item = insert_item(
        &app_pool,
        &NewItem {
            user_id: user.id.clone(),
            meta_blob: opaque_meta_blob.clone(),
            secret_blob: opaque_secret_blob.clone(),
            wrapped_item_key_m: opaque_item_key_m.clone(),
            wrapped_item_key_s: opaque_item_key_s.clone(),
            version: 1,
            padded_size: 256,
        },
    )
    .await?;

    // Verify stored bytes match the exact opaque slices supplied.
    assert_eq!(user.email_hash, opaque_email_hash);
    assert_eq!(user.email_enc, Some(opaque_email_enc));
    assert_eq!(user.opaque_record, opaque_record);
    assert_eq!(user.wrapped_km, opaque_wrapped_km);
    assert_eq!(user.wrapped_ks_master, opaque_wrapped_ks);
    assert_eq!(user.kdf_params, opaque_kdf_params);
    assert_eq!(item.meta_blob, opaque_meta_blob);
    assert_eq!(item.secret_blob, opaque_secret_blob);
    assert_eq!(item.wrapped_item_key_m, opaque_item_key_m);
    assert_eq!(item.wrapped_item_key_s, opaque_item_key_s);

    // Dump every column of every application table in `public` and verify no plaintext appears.
    let tables = [
        "users",
        "devices",
        "sessions",
        "passkeys",
        "totp",
        "recovery_codes",
        "items",
        "audit_events",
    ];

    for table in tables {
        let col_rows = sqlx::query(
            r#"
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'public' AND table_name = $1
            ORDER BY ordinal_position
            "#,
        )
        .bind(table)
        .fetch_all(&app_pool)
        .await?;

        assert!(
            !col_rows.is_empty(),
            "expected table {table} to exist with columns in public schema"
        );

        let mut projections = Vec::with_capacity(col_rows.len());
        for col_row in &col_rows {
            let col_name: String = col_row.try_get("column_name")?;
            projections.push(format!("COALESCE({col_name}::text, '') AS {col_name}"));
        }

        let dump_sql = format!("SELECT {} FROM {table}", projections.join(", "));
        let data_rows = sqlx::query(sqlx::AssertSqlSafe(dump_sql))
            .fetch_all(&app_pool)
            .await?;

        for row in data_rows {
            for idx in 0..col_rows.len() {
                let cell_value: String = row.try_get(idx)?;
                for plaintext in forbidden_plaintexts {
                    assert!(
                        !cell_value.contains(plaintext),
                        "plaintext found in table {table}"
                    );
                }
            }
        }
    }

    // Also verify the 64 KiB CHECK constraint on items.meta_blob and items.secret_blob.
    let oversized_blob = vec![0x42u8; 65_537];
    let oversized_meta_res = insert_item(
        &app_pool,
        &NewItem {
            user_id: user.id.clone(),
            meta_blob: oversized_blob.clone(),
            secret_blob: vec![0x01, 0x02],
            wrapped_item_key_m: vec![0x03, 0x04],
            wrapped_item_key_s: vec![0x05, 0x06],
            version: 1,
            padded_size: 256,
        },
    )
    .await;
    assert!(
        oversized_meta_res.is_err(),
        "expected meta_blob > 64 KiB to be rejected by CHECK constraint"
    );

    let oversized_secret_res = insert_item(
        &app_pool,
        &NewItem {
            user_id: user.id.clone(),
            meta_blob: vec![0x01, 0x02],
            secret_blob: oversized_blob,
            wrapped_item_key_m: vec![0x03, 0x04],
            wrapped_item_key_s: vec![0x05, 0x06],
            version: 1,
            padded_size: 256,
        },
    )
    .await;
    assert!(
        oversized_secret_res.is_err(),
        "expected secret_blob > 64 KiB to be rejected by CHECK constraint"
    );

    Ok(())
}
