#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::fmt;

/// Raw byte length of an opaque access or refresh token (256 bits).
pub const TOKEN_BYTES: usize = 32;

/// 32-byte random opaque token.
/// Zeroed on drop and never prints raw secret bytes in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken([u8; TOKEN_BYTES]);

impl SessionToken {
    /// Generates a fresh 32-byte random token from `OsRng`.
    pub fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps an already-decoded 32-byte token.
    pub const fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    /// Computes the SHA-256 hash stored server-side in `sessions`.
    pub fn sha256(&self) -> [u8; 32] {
        hash_token_bytes(&self.0)
    }

    /// Encodes the token as a 43-character unpadded base64url string for cookies.
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl Drop for SessionToken {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Computes the SHA-256 digest of a 32-byte opaque token.
pub fn hash_token_bytes(token_bytes: &[u8; TOKEN_BYTES]) -> [u8; 32] {
    Sha256::digest(token_bytes).into()
}

/// Result of creating a Stage 1 (password-verified, MFA-pending) session.
pub struct Stage1Issued {
    pub access_token: SessionToken,
    pub session_id: String,
    pub device_id: String,
    pub family_id: String,
}

impl fmt::Debug for Stage1Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stage1Issued")
            .field("access_token", &self.access_token)
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("family_id", &self.family_id)
            .finish()
    }
}

/// Result of issuing or rotating a Stage 2 (fully authenticated) session token pair.
pub struct SessionTokenPair {
    pub access_token: SessionToken,
    pub refresh_token: SessionToken,
    pub session_id: String,
    pub device_id: String,
    pub family_id: String,
}

impl fmt::Debug for SessionTokenPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTokenPair")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("family_id", &self.family_id)
            .finish()
    }
}

/// Session identity yielded by the authentication extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSession {
    pub user_id: String,
    pub device_id: String,
    pub session_id: String,
    pub family_id: String,
    pub stage: i16,
}

/// Device metadata row returned by `GET /auth/devices`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: String,
    pub name_enc: Option<Vec<u8>>,
    pub created_at: String,
    pub last_seen_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug)]
pub enum SessionError {
    Unauthorized,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for SessionError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

/// Resolves an existing active device owned by `user_id` or creates a new one,
/// then inserts a Stage 1 session valid for 5 minutes (no refresh token).
pub async fn create_stage1_session(
    pool: &PgPool,
    user_id: &str,
    requested_device_id: Option<&str>,
) -> Result<Stage1Issued, SessionError> {
    let access_token = SessionToken::generate();
    let access_hash = access_token.sha256();

    let mut tx = pool.begin().await?;

    let device_id: String = if let Some(req_dev_id) = requested_device_id {
        let reused: Option<String> = sqlx::query_scalar!(
            r#"
            UPDATE devices
            SET last_seen_at = now()
            WHERE id = $1::text::uuid
              AND user_id = $2::text::uuid
              AND revoked_at IS NULL
            RETURNING id::text AS "id!"
            "#,
            req_dev_id,
            user_id,
        )
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(existing_id) = reused {
            existing_id
        } else {
            sqlx::query_scalar!(
                r#"
                INSERT INTO devices (user_id, name_enc)
                VALUES ($1::text::uuid, NULL)
                RETURNING id::text AS "id!"
                "#,
                user_id,
            )
            .fetch_one(&mut *tx)
            .await?
        }
    } else {
        sqlx::query_scalar!(
            r#"
            INSERT INTO devices (user_id, name_enc)
            VALUES ($1::text::uuid, NULL)
            RETURNING id::text AS "id!"
            "#,
            user_id,
        )
        .fetch_one(&mut *tx)
        .await?
    };

    let inserted = sqlx::query!(
        r#"
        INSERT INTO sessions (
            user_id,
            device_id,
            family_id,
            stage,
            mfa_verified_at,
            access_hash,
            access_expires_at,
            refresh_hash,
            refresh_expires_at,
            idle_expires_at
        )
        VALUES (
            $1::text::uuid,
            $2::text::uuid,
            gen_random_uuid(),
            1,
            NULL,
            $3,
            now() + interval '5 minutes',
            NULL,
            NULL,
            NULL
        )
        RETURNING
            id::text AS "id!",
            family_id::text AS "family_id!"
        "#,
        user_id,
        &device_id,
        &access_hash[..],
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Stage1Issued {
        access_token,
        session_id: inserted.id,
        device_id,
        family_id: inserted.family_id,
    })
}

/// Upgrades a valid, non-expired Stage 1 session to Stage 2 after second-factor verification.
///
/// Rotates the access token (10-minute lifetime), issues a rotating refresh token (7-day absolute
/// limit, 24-hour idle limit), and invalidates the Stage 1 access token hash immediately.
pub async fn upgrade_session_after_mfa(
    pool: &PgPool,
    user_id: &str,
    session_id: &str,
) -> Result<SessionTokenPair, SessionError> {
    let access_token = SessionToken::generate();
    let refresh_token = SessionToken::generate();
    let access_hash = access_token.sha256();
    let refresh_hash = refresh_token.sha256();

    let mut tx = pool.begin().await?;

    let locked = sqlx::query!(
        r#"
        SELECT
            s.device_id::text AS "device_id!",
            s.family_id::text AS "family_id!"
        FROM sessions s
        INNER JOIN devices d
            ON d.id = s.device_id
           AND d.user_id = s.user_id
        WHERE s.id = $1::text::uuid
          AND s.user_id = $2::text::uuid
          AND s.stage = 1
          AND s.revoked_at IS NULL
          AND s.used_at IS NULL
          AND s.access_expires_at > now()
          AND d.revoked_at IS NULL
        FOR UPDATE OF s
        "#,
        session_id,
        user_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = locked else {
        tx.rollback().await?;
        return Err(SessionError::Unauthorized);
    };

    let updated = sqlx::query!(
        r#"
        UPDATE sessions
        SET stage = 2,
            mfa_verified_at = now(),
            access_hash = $3,
            access_expires_at = now() + interval '10 minutes',
            refresh_hash = $4,
            refresh_expires_at = now() + interval '7 days',
            idle_expires_at = now() + interval '24 hours'
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
          AND stage = 1
          AND revoked_at IS NULL
        "#,
        session_id,
        user_id,
        &access_hash[..],
        &refresh_hash[..],
    )
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() != 1 {
        tx.rollback().await?;
        return Err(SessionError::Unauthorized);
    }

    sqlx::query!(
        r#"
        UPDATE devices
        SET last_seen_at = now()
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
          AND revoked_at IS NULL
        "#,
        &row.device_id,
        user_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(SessionTokenPair {
        access_token,
        refresh_token,
        session_id: String::from(session_id),
        device_id: row.device_id,
        family_id: row.family_id,
    })
}

/// Rotates a Stage 2 refresh token, issuing a new access + refresh pair in the same family.
///
/// If the presented refresh token was already marked `used_at IS NOT NULL`, reuse detection
/// immediately revokes the entire `family_id` (including the newest token) and returns
/// `SessionError::Unauthorized`.
pub async fn refresh_session(
    pool: &PgPool,
    refresh_token_bytes: &[u8; TOKEN_BYTES],
) -> Result<SessionTokenPair, SessionError> {
    let refresh_hash = hash_token_bytes(refresh_token_bytes);
    let mut tx = pool.begin().await?;

    let found = sqlx::query!(
        r#"
        SELECT
            s.id::text AS "id!",
            s.user_id::text AS "user_id!",
            s.device_id::text AS "device_id!",
            s.family_id::text AS "family_id!",
            s.stage,
            (s.mfa_verified_at IS NOT NULL) AS "has_mfa!",
            (s.used_at IS NOT NULL) AS "is_used!",
            (s.revoked_at IS NOT NULL) AS "is_revoked!",
            (d.revoked_at IS NOT NULL) AS "device_is_revoked!",
            (s.refresh_expires_at IS NULL OR now() >= s.refresh_expires_at) AS "is_refresh_expired!",
            (s.idle_expires_at IS NULL OR now() >= s.idle_expires_at) AS "is_idle_expired!"
        FROM sessions s
        INNER JOIN devices d
            ON d.id = s.device_id
           AND d.user_id = s.user_id
        WHERE s.refresh_hash = $1
        FOR UPDATE OF s
        "#,
        &refresh_hash[..],
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = found else {
        tx.rollback().await?;
        return Err(SessionError::Unauthorized);
    };

    // Reuse detection: any replay of an already-rotated refresh token revokes the entire family.
    if row.is_used {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET revoked_at = COALESCE(revoked_at, now())
            WHERE user_id = $1::text::uuid
              AND family_id = $2::text::uuid
            "#,
            &row.user_id,
            &row.family_id,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Err(SessionError::Unauthorized);
    }

    if row.is_revoked
        || row.device_is_revoked
        || row.stage != 2
        || !row.has_mfa
        || row.is_refresh_expired
        || row.is_idle_expired
    {
        tx.rollback().await?;
        return Err(SessionError::Unauthorized);
    }

    let new_access_token = SessionToken::generate();
    let new_refresh_token = SessionToken::generate();
    let new_access_hash = new_access_token.sha256();
    let new_refresh_hash = new_refresh_token.sha256();

    sqlx::query!(
        r#"
        UPDATE sessions
        SET used_at = now()
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
        "#,
        &row.id,
        &row.user_id,
    )
    .execute(&mut *tx)
    .await?;

    // Preserve the family's original mfa_verified_at and 7-day absolute refresh_expires_at ceiling;
    // reset idle_expires_at to 24 hours from now and access_expires_at to 10 minutes from now.
    let new_session_id: String = sqlx::query_scalar!(
        r#"
        INSERT INTO sessions (
            user_id,
            device_id,
            family_id,
            stage,
            mfa_verified_at,
            access_hash,
            access_expires_at,
            refresh_hash,
            refresh_expires_at,
            idle_expires_at
        )
        SELECT
            user_id,
            device_id,
            family_id,
            2,
            mfa_verified_at,
            $3,
            now() + interval '10 minutes',
            $4,
            refresh_expires_at,
            now() + interval '24 hours'
        FROM sessions
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
        RETURNING id::text AS "id!"
        "#,
        &row.id,
        &row.user_id,
        &new_access_hash[..],
        &new_refresh_hash[..],
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        r#"
        UPDATE devices
        SET last_seen_at = now()
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
          AND revoked_at IS NULL
        "#,
        &row.device_id,
        &row.user_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(SessionTokenPair {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        session_id: new_session_id,
        device_id: row.device_id,
        family_id: row.family_id,
    })
}

/// Resolves an opaque access token by SHA-256 hash lookup joined with an active device
/// and an active, non-expired, non-idle-expired session.
pub async fn resolve_access_session(
    pool: &PgPool,
    access_token_bytes: &[u8; TOKEN_BYTES],
) -> Result<AuthenticatedSession, SessionError> {
    let access_hash = hash_token_bytes(access_token_bytes);

    let row = sqlx::query!(
        r#"
        SELECT
            s.id::text AS "session_id!",
            s.user_id::text AS "user_id!",
            s.device_id::text AS "device_id!",
            s.family_id::text AS "family_id!",
            s.stage
        FROM sessions s
        INNER JOIN devices d
            ON d.id = s.device_id
           AND d.user_id = s.user_id
        WHERE s.access_hash = $1
          AND s.revoked_at IS NULL
          AND s.used_at IS NULL
          AND s.access_expires_at > now()
          AND (
              s.stage = 1
              OR (
                  s.stage = 2
                  AND s.mfa_verified_at IS NOT NULL
                  AND s.refresh_expires_at IS NOT NULL
                  AND s.refresh_expires_at > now()
                  AND s.idle_expires_at IS NOT NULL
                  AND s.idle_expires_at > now()
              )
          )
          AND d.revoked_at IS NULL
        "#,
        &access_hash[..],
    )
    .fetch_optional(pool)
    .await?;

    let Some(session) = row else {
        return Err(SessionError::Unauthorized);
    };

    if session.stage == 2 {
        sqlx::query!(
            r#"
            UPDATE sessions
            SET idle_expires_at = now() + interval '24 hours'
            WHERE id = $1::text::uuid
              AND user_id = $2::text::uuid
              AND stage = 2
              AND revoked_at IS NULL
              AND used_at IS NULL
            "#,
            &session.session_id,
            &session.user_id,
        )
        .execute(pool)
        .await?;
    }

    sqlx::query!(
        r#"
        UPDATE devices
        SET last_seen_at = now()
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
          AND revoked_at IS NULL
        "#,
        &session.device_id,
        &session.user_id,
    )
    .execute(pool)
    .await?;

    Ok(AuthenticatedSession {
        user_id: session.user_id,
        device_id: session.device_id,
        session_id: session.session_id,
        family_id: session.family_id,
        stage: session.stage,
    })
}

/// Revokes every session in `family_id` owned by `user_id`.
pub async fn logout_session_family(
    pool: &PgPool,
    user_id: &str,
    family_id: &str,
) -> Result<(), SessionError> {
    sqlx::query!(
        r#"
        UPDATE sessions
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE user_id = $1::text::uuid
          AND family_id = $2::text::uuid
        "#,
        user_id,
        family_id,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Lists all devices owned by `user_id`.
pub async fn list_user_devices(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query_as!(
        DeviceRow,
        r#"
        SELECT
            id::text AS "id!",
            name_enc,
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "created_at!",
            to_char(last_seen_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "last_seen_at!",
            to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS "revoked_at"
        FROM devices
        WHERE user_id = $1::text::uuid
        ORDER BY created_at DESC, id DESC
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

/// Revokes a specific active device owned by `user_id` and all sessions bound to it.
/// Returns `Ok(true)` if the device existed, belonged to `user_id`, and was not yet revoked.
pub async fn revoke_device_and_sessions(
    pool: &PgPool,
    user_id: &str,
    device_id: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let dev_res = sqlx::query!(
        r#"
        UPDATE devices
        SET revoked_at = now()
        WHERE id = $1::text::uuid
          AND user_id = $2::text::uuid
          AND revoked_at IS NULL
        "#,
        device_id,
        user_id,
    )
    .execute(&mut *tx)
    .await?;

    if dev_res.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }

    sqlx::query!(
        r#"
        UPDATE sessions
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE device_id = $1::text::uuid
          AND user_id = $2::text::uuid
        "#,
        device_id,
        user_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(true)
}
