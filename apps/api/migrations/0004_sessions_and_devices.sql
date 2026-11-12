-- Migration: 0004_sessions_and_devices.sql
--
-- What:
--   1. Makes `devices.name_enc` nullable so `login/finish` can register a device record
--      before the client encrypts and uploads a device nickname.
--   2. Extends `sessions` to support two-stage authentication (Stage 1: password verified,
--      MFA pending; Stage 2: fully authenticated after MFA), hashed opaque access and
--      refresh tokens, 5m/10m access expiry, 24h idle expiry, 7d absolute family expiry,
--      single-use refresh rotation tracking (`used_at`), and direct `user_id` ownership
--      filtering on every query.
--   3. Comments every column on `devices` and `sessions`.
--
-- Why:
--   Enforces server-side opaque session management (PRD Section 7) without storing raw
--   tokens or JWTs, while preserving least-privilege permissions (`vault_app` has no DDL
--   rights and `audit_events` stays append-only).

-- 1. devices: make name_enc nullable
ALTER TABLE devices
    ALTER COLUMN name_enc DROP NOT NULL;

ALTER TABLE devices
    DROP CONSTRAINT chk_devices_name_enc_len,
    ADD CONSTRAINT chk_devices_name_enc_len CHECK (
        name_enc IS NULL OR (octet_length(name_enc) > 0 AND octet_length(name_enc) <= 1024)
    );

COMMENT ON COLUMN devices.id IS 'Primary UUID identifier for the registered device.';
COMMENT ON COLUMN devices.user_id IS 'Owning user account UUID (FK -> users.id ON DELETE CASCADE).';
COMMENT ON COLUMN devices.name_enc IS 'Optional client-encrypted human-readable device label (<= 1024 bytes).';
COMMENT ON COLUMN devices.created_at IS 'Timestamp when the device record was created.';
COMMENT ON COLUMN devices.last_seen_at IS 'Timestamp of the most recent authenticated activity on this device.';
COMMENT ON COLUMN devices.revoked_at IS 'Timestamp when the device was revoked; NULL while active.';

-- 2. sessions: add two-stage auth, access token hash, idle/absolute expiries, and user_id
ALTER TABLE sessions
    ADD COLUMN user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ADD COLUMN stage SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN mfa_verified_at TIMESTAMPTZ,
    ADD COLUMN access_hash BYTEA NOT NULL UNIQUE,
    ADD COLUMN access_expires_at TIMESTAMPTZ NOT NULL,
    ADD COLUMN idle_expires_at TIMESTAMPTZ,
    ADD COLUMN used_at TIMESTAMPTZ,
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE sessions
    RENAME COLUMN expires_at TO refresh_expires_at;

ALTER TABLE sessions
    ALTER COLUMN refresh_hash DROP NOT NULL,
    ALTER COLUMN refresh_expires_at DROP NOT NULL;

ALTER TABLE sessions
    DROP CONSTRAINT chk_sessions_refresh_hash_len,
    ADD CONSTRAINT chk_sessions_refresh_hash_len CHECK (
        refresh_hash IS NULL OR octet_length(refresh_hash) = 32
    ),
    ADD CONSTRAINT chk_sessions_access_hash_len CHECK (
        octet_length(access_hash) = 32
    ),
    ADD CONSTRAINT chk_sessions_stage_valid CHECK (
        stage IN (1, 2)
    ),
    ADD CONSTRAINT chk_sessions_stage_fields CHECK (
        (
            stage = 1
            AND mfa_verified_at IS NULL
            AND refresh_hash IS NULL
            AND refresh_expires_at IS NULL
            AND idle_expires_at IS NULL
        )
        OR
        (
            stage = 2
            AND mfa_verified_at IS NOT NULL
            AND refresh_hash IS NOT NULL
            AND refresh_expires_at IS NOT NULL
            AND idle_expires_at IS NOT NULL
        )
    );

CREATE INDEX idx_sessions_user_id ON sessions(user_id);

COMMENT ON COLUMN sessions.id IS 'Primary UUID identifier for this session token generation.';
COMMENT ON COLUMN sessions.user_id IS 'Owning user account UUID (FK -> users.id ON DELETE CASCADE) for row-level ownership checks.';
COMMENT ON COLUMN sessions.device_id IS 'Bound device UUID (FK -> devices.id ON DELETE CASCADE).';
COMMENT ON COLUMN sessions.family_id IS 'Rotation family UUID shared across all refresh rotations of a single login.';
COMMENT ON COLUMN sessions.stage IS 'Authentication stage: 1 = OPAQUE password verified (MFA pending), 2 = fully authenticated after MFA.';
COMMENT ON COLUMN sessions.mfa_verified_at IS 'Timestamp when second-factor authentication succeeded; NULL in stage 1.';
COMMENT ON COLUMN sessions.access_hash IS 'SHA-256 digest (32 bytes) of the opaque access token; raw token is never stored.';
COMMENT ON COLUMN sessions.access_expires_at IS 'Expiration timestamp of the access token (5 minutes in stage 1, 10 minutes in stage 2).';
COMMENT ON COLUMN sessions.refresh_hash IS 'SHA-256 digest (32 bytes) of the opaque refresh token; NULL in stage 1.';
COMMENT ON COLUMN sessions.refresh_expires_at IS 'Absolute 7-day ceiling timestamp for the session family; NULL in stage 1.';
COMMENT ON COLUMN sessions.idle_expires_at IS 'Sliding 24-hour idle expiration timestamp; NULL in stage 1.';
COMMENT ON COLUMN sessions.used_at IS 'Timestamp when this refresh token generation was rotated; non-NULL reuse triggers family revocation.';
COMMENT ON COLUMN sessions.created_at IS 'Timestamp when this session row was created.';
COMMENT ON COLUMN sessions.revoked_at IS 'Timestamp when this session or its family/device was revoked; NULL while active.';
