-- Migration: 0001_initial_schema.sql
--
-- What:
--   Creates the core PostgreSQL tables for the Strongroom zero-knowledge password vault
--   as specified in Section 12 of docs/PRD.md:
--     1. users
--     2. devices
--     3. sessions
--     4. passkeys
--     5. totp
--     6. recovery_codes
--     7. items
--     8. audit_events
--
-- Why:
--   Enforces the zero-knowledge data model at the database boundary:
--   - All encrypted payloads, wrapped keys, OPAQUE records, and cryptographic hashes are stored
--     as `BYTEA` with explicit `CHECK` constraints bounding minimum and maximum byte lengths
--     (e.g., `meta_blob` and `secret_blob` are capped at 64 KiB / 65536 bytes).
--   - All primary keys use `UUID` (`gen_random_uuid()`) and all timestamps use `TIMESTAMPTZ`.
--   - User-owned records reference `users(id)` (or `devices(id)`) with `ON DELETE CASCADE` so
--     account deletion removes all user data, EXCEPT `audit_events.user_id` (and `device_id`)
--     which use `ON DELETE SET NULL` so the append-only security log survives account deletion.
--   - Indexes are created on every foreign key column and on `sessions.family_id` for fast
--     ownership filtering, cascading deletes, and refresh-token family revocation.

-- 1. users: Account records holding OPAQUE state and master-key-wrapped vault keys.
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash BYTEA NOT NULL UNIQUE,
    email_enc BYTEA NOT NULL,
    opaque_record BYTEA NOT NULL,
    wrapped_km BYTEA NOT NULL,
    wrapped_ks_master BYTEA NOT NULL,
    kdf_params BYTEA NOT NULL,
    key_version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_users_email_hash_len CHECK (octet_length(email_hash) > 0 AND octet_length(email_hash) <= 64),
    CONSTRAINT chk_users_email_enc_len CHECK (octet_length(email_enc) > 0 AND octet_length(email_enc) <= 1024),
    CONSTRAINT chk_users_opaque_record_len CHECK (octet_length(opaque_record) > 0 AND octet_length(opaque_record) <= 4096),
    CONSTRAINT chk_users_wrapped_km_len CHECK (octet_length(wrapped_km) > 0 AND octet_length(wrapped_km) <= 1024),
    CONSTRAINT chk_users_wrapped_ks_master_len CHECK (octet_length(wrapped_ks_master) > 0 AND octet_length(wrapped_ks_master) <= 1024),
    CONSTRAINT chk_users_kdf_params_len CHECK (octet_length(kdf_params) > 0 AND octet_length(kdf_params) <= 1024),
    CONSTRAINT chk_users_key_version_pos CHECK (key_version >= 1)
);

-- 2. devices: Registered client devices bound to a user account.
CREATE TABLE devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name_enc BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    CONSTRAINT chk_devices_name_enc_len CHECK (octet_length(name_enc) > 0 AND octet_length(name_enc) <= 1024)
);

CREATE INDEX idx_devices_user_id ON devices(user_id);

-- 3. sessions: Rotating refresh-token sessions bound to a device and rotation family.
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    refresh_hash BYTEA NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT chk_sessions_refresh_hash_len CHECK (octet_length(refresh_hash) > 0 AND octet_length(refresh_hash) <= 64)
);

CREATE INDEX idx_sessions_device_id ON sessions(device_id);
CREATE INDEX idx_sessions_family_id ON sessions(family_id);

-- 4. passkeys: WebAuthn credentials for 2FA and optional PRF-wrapped Vault Secret Key (K_s).
CREATE TABLE passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL,
    wrapped_ks_prf BYTEA,
    name_enc BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_passkeys_credential_id_len CHECK (octet_length(credential_id) > 0 AND octet_length(credential_id) <= 1024),
    CONSTRAINT chk_passkeys_public_key_len CHECK (octet_length(public_key) > 0 AND octet_length(public_key) <= 8192),
    CONSTRAINT chk_passkeys_sign_count_nonneg CHECK (sign_count >= 0),
    CONSTRAINT chk_passkeys_wrapped_ks_prf_len CHECK (
        wrapped_ks_prf IS NULL OR (octet_length(wrapped_ks_prf) > 0 AND octet_length(wrapped_ks_prf) <= 1024)
    ),
    CONSTRAINT chk_passkeys_name_enc_len CHECK (octet_length(name_enc) > 0 AND octet_length(name_enc) <= 1024)
);

CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);

-- 5. totp: Fallback second-factor TOTP secret (encrypted with a server key) per user.
CREATE TABLE totp (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc BYTEA NOT NULL,
    verified_at TIMESTAMPTZ,
    CONSTRAINT chk_totp_secret_enc_len CHECK (octet_length(secret_enc) > 0 AND octet_length(secret_enc) <= 1024)
);

-- 6. recovery_codes: Hashed single-use 2FA recovery codes per user.
CREATE TABLE recovery_codes (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_hash),
    CONSTRAINT chk_recovery_codes_code_hash_len CHECK (octet_length(code_hash) > 0 AND octet_length(code_hash) <= 64)
);

CREATE INDEX idx_recovery_codes_user_id ON recovery_codes(user_id);

-- 7. items: Encrypted vault items (both metadata and secrets are client-encrypted blobs).
CREATE TABLE items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    meta_blob BYTEA NOT NULL,
    secret_blob BYTEA NOT NULL,
    wrapped_item_key_m BYTEA NOT NULL,
    wrapped_item_key_s BYTEA NOT NULL,
    version INTEGER NOT NULL,
    padded_size INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT chk_items_meta_blob_len CHECK (octet_length(meta_blob) > 0 AND octet_length(meta_blob) <= 65536),
    CONSTRAINT chk_items_secret_blob_len CHECK (octet_length(secret_blob) > 0 AND octet_length(secret_blob) <= 65536),
    CONSTRAINT chk_items_wrapped_key_m_len CHECK (octet_length(wrapped_item_key_m) > 0 AND octet_length(wrapped_item_key_m) <= 1024),
    CONSTRAINT chk_items_wrapped_key_s_len CHECK (octet_length(wrapped_item_key_s) > 0 AND octet_length(wrapped_item_key_s) <= 1024),
    CONSTRAINT chk_items_version_pos CHECK (version >= 1),
    CONSTRAINT chk_items_padded_size_bounds CHECK (padded_size > 0 AND padded_size <= 131072)
);

CREATE INDEX idx_items_user_id ON items(user_id);

-- 8. audit_events: Append-only security event log. Survives user/device deletion via ON DELETE SET NULL.
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    ip_hash BYTEA NOT NULL,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_audit_events_type_len CHECK (char_length(type) > 0 AND char_length(type) <= 64),
    CONSTRAINT chk_audit_events_ip_hash_len CHECK (octet_length(ip_hash) > 0 AND octet_length(ip_hash) <= 64)
);

CREATE INDEX idx_audit_events_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_events_device_id ON audit_events(device_id);
