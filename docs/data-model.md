# Server Data Model (`docs/PRD.md` Section 12)

The PostgreSQL database stores only opaque identifiers, timestamps, one-way cryptographic hashes, OPAQUE protocol records, wrapped keys, and client-encrypted ciphertext envelopes (`BYTEA`). The server never receives or stores anything capable of decrypting user vault data.

## Database Roles

| Role | Responsibility | Allowed SQL Operations |
| --- | --- | --- |
| `vault_migrator` | Schema owner; runs SQLx migrations (`apps/api/migrations/`) | Full DDL (`CREATE`, `ALTER`, `DROP`) and `GRANT`/`REVOKE` in `public` |
| `vault_app` | API runtime connection pool (`DATABASE_URL`) | `SELECT, INSERT, UPDATE, DELETE` on `users`, `devices`, `sessions`, `passkeys`, `totp`, `recovery_codes`, `items`; `SELECT, INSERT` only on `audit_events`; **no DDL** |

## Tables and Ciphertext / Sensitive Column Classification

### 1. `users`

Stores account registration records and wrapped vault keys.

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `id` | `UUID` (PK) | Identifier | Generated via `gen_random_uuid()` |
| `email_hash` | `BYTEA` (`UNIQUE`, `<= 64 B`) | **Cryptographic hash** | Lookup hash of normalized email address |
| `email_enc` | `BYTEA` (`<= 1024 B`) | **Ciphertext** | Encrypted email used strictly for security alert delivery |
| `opaque_record` | `BYTEA` (`<= 4096 B`) | **Cryptographic protocol state** | OPAQUE (RFC 9807) registration record; contains no plaintext password |
| `wrapped_km` | `BYTEA` (`<= 1024 B`) | **Ciphertext (wrapped key)** | Vault Metadata Key ($K_m$) wrapped with AES-256-GCM under the client KEK |
| `wrapped_ks_master` | `BYTEA` (`<= 1024 B`) | **Ciphertext (wrapped key)** | Vault Secret Key ($K_s$) wrapped with AES-256-GCM under the client KEK |
| `kdf_params` | `BYTEA` (`<= 1024 B`) | **Opaque parameters blob** | Serialized client KDF parameters (Argon2id / HKDF metadata) |
| `key_version` | `INTEGER` (`>= 1`) | Metadata | Monotonic key-hierarchy version bound into item AAD |
| `created_at` | `TIMESTAMPTZ` | Timestamp | Account creation timestamp |

### 2. `devices`

Tracks registered client devices for session binding and remote revocation.

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `id` | `UUID` (PK) | Identifier | Generated via `gen_random_uuid()` |
| `user_id` | `UUID` (FK -> `users.id`) | Identifier | `ON DELETE CASCADE`; indexed (`idx_devices_user_id`) |
| `name_enc` | `BYTEA` (nullable, `<= 1024 B`) | **Ciphertext** | Optional client-encrypted human-readable device label (`NULL` until client uploads encrypted label) |
| `created_at` | `TIMESTAMPTZ` | Timestamp | Device registration time |
| `last_seen_at` | `TIMESTAMPTZ` | Timestamp | Last authenticated activity from this device |
| `revoked_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Non-null once the device is revoked |

### 3. `sessions`

Tracks two-stage opaque sessions (Stage 1: password verified / MFA pending; Stage 2: fully authenticated) and rotating refresh-token families per device.

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `id` | `UUID` (PK) | Identifier | Generated via `gen_random_uuid()` |
| `user_id` | `UUID` (FK -> `users.id`) | Identifier | `ON DELETE CASCADE`; indexed (`idx_sessions_user_id`); enforced in every session query |
| `device_id` | `UUID` (FK -> `devices.id`) | Identifier | `ON DELETE CASCADE`; indexed (`idx_sessions_device_id`) |
| `family_id` | `UUID` | Identifier | Token rotation family for reuse detection; indexed (`idx_sessions_family_id`) |
| `stage` | `SMALLINT` (`1 \| 2`) | Metadata | `1` = OPAQUE password verified (MFA pending); `2` = fully authenticated after MFA |
| `mfa_verified_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Set when upgraded to Stage 2; `NULL` in Stage 1 |
| `access_hash` | `BYTEA` (`UNIQUE`, `32 B`) | **Cryptographic hash** | SHA-256 of the opaque access token (raw token is never stored) |
| `access_expires_at` | `TIMESTAMPTZ` | Timestamp | Access token expiry (`5 minutes` in Stage 1, `10 minutes` in Stage 2) |
| `refresh_hash` | `BYTEA` (nullable, `UNIQUE`, `32 B`) | **Cryptographic hash** | SHA-256 of the opaque refresh token (`NULL` in Stage 1) |
| `refresh_expires_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Absolute 7-day ceiling for the session family (`NULL` in Stage 1) |
| `idle_expires_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Sliding 24-hour idle expiration timestamp (`NULL` in Stage 1) |
| `used_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Non-null once rotated by `/auth/refresh`; replaying a used token revokes the entire `family_id` |
| `created_at` | `TIMESTAMPTZ` | Timestamp | Session row creation timestamp |
| `revoked_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Non-null once the session, family, or parent device is revoked |

### 4. `passkeys`

Stores WebAuthn credentials for second-factor authentication and biometric PRF reveal gating.

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `id` | `UUID` (PK) | Identifier | Generated via `gen_random_uuid()` |
| `user_id` | `UUID` (FK -> `users.id`) | Identifier | `ON DELETE CASCADE`; indexed (`idx_passkeys_user_id`) |
| `credential_id` | `BYTEA` (`UNIQUE`, `<= 1024 B`) | **Opaque WebAuthn ID** | Authenticator credential identifier |
| `public_key` | `BYTEA` (`<= 8192 B`) | **Cryptographic public key** | Serialized COSE public key / WebAuthn credential state |
| `sign_count` | `BIGINT` (`>= 0`) | Metadata | WebAuthn signature counter for clone detection |
| `wrapped_ks_prf` | `BYTEA` (nullable, `<= 1024 B`) | **Ciphertext (wrapped key)** | Vault Secret Key ($K_s$) wrapped under the passkey's client-side PRF key |
| `name_enc` | `BYTEA` (`<= 1024 B`) | **Ciphertext** | Client-encrypted passkey nickname |
| `created_at` | `TIMESTAMPTZ` | Timestamp | Passkey registration timestamp |

### 5. `totp`

Stores the fallback second-factor TOTP seed for accounts using authenticator apps.

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `user_id` | `UUID` (PK, FK -> `users.id`) | Identifier | `ON DELETE CASCADE` (1:1 with `users`) |
| `secret_enc` | `BYTEA` (`<= 1024 B`) | **Ciphertext** | Login 2FA TOTP secret encrypted with a server key (not a vault item secret) |
| `verified_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Set once the user verifies a valid TOTP code |

### 6. `recovery_codes`

Stores single-use 2FA recovery code hashes (10 issued per user).

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `user_id` | `UUID` (PK, FK -> `users.id`) | Identifier | `ON DELETE CASCADE`; indexed (`idx_recovery_codes_user_id`) |
| `code_hash` | `BYTEA` (PK, `<= 64 B`) | **Cryptographic hash** | One-way hash of the single-use recovery code |
| `used_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Non-null once the recovery code has been consumed |

### 7. `items`

Stores encrypted vault items. Every query against `items` must filter by `user_id`.

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `id` | `UUID` (PK) | Identifier | Generated via `gen_random_uuid()` |
| `user_id` | `UUID` (FK -> `users.id`) | Identifier | `ON DELETE CASCADE`; indexed (`idx_items_user_id`) |
| `meta_blob` | `BYTEA` (`<= 64 KiB`) | **Ciphertext** | Client-encrypted metadata envelope (title, URL, username, notes), padded to 256-byte buckets and bound via AAD |
| `secret_blob` | `BYTEA` (`<= 64 KiB`) | **Ciphertext** | Client-encrypted secret envelope (password, item TOTP seed, recovery notes), bound via AAD |
| `wrapped_item_key_m` | `BYTEA` (`<= 1024 B`) | **Ciphertext (wrapped key)** | Per-item metadata key wrapped under $K_m$ |
| `wrapped_item_key_s` | `BYTEA` (`<= 1024 B`) | **Ciphertext (wrapped key)** | Per-item secret key wrapped under $K_s$ |
| `version` | `INTEGER` (`>= 1`) | Metadata | Envelope/item version bound into AAD |
| `padded_size` | `INTEGER` (`1..=131072`) | Metadata | Padded ciphertext size in bytes |
| `created_at` | `TIMESTAMPTZ` | Timestamp | Creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | Timestamp | Last update timestamp |
| `deleted_at` | `TIMESTAMPTZ` (nullable) | Timestamp | Soft-delete timestamp (`NULL` while active; 30-day trash retention) |

### 8. `audit_events`

Append-only security event log (`vault_app` has `SELECT` and `INSERT` only; `UPDATE` and `DELETE` are prohibited).

| Column | Type | Classification | Notes |
| --- | --- | --- | --- |
| `id` | `UUID` (PK) | Identifier | Generated via `gen_random_uuid()` |
| `user_id` | `UUID` (nullable, FK -> `users.id`) | Identifier | `ON DELETE SET NULL` so audit logs survive account deletion; indexed (`idx_audit_events_user_id`) |
| `type` | `TEXT` (`1..=64 chars`) | Event code | Enumerated event category (e.g., `login_succeeded`, `login_failed`) |
| `ip_hash` | `BYTEA` (`<= 64 B`) | **Cryptographic hash** | Keyed hash of client IP address (raw IP is never stored) |
| `device_id` | `UUID` (nullable, FK -> `devices.id`) | Identifier | `ON DELETE SET NULL`; indexed (`idx_audit_events_device_id`) |
| `created_at` | `TIMESTAMPTZ` | Timestamp | Event timestamp |
