# Cryptographic Design

> Stub created in Phase 0, Step 1. Full cryptographic specification to be expanded from `docs/PRD.md` Sections 5 and 6.

---

## OPAQUE server design

### 1. Cipher Suite (`ServerSuite`)
- **OPRF Cipher Suite (`OprfCs`):** `opaque_ke::Ristretto255` (`OPRF(ristretto255, SHA-512)` per RFC 9497 §4.1 and RFC 9807 §10.1).
- **Key Exchange (`KeyExchange`):** `opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>` (3DH over `ristretto255` with `SHA-512`).
- **Key Stretching Function (`Ksf`):**
  - **Production server (`ServerSuite`):** `opaque_ke::ksf::Identity`. Because the OPAQUE server never runs the KSF during registration or login (RFC 9807 §3.3), the production server binary does not compile `argon2` into `[dependencies]`. `ServerSuite` carries an explicit warning that it must **never** be used for client-side operations.
  - **Client (`@serenity-kit/opaque` in the browser, and `TestClientSuite` in Rust `[dev-dependencies]`):** Argon2id (`argon2::Argon2<'static>`, V0x13). Because the wire protocol messages (`RegistrationRequest`, `RegistrationResponse`, `RegistrationUpload`, `CredentialRequest`, `CredentialResponse`, `CredentialFinalization`) depend only on the OPRF group (`Ristretto255`) and key exchange (`TripleDh<Ristretto255, Sha512>`), serialized message bytes are 100% compatible between `ServerSuite` and the client suite.

### 2. Server Secrets and Rotation Impact
All three secrets are base64url-encoded environment variables validated at startup (`apps/api/src/config.rs`). Their Rust wrapper types implement custom `Debug` formatting that outputs `"[redacted]"` so secret bytes can never be logged. Fresh values can be generated once to stdout via `cargo run -p strongroom-api --bin gen-secrets`.

| Environment Variable | Decoded Size | Purpose | What Rotating It Breaks |
| --- | --- | --- | --- |
| `OPAQUE_SERVER_SETUP` | 128 bytes | Serialized `opaque_ke::ServerSetup<ServerSuite>` containing the 64-byte `oprf_seed`, 32-byte server static private key, and 32-byte dummy public key. | **Invalidates every user's login (`opaque_record`).** Changing `oprf_seed` changes the OPRF output (and thus the client's `export_key` and envelope key), and changing the server static keypair breaks envelope authentication. |
| `CREDENTIAL_ID_KEY` | 32 bytes | HMAC-SHA-256 key used by `credential_identifier()` to derive the 32-byte OPAQUE `credential_identifier` from the canonical email. | **Invalidates every user's login (`opaque_record`).** `opaque-ke` derives each user's per-credential OPRF scalar from `HKDF(oprf_seed, credential_identifier)`. Changing `CREDENTIAL_ID_KEY` changes `credential_identifier` and therefore changes the OPRF output for all existing users. |
| `EMAIL_HASH_KEY` | 32 bytes | HMAC-SHA-256 key used by `email_hash()` to compute the 32-byte lookup key stored in `users.email_hash`. | **Breaks database lookups by email.** Existing rows in `users` will no longer match `WHERE email_hash = $1` unless `users.email_hash` is migrated or re-indexed. |

### 3. In-Memory Pending Login Store (`PendingLoginStore`)
- **Design:** Between `login/start` and `login/finish`, the server holds the `ServerLogin` state and `user_id: Option<Uuid>` (`None` for the unknown-email dummy path) in an in-memory `HashMap<[u8; 32], PendingLoginEntry>` protected by a synchronous `std::sync::Mutex` (`apps/api/src/auth/pending.rs`).
- **Bounds & Eviction Policy:**
  - **TTL:** 60 seconds (`LOGIN_STATE_TTL`).
  - **Hard Cap:** 10,000 entries (`MAX_PENDING_LOGINS`).
  - On every `insert()`, expired entries are purged first. If 10,000 unexpired entries remain, the new login attempt is **rejected** rather than evicting an older unexpired entry, so an unauthenticated flood cannot evict legitimate users' in-progress logins before they reach `login/finish`.
  - **Single-use:** `take()` atomically removes the entry by its 32-byte random `login_id` (generated via `OsRng`), preventing replay of `CredentialFinalization`.
- **Single-Instance Limitation:** Because `PendingLoginStore` lives in process memory, all requests for a given `login/start` -> `login/finish` pair must reach the same API process. This matches our v1 single-instance Render deployment (`docs/PRD.md` §3). Running multiple API instances horizontally later will require moving pending login state to a shared store (such as PostgreSQL or Redis) or enforcing sticky routing.

### 4. ASCII Email Limitation (v1)
- `canonicalize_email()` (`apps/api/src/auth/email.rs`) trims leading/trailing whitespace, enforces a maximum length of 254 characters, requires a single `@` with non-empty local and domain parts, rejects any internal whitespace or control characters, and lowercases the address.
- **Known v1 limitation:** Non-ASCII (internationalized / UTF-8) email addresses are rejected (`EmailError::NonAscii`). Restricting v1 to ASCII avoids Unicode normalization discrepancies (NFC vs. NFKC across browsers and runtimes) that could cause a user's email hash or OPAQUE `credential_identifier` to drift across devices.

### 5. Logging Privacy & SQLx Statement Logging
- The API defaults to log level `INFO` unless `LOG_LEVEL` is explicitly set (`apps/api/src/main.rs`).
- `connect_pool()` (`apps/api/src/db/mod.rs`) calls `ConnectOptions::disable_statement_logging()` (setting both `log_statements` and `log_slow_statements` to `LevelFilter::Off`). Even if `LOG_LEVEL=debug` or `trace` is enabled, SQLx will never emit per-query `rows_returned` / `rows_affected` records that would reveal to log readers whether an `email_hash` lookup matched an existing account.
- `/auth/*` request logs emit only `(event, status, request_id)` and never log emails, email hashes, request bodies, `login_id`s, tokens, cookies, token hashes, or base64 fields.

---

## Opaque Session & Refresh Token Design

### 1. Token Format and Server-Side Hashing (No JWTs)
- Every access token and refresh token is **32 random bytes** generated from `OsRng` (256 bits of entropy), encoded on the wire as a 43-character unpadded `base64url` string.
- The server **never** signs or issues JWTs and **never** stores raw tokens in PostgreSQL. Instead, `sessions.access_hash` and `sessions.refresh_hash` store only the 32-byte `SHA-256` digest of the decoded token bytes.
- Because tokens carry no embedded claims and are resolved solely by hash lookup in `sessions` joined with `devices`, logout, refresh-token reuse detection, and remote device revocation take effect immediately on the next request.

### 2. Two-Stage Session Lifecycle
1. **Stage 1 (Password verified, MFA pending):**
   - Created by `POST /auth/login/finish` upon OPAQUE verification.
   - Issues only an access token (`__Host-at`) valid for **5 minutes**, with **no** refresh token (`refresh_hash = NULL`).
   - Permitted only on `/auth/session`, `/auth/logout`, and future 2FA verification endpoints.
2. **Stage 2 (Fully authenticated):**
   - Created by `upgrade_session_after_mfa(...)` after second-factor verification succeeds.
   - Rotates `access_hash` immediately (invalidating the Stage 1 token), sets `access_expires_at = now() + 10 minutes`, and issues a rotating refresh token (`__Host-rt`) with a **7-day absolute ceiling** (`refresh_expires_at = now() + 7 days`) and a **24-hour sliding idle window** (`idle_expires_at = now() + 24 hours`).

### 3. Refresh Token Rotation & Reuse Detection
- `POST /auth/refresh` locks the matching `sessions` row (`FOR UPDATE`), verifies it is an active Stage 2 session within both the 7-day absolute limit and 24-hour idle limit on a non-revoked device, marks the old row `used_at = now()`, and inserts a fresh row in the same `family_id` (preserving `mfa_verified_at` and the original 7-day `refresh_expires_at` ceiling while resetting `idle_expires_at` to 24 hours).
- **Reuse detection:** If `POST /auth/refresh` receives a refresh token whose row already has `used_at IS NOT NULL`, the server immediately revokes the **entire** `family_id` (`UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()) WHERE user_id = $1 AND family_id = $2`) and returns the uniform `401` error.

### 4. Cookie Hardening, CSRF, and CORS
- **Cookies:** Default production cookies use `__Host-at` and `__Host-rt` with `HttpOnly; Secure; SameSite=Strict; Path=/` and no `Domain` attribute.
- **Local HTTP dev switch (`DEV_INSECURE_COOKIES`):** Off (`false`) by default. When explicitly set to `true` (permitted only when `APP_ORIGIN` is `http://localhost` or `http://127.0.0.1`), `Secure` is omitted and the `__Host-` prefix is dropped (`at`, `rt`) because browsers discard `__Host-` cookies that lack `Secure`.
- **CSRF:** Every authenticated mutating request (`POST`/`PUT`/`PATCH`/`DELETE`, excluding the unauthenticated OPAQUE `/auth/signup/*` and `/auth/login/*` endpoints) must include `X-Vault-CSRF: 1`, otherwise `403`.
- **CORS:** Strict allowlist of the single `APP_ORIGIN` configured at startup (`Access-Control-Allow-Credentials: true`, `Vary: Origin`, only `GET, POST, DELETE, OPTIONS` and `Content-Type, X-Vault-CSRF`). No wildcard or arbitrary origin reflection.
