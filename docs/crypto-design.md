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
- `/auth/*` request logs emit only `(event, status, request_id)` and never log emails, email hashes, request bodies, `login_id`s, or base64 fields.
