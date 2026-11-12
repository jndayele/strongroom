# HTTP API Reference (Phase 1, Step 5 — Sessions, Cookies, CSRF, CORS, and Devices)

> **DEPLOYMENT WARNING — DO NOT EXPOSE PUBLICLY YET:**
> Mandatory second-factor (2FA) verification endpoints and login rate limiting are not yet implemented. Until those steps are complete, this API must not be deployed or exposed to the public internet.

---

## Global Request & Response Rules

- **Content-Type:** Every `POST /auth/*` request with a JSON body (`/auth/signup/*`, `/auth/login/*`) must include `Content-Type: application/json`. Requests with a missing or non-JSON `Content-Type` are rejected with `400 Bad Request`.
- **Body Size Limit:** Maximum request body size is **16 KiB** (`16,384` bytes). Requests exceeding 16 KiB are rejected with `413 Payload Too Large` (`{"error":"invalid_request"}`).
- **Strict JSON Schema:** All JSON request bodies enforce `#[serde(deny_unknown_fields)]`. Any unknown field, missing required field, or wrong value type returns `400 Bad Request` (`{"error":"invalid_request"}`).
- **Binary Encoding:** All binary fields (`registration_request`, `registration_response`, `registration_record`, `wrapped_km`, `wrapped_ks_master`, `credential_request`, `credential_response`, `login_id`, `credential_finalization`, `name_enc`) are URL-safe Base64 strings without padding (`base64url`), enforced with explicit maximum lengths prior to decoding.
- **Email Canonicalization:** All `email` inputs pass through `canonicalize_email` (trimmed, ASCII-only, `<= 254` characters, single `@`, non-empty local and domain parts, converted to ASCII lowercase). Plaintext emails are never stored in the database and never written to logs.
- **Constant `kdf_params`:** `kdf_params` is a single server-wide constant (`memory: 65536` KiB, `iterations: 3`, `parallelism: 1`) returned identically on every `signup/start` and `login/start` response for both known and unknown email addresses.
- **Logging:** The server logs only `(event, status, request_id)` for `/auth/*` requests. Emails, email hashes, request bodies, tokens, cookies, token hashes, and base64 fields are never logged.
- **Security Headers:** Every response sets `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.

---

## Cookies, Sessions, CSRF, and CORS

### Cookies & Local Dev Switch
- Session tokens are **opaque 32-byte random values** from `OsRng` encoded as 43-character unpadded `base64url` strings (never JWTs). Only their `SHA-256` digests are stored in PostgreSQL.
- **Default / Production (`DEV_INSECURE_COOKIES=false`, default when unset):**
  - Access cookie: `__Host-at=<token>; HttpOnly; Secure; SameSite=Strict; Path=/`
  - Refresh cookie: `__Host-rt=<token>; HttpOnly; Secure; SameSite=Strict; Path=/`
  - No `Domain` attribute is ever set.
- **Local HTTP Dev Switch (`DEV_INSECURE_COOKIES=true`):**
  - Permitted **only** when `APP_ORIGIN` is `http://localhost[:port]` or `http://127.0.0.1[:port]` (startup fails otherwise).
  - Omits `Secure` and drops the `__Host-` prefix (emitting `at` and `rt` with `HttpOnly; SameSite=Strict; Path=/` and no `Domain`), because browsers discard `__Host-` cookies that lack `Secure`.

### Two Authentication Stages
1. **Stage 1 (Password verified, MFA pending):**
   - Issued on `POST /auth/login/finish` success.
   - Sets `__Host-at` valid for **5 minutes**, with **no** refresh token (`__Host-rt` is not issued).
   - Usable **only** on `GET /auth/session`, `POST /auth/logout`, and future 2FA verification endpoints. Calling Stage 2 endpoints returns `403 Forbidden` (`{"error":"mfa_required"}`).
2. **Stage 2 (Fully authenticated):**
   - Issued by `upgrade_session_after_mfa(...)` once second-factor verification succeeds.
   - Rotates `__Host-at` (valid **10 minutes**) and issues rotating `__Host-rt` (**7-day absolute ceiling**, **24-hour sliding idle window**).

### CSRF Protection
- Every authenticated mutating request (`POST`, `PUT`, `PATCH`, `DELETE`) must include the header `X-Vault-CSRF: 1`, otherwise the server returns `403 Forbidden` (`{"error":"csrf_failed"}`).
- Exempt unauthenticated OPAQUE ceremony endpoints: `POST /auth/signup/start`, `POST /auth/signup/finish`, `POST /auth/login/start`, `POST /auth/login/finish`.
- Safe methods (`GET`, `HEAD`, `OPTIONS`) do not require `X-Vault-CSRF`.

### CORS Policy
- Configured strictly from `APP_ORIGIN` (exactly one `http://` or `https://` origin; no wildcard `*`, no arbitrary origin reflection).
- Every response includes `Vary: Origin`.
- Only requests whose `Origin` header exactly equals `APP_ORIGIN` receive `Access-Control-Allow-Origin: <APP_ORIGIN>` and `Access-Control-Allow-Credentials: true`.
- `OPTIONS` preflight requests return `204 No Content`, and for `APP_ORIGIN` also return `Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS`, `Access-Control-Allow-Headers: Content-Type, X-Vault-CSRF`, and `Access-Control-Max-Age: 600`. Other origins receive no `Access-Control-*` headers.

---

## Endpoints

### 1. `POST /auth/signup/start`

Starts an OPAQUE registration ceremony by evaluating the client's blinded `registration_request` against the deterministic per-credential OPRF key derived from the canonical email. Behaves identically for new and already-registered email addresses.

- **Request Body:**
  ```json
  {
    "email": "alice@example.com",
    "registration_request": "<base64url, max 128 chars, 32 bytes decoded>"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "registration_response": "<base64url, 86 chars, 64 bytes decoded>",
    "kdf_params": {
      "memory": 65536,
      "iterations": 3,
      "parallelism": 1
    }
  }
  ```

---

### 2. `POST /auth/signup/finish`

Validates the client's `registration_record` (`RegistrationUpload`) and the size bounds on `wrapped_km` and `wrapped_ks_master` (`1..=1024` bytes decoded), then inserts the user row using `INSERT INTO users ... ON CONFLICT (email_hash) DO NOTHING`.

- **Conflict / Enumeration Semantics:** If a row with the same `email_hash` already exists, the existing row is **never** overwritten or modified, and the endpoint returns the exact same `200 OK` `{"status":"ok"}` response on the same code path.
- **`email_enc`:** Stored as `NULL` until email verification / server-side AEAD is added.

- **Request Body:**
  ```json
  {
    "email": "alice@example.com",
    "registration_record": "<base64url, max 512 chars, 192 bytes decoded>",
    "wrapped_km": "<base64url, max 1368 chars, 1..=1024 bytes decoded>",
    "wrapped_ks_master": "<base64url, max 1368 chars, 1..=1024 bytes decoded>"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "status": "ok"
  }
  ```

---

### 3. `POST /auth/login/start`

Looks up the user by `email_hash` in a single query and initiates an OPAQUE login ceremony:
- **Known email:** Runs `opaque::login_start` with `Some(opaque_record)` and stores the pending login state with `user_id: Some(user.id)`.
- **Unknown email:** Runs `opaque::login_start` with `None` (constant-time dummy record + deterministic OPRF evaluation) and stores the pending login state with `user_id: None`.
- Both paths return the exact same HTTP status (`200 OK`), JSON keys, `login_id` length (`43` chars), `credential_response` length (`427` chars), and constant `kdf_params`.

- **Request Body:**
  ```json
  {
    "email": "alice@example.com",
    "credential_request": "<base64url, max 256 chars, 96 bytes decoded>"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "login_id": "<base64url, 43 chars, 32 bytes decoded>",
    "credential_response": "<base64url, 427 chars, 320 bytes decoded>",
    "kdf_params": {
      "memory": 65536,
      "iterations": 3,
      "parallelism": 1
    }
  }
  ```

---

### 4. `POST /auth/login/finish`

Atomically removes (`take()`) the single-use pending login state for `login_id` and verifies the client's `credential_finalization`.

- **Device Binding:** Accepts an optional `device_id` UUID string. Reuses that device **only** if it exists, belongs to this same user, and has `revoked_at IS NULL`; otherwise creates a new device record (`name_enc = NULL`).
- **Stage 1 Session Issuance:** On success, creates a Stage 1 session (5-minute access token, no refresh token) and sets the `__Host-at` cookie. Does **not** release `wrapped_km` or `wrapped_ks_master`.

- **Request Body:**
  ```json
  {
    "login_id": "<base64url, max 128 chars, 32 bytes decoded>",
    "credential_finalization": "<base64url, max 256 chars, 64 bytes decoded>",
    "device_id": "<optional UUID string>"
  }
  ```
- **Success Response (`200 OK` + `Set-Cookie: __Host-at=...`):**
  ```json
  {
    "status": "mfa_required"
  }
  ```
- **Authentication Failure Response (`401 Unauthorized`, no `Set-Cookie`):**
  Returned uniformly (byte-for-byte identical body) for a missing, expired, or replayed `login_id`, a wrong password / invalid MAC, or an unknown-email dummy login ceremony:
  ```json
  {
    "error": "authentication_failed"
  }
  ```

---

### 5. `POST /auth/refresh`

Requires `X-Vault-CSRF: 1` and a valid Stage 2 `__Host-rt` refresh cookie.

- **Rotation & Reuse Detection:** Atomically marks the presented refresh token as used (`used_at = now()`) and issues a fresh `__Host-at` (10m) and `__Host-rt` pair in the same `family_id`, preserving the original 7-day `refresh_expires_at` ceiling and resetting `idle_expires_at` to 24 hours.
- **Reuse Replay:** Presenting a refresh token that already has `used_at IS NOT NULL` immediately revokes the **entire** `family_id` (including the newest token) and returns the uniform `401` body (`{"error":"authentication_failed"}`).
- **Success Response (`200 OK` + `Set-Cookie: __Host-at=...`, `Set-Cookie: __Host-rt=...`):**
  ```json
  {
    "status": "ok"
  }
  ```

---

### 6. `POST /auth/logout`

Requires `X-Vault-CSRF: 1` and a valid Stage 1 or Stage 2 `__Host-at` cookie.

- Revokes the caller's entire `family_id` in `sessions` and clears both `__Host-at` and `__Host-rt` cookies (`Max-Age=0`).
- **Success Response (`200 OK` + clearing `Set-Cookie` headers):**
  ```json
  {
    "status": "ok"
  }
  ```

---

### 7. `GET /auth/session`

Requires a valid Stage 1 or Stage 2 `__Host-at` cookie.

- **Success Response (`200 OK`):**
  ```json
  {
    "user_id": "<uuid>",
    "device_id": "<uuid>",
    "stage": 1
  }
  ```
  (`stage` is `1` while MFA is pending or `2` once fully authenticated.)

---

### 8. `GET /auth/devices`

Requires a valid **Stage 2** `__Host-at` cookie (returns `403 {"error":"mfa_required"}` in Stage 1).

- Lists all devices belonging to the authenticated user (`WHERE user_id = ...`).
- **Success Response (`200 OK`):**
  ```json
  {
    "devices": [
      {
        "id": "<uuid>",
        "name_enc": "<base64url or null>",
        "created_at": "2026-11-11T03:00:00.000000Z",
        "last_seen_at": "2026-11-11T03:05:00.000000Z",
        "revoked_at": null
      }
    ]
  }
  ```

---

### 9. `DELETE /auth/devices/{id}`

Requires `X-Vault-CSRF: 1` and a valid **Stage 2** `__Host-at` cookie (returns `403 {"error":"mfa_required"}` in Stage 1).

- Revokes the specified active device owned by the caller (`revoked_at = now()`) and revokes **all** sessions bound to that device.
- **Cross-user / Missing / Already-Revoked Semantics:** Nonexistent IDs, malformed IDs, already-revoked devices, and devices belonging to another user all return the exact same `404 Not Found` (`{"error":"not_found"}`).
- **Success Response (`200 OK`):**
  ```json
  {
    "status": "ok"
  }
  ```

---

## Error Semantics Summary

| Status Code | Response Body | When Returned |
| --- | --- | --- |
| `400 Bad Request` | `{"error":"invalid_request"}` | Missing/invalid `Content-Type: application/json`, malformed JSON, unknown JSON field, invalid/non-ASCII email, invalid base64url, invalid `device_id` UUID on `login/finish`, field exceeding max length, or malformed OPAQUE request/upload message. |
| `401 Unauthorized` | `{"error":"authentication_failed"}` | Uniform across: `/auth/login/finish` failure, missing/malformed/duplicate/oversized cookie, unknown token, expired access/idle/absolute token, revoked session, revoked device, and refresh-token reuse detection. |
| `403 Forbidden` | `{"error":"csrf_failed"}` | Mutating non-exempt request missing `X-Vault-CSRF: 1`. |
| `403 Forbidden` | `{"error":"mfa_required"}` | Valid Stage 1 session attempting to call a Stage 2 endpoint (`/auth/devices*`). |
| `404 Not Found` | `{"error":"not_found"}` | `DELETE /auth/devices/{id}` when device does not exist, belongs to another user, or is already revoked. |
| `413 Payload Too Large` | `{"error":"invalid_request"}` | Request body exceeds `16 KiB` (`16,384` bytes). |
| `500 Internal Server Error` | `{"error":"internal_error"}` | Unexpected database error or internal state store capacity error (never includes internal error text). |

---

## Known Design Debt

- **Unverified pre-registration in `/auth/signup/finish`:** Because `/auth/signup/finish` currently inserts directly into `users` before email verification exists, an attacker who submits `/auth/signup/start` + `/auth/signup/finish` for someone else's email address can pre-register that `email_hash`. When the real owner later attempts to sign up with the same email, `INSERT ... ON CONFLICT (email_hash) DO NOTHING` makes their signup a silent no-op while leaving the attacker's `opaque_record` in `users`.
- **Required fix in the email-verification step:** Store unverified signups in a separate `pending_signups` table with a short expiry TTL and a one-time verification token, and insert the row into `users` **only after** the user confirms the email verification link. Expired, unconfirmed rows in `pending_signups` must never block the real email owner from signing up.
