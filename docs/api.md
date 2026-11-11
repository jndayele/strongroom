# HTTP API Reference (Phase 1, Step 3C — OPAQUE Authentication)

> **DEPLOYMENT WARNING — DO NOT EXPOSE PUBLICLY YET:**
> These `/auth/*` endpoints do **not** have rate limiting, session issuance, or mandatory second-factor (2FA) enforcement yet. Rate limiting and session gating will be added in the sessions and 2FA steps. Until those steps are complete, this API must not be deployed or exposed to the public internet.

---

## Global Request & Response Rules

- **Content-Type:** Every `POST /auth/*` request must include `Content-Type: application/json`. Requests with a missing or non-JSON `Content-Type` are rejected with `400 Bad Request`.
- **Body Size Limit:** Maximum request body size is **16 KiB** (`16,384` bytes). Requests exceeding 16 KiB are rejected with `413 Payload Too Large` (`{"error":"invalid_request"}`).
- **Strict JSON Schema:** All request bodies enforce `#[serde(deny_unknown_fields)]`. Any unknown field, missing required field, or wrong value type returns `400 Bad Request` (`{"error":"invalid_request"}`).
- **Binary Encoding:** All binary fields (`registration_request`, `registration_response`, `registration_record`, `wrapped_km`, `wrapped_ks_master`, `credential_request`, `credential_response`, `login_id`, `credential_finalization`) are URL-safe Base64 strings without padding (`base64url`), enforced with explicit maximum lengths prior to decoding.
- **Email Canonicalization:** All `email` inputs pass through `canonicalize_email` (trimmed, ASCII-only, `<= 254` characters, single `@`, non-empty local and domain parts, converted to ASCII lowercase). Plaintext emails are never stored in the database and never written to logs.
- **Constant `kdf_params`:** `kdf_params` is a single server-wide constant (`memory: 65536` KiB, `iterations: 3`, `parallelism: 1`) returned identically on every `signup/start` and `login/start` response for both known and unknown email addresses.
- **Logging:** The server logs only `(event, status, request_id)` for `/auth/*` requests. Emails, email hashes, request bodies, and base64 fields are never logged.

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
- **`email_enc`:** Stored as `NULL` in this step; it will be populated during the email-verification step once server-side AEAD is added.

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

Atomically removes (`take()`) the single-use pending login state for `login_id` and verifies the client's `credential_finalization` MAC.

- **Security Gate:** A successful response (`200 OK`) confirms only that the OPAQUE password ceremony succeeded (`{"status":"password_verified"}`). It does **not** return `wrapped_km`, `wrapped_ks_master`, tokens, or session cookies; those are gated by 2FA in later steps.

- **Request Body:**
  ```json
  {
    "login_id": "<base64url, max 128 chars, 32 bytes decoded>",
    "credential_finalization": "<base64url, max 256 chars, 64 bytes decoded>"
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "status": "password_verified"
  }
  ```
- **Authentication Failure Response (`401 Unauthorized`):**
  Returned uniformly (byte-for-byte identical body) for a missing, expired, or replayed `login_id`, a wrong password / invalid MAC, or an unknown-email dummy login ceremony:
  ```json
  {
    "error": "authentication_failed"
  }
  ```

---

## Error Semantics Summary

| Status Code | Response Body | When Returned |
| --- | --- | --- |
| `400 Bad Request` | `{"error":"invalid_request"}` | Missing/invalid `Content-Type: application/json`, malformed JSON, unknown JSON field, invalid/non-ASCII email, invalid base64url, field exceeding max length, or malformed OPAQUE request/upload message. |
| `401 Unauthorized` | `{"error":"authentication_failed"}` | `/auth/login/finish` with a missing, expired, or replayed `login_id`, wrong password / bad MAC, or unknown-email dummy state. |
| `413 Payload Too Large` | `{"error":"invalid_request"}` | Request body exceeds `16 KiB` (`16,384` bytes). |
| `500 Internal Server Error` | `{"error":"internal_error"}` | Unexpected database error or internal state store capacity error (never includes internal error text). |

---

## Known Design Debt

- **Unverified pre-registration in `/auth/signup/finish`:** Because `/auth/signup/finish` currently inserts directly into `users` before email verification exists, an attacker who submits `/auth/signup/start` + `/auth/signup/finish` for someone else's email address can pre-register that `email_hash`. When the real owner later attempts to sign up with the same email, `INSERT ... ON CONFLICT (email_hash) DO NOTHING` makes their signup a silent no-op while leaving the attacker's `opaque_record` in `users`.
- **Required fix in the email-verification step:** Store unverified signups in a separate `pending_signups` table with a short expiry TTL and a one-time verification token, and insert the row into `users` **only after** the user confirms the email verification link. Expired, unconfirmed rows in `pending_signups` must never block the real email owner from signing up.
