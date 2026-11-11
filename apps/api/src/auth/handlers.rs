#![forbid(unsafe_code)]

use axum::body::to_bytes;
use axum::extract::{FromRequest, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use crate::auth::email::{canonicalize_email, credential_identifier, email_hash};
use crate::auth::opaque::{self, AuthError};
use crate::auth::pending::{PendingLoginStore, Uuid};
use crate::config::{CredentialIdKey, EmailHashKey, OpaqueServerSetup};
use crate::db::{create_user_on_conflict_do_nothing, get_user_by_email_hash, NewUser};
use crate::MAX_BODY_BYTES;

/// Hard maximum base64url length for `registration_request` (raw is 32 bytes / 43 chars).
pub const MAX_B64_REGISTRATION_REQUEST_LEN: usize = 128;

/// Hard maximum base64url length for `registration_record` (raw is 192 bytes / 256 chars).
pub const MAX_B64_REGISTRATION_RECORD_LEN: usize = 512;

/// Hard maximum base64url length for `wrapped_km` and `wrapped_ks_master` (raw max 1024 bytes / 1366 chars).
pub const MAX_B64_WRAPPED_KEY_LEN: usize = 1368;

/// Hard maximum decoded byte length for `wrapped_km` and `wrapped_ks_master` (matches DB CHECK constraint).
pub const MAX_WRAPPED_KEY_BYTES: usize = 1024;

/// Hard maximum base64url length for `credential_request` (raw is 96 bytes / 128 chars).
pub const MAX_B64_CREDENTIAL_REQUEST_LEN: usize = 256;

/// Hard maximum base64url length for `login_id` (raw is 32 bytes / 43 chars).
pub const MAX_B64_LOGIN_ID_LEN: usize = 128;

/// Hard maximum base64url length for `credential_finalization` (raw is 64 bytes / 86 chars).
pub const MAX_B64_CREDENTIAL_FINALIZATION_LEN: usize = 256;

/// Initial key version stored on newly registered user rows.
pub const INITIAL_KEY_VERSION: i32 = 1;

/// Argon2id parameters returned to clients for OPAQUE key stretching.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Single server-wide constant KDF parameter set (64 MiB memory, 3 iterations, parallelism 1).
/// Returned identically for every request (known or unknown email) to prevent user enumeration.
pub const DEFAULT_KDF_PARAMS: KdfParams = KdfParams {
    memory: 65_536,
    iterations: 3,
    parallelism: 1,
};

/// Canonical serialized bytes for `DEFAULT_KDF_PARAMS` stored in `users.kdf_params`.
const DEFAULT_KDF_PARAMS_BYTES: &[u8] = b"{\"memory\":65536,\"iterations\":3,\"parallelism\":1}";

/// Shared application state held inside an `Arc` and extracted via `axum::extract::State`.
pub struct AppState {
    pub pool: PgPool,
    pub opaque_server_setup: OpaqueServerSetup,
    pub credential_id_key: CredentialIdKey,
    pub email_hash_key: EmailHashKey,
    pub pending_logins: PendingLoginStore,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        opaque_server_setup: OpaqueServerSetup,
        credential_id_key: CredentialIdKey,
        email_hash_key: EmailHashKey,
    ) -> Self {
        Self {
            pool,
            opaque_server_setup,
            credential_id_key,
            email_hash_key,
            pending_logins: PendingLoginStore::new(),
        }
    }
}

impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("pool", &"[PgPool]")
            .field("opaque_server_setup", &self.opaque_server_setup)
            .field("credential_id_key", &self.credential_id_key)
            .field("email_hash_key", &self.email_hash_key)
            .field("pending_logins", &self.pending_logins)
            .finish()
    }
}

/// Uniform JSON error payload returned by all endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub error: String,
}

/// API error variants mapped to uniform HTTP status codes and static error bodies.
/// Never carries or formats internal database, serde, or OPAQUE error details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    InvalidRequest,
    PayloadTooLarge,
    AuthenticationFailed,
    InternalError,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"),
            Self::AuthenticationFailed => (StatusCode::UNAUTHORIZED, "authentication_failed"),
            Self::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        (
            status,
            Json(ErrorBody {
                error: String::from(code),
            }),
        )
            .into_response()
    }
}

/// Custom Axum extractor that enforces:
/// 1. `Content-Type: application/json` header is present.
/// 2. Request body does not exceed `MAX_BODY_BYTES` (16 KiB).
/// 3. Strict JSON deserialization (`#[serde(deny_unknown_fields)]` on `T`), returning a uniform
///    `400 {"error":"invalid_request"}` without leaking serde error messages.
pub struct StrictJson<T>(pub T);

impl<S, T> FromRequest<S> for StrictJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if !has_json_content_type(&req) {
            return Err(ApiError::InvalidRequest);
        }

        let bytes = to_bytes(req.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|_| ApiError::PayloadTooLarge)?;

        let value = serde_json::from_slice::<T>(&bytes).map_err(|_| ApiError::InvalidRequest)?;
        Ok(Self(value))
    }
}

fn has_json_content_type(req: &Request) -> bool {
    let Some(header_val) = req.headers().get(CONTENT_TYPE) else {
        return false;
    };
    let Ok(raw) = header_val.to_str() else {
        return false;
    };
    let media_type = raw.split(';').next().unwrap_or("").trim();
    media_type.eq_ignore_ascii_case("application/json")
}

fn decode_b64url_bounded(input: &str, max_b64_len: usize) -> Result<Vec<u8>, ApiError> {
    if input.is_empty() || input.len() > max_b64_len {
        return Err(ApiError::InvalidRequest);
    }
    let unpadded = input.trim_end_matches('=');
    if unpadded.is_empty() {
        return Err(ApiError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(unpadded)
        .map_err(|_| ApiError::InvalidRequest)?;
    if bytes.is_empty() {
        return Err(ApiError::InvalidRequest);
    }
    Ok(bytes)
}

fn parse_uuid_str(uuid_str: &str) -> Option<Uuid> {
    // Standard canonical UUID text representation is 36 ASCII hex/hyphen chars: 8-4-4-4-12.
    if uuid_str.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut byte_idx = 0usize;
    let bytes = uuid_str.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if bytes[i] != b'-' {
                return None;
            }
            i += 1;
            continue;
        }
        if i + 1 >= bytes.len() || byte_idx >= 16 {
            return None;
        }
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out[byte_idx] = (hi << 4) | lo;
        byte_idx += 1;
        i += 2;
    }

    if byte_idx == 16 {
        Some(Uuid::from_bytes(out))
    } else {
        None
    }
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn generate_request_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Middleware for `/auth/*` routes that logs ONLY the event name, HTTP status code, and a random
/// `request_id`. Never logs emails, hashes, request bodies, or base64 fields.
pub async fn auth_logging_middleware(request: Request, next: Next) -> Response {
    let event_name = match request.uri().path() {
        "/signup/start" | "/auth/signup/start" => "auth.signup.start",
        "/signup/finish" | "/auth/signup/finish" => "auth.signup.finish",
        "/login/start" | "/auth/login/start" => "auth.login.start",
        "/login/finish" | "/auth/login/finish" => "auth.login.finish",
        _ => "auth.request",
    };
    let request_id = generate_request_id();

    let response = next.run(request).await;

    tracing::info!(
        event = event_name,
        status = response.status().as_u16(),
        request_id = %request_id,
    );

    response
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignupStartRequest {
    pub email: String,
    pub registration_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignupStartResponse {
    pub registration_response: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignupFinishRequest {
    pub email: String,
    pub registration_record: String,
    pub wrapped_km: String,
    pub wrapped_ks_master: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignupFinishResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    pub email: String,
    pub credential_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginStartResponse {
    pub login_id: String,
    pub credential_response: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    pub login_id: String,
    pub credential_finalization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishResponse {
    pub status: String,
}

/// `POST /auth/signup/start`
///
/// Canonicalizes `email`, derives the deterministic `credential_identifier`, evaluates the blinded
/// OPAQUE `registration_request`, and returns `{ registration_response, kdf_params }`.
/// Works identically for new and existing emails.
pub async fn signup_start_handler(
    State(state): State<Arc<AppState>>,
    StrictJson(req): StrictJson<SignupStartRequest>,
) -> Result<Json<SignupStartResponse>, ApiError> {
    let canonical_email = canonicalize_email(&req.email).map_err(|_| ApiError::InvalidRequest)?;
    let reg_req_bytes =
        decode_b64url_bounded(&req.registration_request, MAX_B64_REGISTRATION_REQUEST_LEN)?;

    let cred_id = credential_identifier(&state.credential_id_key, &canonical_email);
    let reg_resp_bytes =
        opaque::registration_start(&state.opaque_server_setup, &cred_id, &reg_req_bytes)
            .map_err(|_| ApiError::InvalidRequest)?;

    Ok(Json(SignupStartResponse {
        registration_response: URL_SAFE_NO_PAD.encode(reg_resp_bytes),
        kdf_params: DEFAULT_KDF_PARAMS,
    }))
}

/// `POST /auth/signup/finish`
///
/// Validates `email`, parses the OPAQUE `registration_record`, validates `wrapped_km` and
/// `wrapped_ks_master` size bounds, and executes `INSERT INTO users ... ON CONFLICT (email_hash) DO NOTHING`.
/// Existing user rows are never overwritten or modified, and the response is always `200 {"status":"ok"}`.
pub async fn signup_finish_handler(
    State(state): State<Arc<AppState>>,
    StrictJson(req): StrictJson<SignupFinishRequest>,
) -> Result<Json<SignupFinishResponse>, ApiError> {
    let canonical_email = canonicalize_email(&req.email).map_err(|_| ApiError::InvalidRequest)?;
    let upload_bytes =
        decode_b64url_bounded(&req.registration_record, MAX_B64_REGISTRATION_RECORD_LEN)?;
    let opaque_record =
        opaque::registration_finish(&upload_bytes).map_err(|_| ApiError::InvalidRequest)?;

    let wrapped_km = decode_b64url_bounded(&req.wrapped_km, MAX_B64_WRAPPED_KEY_LEN)?;
    if wrapped_km.len() > MAX_WRAPPED_KEY_BYTES {
        return Err(ApiError::InvalidRequest);
    }

    let wrapped_ks_master = decode_b64url_bounded(&req.wrapped_ks_master, MAX_B64_WRAPPED_KEY_LEN)?;
    if wrapped_ks_master.len() > MAX_WRAPPED_KEY_BYTES {
        return Err(ApiError::InvalidRequest);
    }

    let user_email_hash = email_hash(&state.email_hash_key, &canonical_email);

    let new_user = NewUser {
        email_hash: user_email_hash.to_vec(),
        email_enc: None,
        opaque_record,
        wrapped_km,
        wrapped_ks_master,
        kdf_params: DEFAULT_KDF_PARAMS_BYTES.to_vec(),
        key_version: INITIAL_KEY_VERSION,
    };

    create_user_on_conflict_do_nothing(&state.pool, &new_user)
        .await
        .map_err(|_| ApiError::InternalError)?;

    Ok(Json(SignupFinishResponse {
        status: String::from("ok"),
    }))
}

/// `POST /auth/login/start`
///
/// Canonicalizes `email`, looks up the user by `email_hash` in a single query, and runs
/// `opaque::login_start` with either `Some(opaque_record)` (found) or `None` (not found -> dummy).
/// Stores the pending login state with `user_id: Some/None` and returns `{ login_id, credential_response, kdf_params }`.
pub async fn login_start_handler(
    State(state): State<Arc<AppState>>,
    StrictJson(req): StrictJson<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, ApiError> {
    let canonical_email = canonicalize_email(&req.email).map_err(|_| ApiError::InvalidRequest)?;
    let cred_req_bytes =
        decode_b64url_bounded(&req.credential_request, MAX_B64_CREDENTIAL_REQUEST_LEN)?;

    let user_email_hash = email_hash(&state.email_hash_key, &canonical_email);
    let cred_id = credential_identifier(&state.credential_id_key, &canonical_email);

    let maybe_user = get_user_by_email_hash(&state.pool, &user_email_hash)
        .await
        .map_err(|_| ApiError::InternalError)?;

    let (record_slice, user_uuid): (Option<&[u8]>, Option<Uuid>) = match maybe_user.as_ref() {
        Some(user) => {
            let parsed_uuid = parse_uuid_str(&user.id).ok_or(ApiError::InternalError)?;
            (Some(user.opaque_record.as_slice()), Some(parsed_uuid))
        }
        None => (None, None),
    };

    let (login_state, cred_resp_bytes) = opaque::login_start(
        &state.opaque_server_setup,
        &cred_id,
        record_slice,
        &cred_req_bytes,
    )
    .map_err(|_| ApiError::InvalidRequest)?;

    let login_id = state
        .pending_logins
        .insert(login_state, user_uuid, Instant::now())
        .map_err(|_| ApiError::InternalError)?;

    Ok(Json(LoginStartResponse {
        login_id: URL_SAFE_NO_PAD.encode(login_id),
        credential_response: URL_SAFE_NO_PAD.encode(cred_resp_bytes),
        kdf_params: DEFAULT_KDF_PARAMS,
    }))
}

/// `POST /auth/login/finish`
///
/// Atomically removes (`take()`) the single-use pending login entry for `login_id` and verifies
/// `credential_finalization`. Missing, expired, or replayed `login_id` values, wrong passwords,
/// and unknown-email dummy entries all return the exact same `401 {"error":"authentication_failed"}`.
pub async fn login_finish_handler(
    State(state): State<Arc<AppState>>,
    StrictJson(req): StrictJson<LoginFinishRequest>,
) -> Result<Json<LoginFinishResponse>, ApiError> {
    let login_id_vec = decode_b64url_bounded(&req.login_id, MAX_B64_LOGIN_ID_LEN)?;
    let finalization_bytes = decode_b64url_bounded(
        &req.credential_finalization,
        MAX_B64_CREDENTIAL_FINALIZATION_LEN,
    )?;

    let Ok(login_id): Result<[u8; 32], _> = login_id_vec.try_into() else {
        return Err(ApiError::AuthenticationFailed);
    };

    let (login_state, maybe_user_id) = state
        .pending_logins
        .take(&login_id, Instant::now())
        .map_err(|_: AuthError| ApiError::AuthenticationFailed)?;

    opaque::login_finish(login_state, &finalization_bytes)
        .map_err(|_: AuthError| ApiError::AuthenticationFailed)?;

    if maybe_user_id.is_none() {
        return Err(ApiError::AuthenticationFailed);
    }

    Ok(Json(LoginFinishResponse {
        status: String::from("password_verified"),
    }))
}
