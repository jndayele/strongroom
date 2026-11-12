#![forbid(unsafe_code)]

use axum::body::{to_bytes, Body};
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_MAX_AGE, CONTENT_TYPE, ORIGIN, SET_COOKIE, VARY,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{AppendHeaders, IntoResponse, Response};
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

use crate::auth::cookies::{extract_token_cookie, CookieSettings};
use crate::auth::email::{canonicalize_email, credential_identifier, email_hash};
use crate::auth::opaque::{self, AuthError};
use crate::auth::pending::{PendingLoginStore, Uuid};
use crate::auth::sessions::{
    create_stage1_session, list_user_devices, logout_session_family, refresh_session,
    resolve_access_session, revoke_device_and_sessions, AuthenticatedSession, SessionError,
};
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

/// Custom CSRF header required on all authenticated mutating requests.
pub static CSRF_HEADER_NAME: HeaderName = HeaderName::from_static("x-vault-csrf");

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
    pub app_origin: String,
    pub cookie_settings: CookieSettings,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        opaque_server_setup: OpaqueServerSetup,
        credential_id_key: CredentialIdKey,
        email_hash_key: EmailHashKey,
        app_origin: String,
        dev_insecure_cookies: bool,
    ) -> Self {
        Self {
            pool,
            opaque_server_setup,
            credential_id_key,
            email_hash_key,
            pending_logins: PendingLoginStore::new(),
            app_origin,
            cookie_settings: CookieSettings::new(dev_insecure_cookies),
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
            .field("app_origin", &self.app_origin)
            .field("cookie_settings", &self.cookie_settings)
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
    CsrfFailed,
    MfaRequired,
    NotFound,
    InternalError,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"),
            Self::AuthenticationFailed => (StatusCode::UNAUTHORIZED, "authentication_failed"),
            Self::CsrfFailed => (StatusCode::FORBIDDEN, "csrf_failed"),
            Self::MfaRequired => (StatusCode::FORBIDDEN, "mfa_required"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
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

/// Axum extractor that authenticates either a Stage 1 (MFA-pending) or Stage 2 (full) session
/// from the access token cookie (`__Host-at`, or `at` in dev-insecure mode).
#[derive(Debug, Clone)]
pub struct SessionAuth(pub AuthenticatedSession);

impl FromRequestParts<Arc<AppState>> for SessionAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let session = extract_authenticated_session(parts, state).await?;
        Ok(Self(session))
    }
}

/// Axum extractor that requires a Stage 2 (fully authenticated after MFA) session.
#[derive(Debug, Clone)]
pub struct FullAuth(pub AuthenticatedSession);

impl FromRequestParts<Arc<AppState>> for FullAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let session = extract_authenticated_session(parts, state).await?;
        if session.stage != 2 {
            return Err(ApiError::MfaRequired);
        }
        Ok(Self(session))
    }
}

async fn extract_authenticated_session(
    parts: &Parts,
    state: &AppState,
) -> Result<AuthenticatedSession, ApiError> {
    let cookie_name = state.cookie_settings.access_cookie_name();
    let token_bytes =
        extract_token_cookie(&parts.headers, cookie_name).ok_or(ApiError::AuthenticationFailed)?;

    resolve_access_session(&state.pool, &token_bytes)
        .await
        .map_err(|err| match err {
            SessionError::Unauthorized => ApiError::AuthenticationFailed,
            SessionError::Database(_) => ApiError::InternalError,
        })
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

fn format_uuid(uuid: &Uuid) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = uuid.as_bytes();
    let mut out = String::with_capacity(36);
    for (idx, b) in bytes.iter().enumerate() {
        if idx == 4 || idx == 6 || idx == 8 || idx == 10 {
            out.push('-');
        }
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
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
/// `request_id`. Never logs emails, hashes, tokens, cookies, request bodies, or base64 fields.
pub async fn auth_logging_middleware(request: Request, next: Next) -> Response {
    let event_name = match request.uri().path() {
        "/signup/start" | "/auth/signup/start" => "auth.signup.start",
        "/signup/finish" | "/auth/signup/finish" => "auth.signup.finish",
        "/login/start" | "/auth/login/start" => "auth.login.start",
        "/login/finish" | "/auth/login/finish" => "auth.login.finish",
        "/refresh" | "/auth/refresh" => "auth.refresh",
        "/logout" | "/auth/logout" => "auth.logout",
        "/session" | "/auth/session" => "auth.session",
        "/devices" | "/auth/devices" => "auth.devices.list",
        p if p.starts_with("/devices/") || p.starts_with("/auth/devices/") => "auth.devices.delete",
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

/// Enforces `X-Vault-CSRF: 1` on all mutating requests except the unauthenticated OPAQUE endpoints.
pub async fn csrf_middleware(request: Request, next: Next) -> Response {
    let method = request.method();
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(request).await;
    }

    let path = request.uri().path();
    if matches!(
        path,
        "/auth/signup/start" | "/auth/signup/finish" | "/auth/login/start" | "/auth/login/finish"
    ) {
        return next.run(request).await;
    }

    let mut csrf_headers = request.headers().get_all(&CSRF_HEADER_NAME).iter();
    let valid_csrf = match (csrf_headers.next(), csrf_headers.next()) {
        (Some(val), None) => val.as_bytes() == b"1",
        _ => false,
    };

    if !valid_csrf {
        return ApiError::CsrfFailed.into_response();
    }

    next.run(request).await
}

/// Strict single-origin CORS middleware configured exclusively from `AppState.app_origin`.
/// Never uses `*`, never reflects arbitrary origins, and handles `OPTIONS` preflight cleanly.
pub async fn cors_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let mut origins = request.headers().get_all(ORIGIN).iter();
    let is_allowed_origin = match (origins.next(), origins.next()) {
        (Some(origin_val), None) => origin_val.as_bytes() == state.app_origin.as_bytes(),
        _ => false,
    };

    if *request.method() == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        let headers = response.headers_mut();
        headers.insert(VARY, HeaderValue::from_static("Origin"));
        if is_allowed_origin {
            if let Ok(origin_hdr) = HeaderValue::from_str(&state.app_origin) {
                headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin_hdr);
                headers.insert(
                    ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
                headers.insert(
                    ACCESS_CONTROL_ALLOW_METHODS,
                    HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
                );
                headers.insert(
                    ACCESS_CONTROL_ALLOW_HEADERS,
                    HeaderValue::from_static("Content-Type, X-Vault-CSRF"),
                );
                headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
            }
        }
        return response;
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(VARY, HeaderValue::from_static("Origin"));
    if is_allowed_origin {
        if let Ok(origin_hdr) = HeaderValue::from_str(&state.app_origin) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin_hdr);
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    }

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
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatusResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    pub user_id: String,
    pub device_id: String,
    pub stage: i16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceResponse {
    pub id: String,
    pub name_enc: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevicesListResponse {
    pub devices: Vec<DeviceResponse>,
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
/// `credential_finalization`. On success, binds a device (reusing `device_id` only if active
/// and owned by this user), issues a Stage 1 `__Host-at` cookie valid for 5 minutes, and
/// returns `200 {"status":"mfa_required"}`. Failures return uniform `401` with no cookie.
pub async fn login_finish_handler(
    State(state): State<Arc<AppState>>,
    StrictJson(req): StrictJson<LoginFinishRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let login_id_vec = decode_b64url_bounded(&req.login_id, MAX_B64_LOGIN_ID_LEN)?;
    let finalization_bytes = decode_b64url_bounded(
        &req.credential_finalization,
        MAX_B64_CREDENTIAL_FINALIZATION_LEN,
    )?;

    let requested_device_id = match req.device_id {
        Some(ref raw_dev_id) => {
            let parsed = parse_uuid_str(raw_dev_id).ok_or(ApiError::InvalidRequest)?;
            Some(format_uuid(&parsed))
        }
        None => None,
    };

    let Ok(login_id): Result<[u8; 32], _> = login_id_vec.try_into() else {
        return Err(ApiError::AuthenticationFailed);
    };

    let (login_state, maybe_user_id) = state
        .pending_logins
        .take(&login_id, Instant::now())
        .map_err(|_: AuthError| ApiError::AuthenticationFailed)?;

    opaque::login_finish(login_state, &finalization_bytes)
        .map_err(|_: AuthError| ApiError::AuthenticationFailed)?;

    let Some(user_uuid) = maybe_user_id else {
        return Err(ApiError::AuthenticationFailed);
    };

    let user_id_str = format_uuid(&user_uuid);
    let issued = create_stage1_session(&state.pool, &user_id_str, requested_device_id.as_deref())
        .await
        .map_err(|_| ApiError::InternalError)?;

    let access_cookie = state
        .cookie_settings
        .build_access_cookie(&issued.access_token.to_base64url())
        .map_err(|_| ApiError::InternalError)?;

    Ok((
        StatusCode::OK,
        AppendHeaders([(SET_COOKIE, access_cookie)]),
        Json(LoginFinishResponse {
            status: String::from("mfa_required"),
        }),
    ))
}

/// `POST /auth/refresh`
///
/// Rotates a Stage 2 refresh token (`__Host-rt`) and issues a new `__Host-at` + `__Host-rt`
/// pair in the same family. Replaying an already-used refresh token revokes the entire family.
pub async fn refresh_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let refresh_cookie_name = state.cookie_settings.refresh_cookie_name();
    let refresh_bytes = extract_token_cookie(&headers, refresh_cookie_name)
        .ok_or(ApiError::AuthenticationFailed)?;

    let pair = refresh_session(&state.pool, &refresh_bytes)
        .await
        .map_err(|err| match err {
            SessionError::Unauthorized => ApiError::AuthenticationFailed,
            SessionError::Database(_) => ApiError::InternalError,
        })?;

    let at_cookie = state
        .cookie_settings
        .build_access_cookie(&pair.access_token.to_base64url())
        .map_err(|_| ApiError::InternalError)?;
    let rt_cookie = state
        .cookie_settings
        .build_refresh_cookie(&pair.refresh_token.to_base64url())
        .map_err(|_| ApiError::InternalError)?;

    Ok((
        StatusCode::OK,
        AppendHeaders([(SET_COOKIE, at_cookie), (SET_COOKIE, rt_cookie)]),
        Json(StatusResponse {
            status: String::from("ok"),
        }),
    ))
}

/// `POST /auth/logout`
///
/// Revokes the caller's session family (usable in Stage 1 or Stage 2) and clears both cookies.
pub async fn logout_handler(
    State(state): State<Arc<AppState>>,
    SessionAuth(session): SessionAuth,
) -> Result<impl IntoResponse, ApiError> {
    logout_session_family(&state.pool, &session.user_id, &session.family_id)
        .await
        .map_err(|_| ApiError::InternalError)?;

    let clear_at = state.cookie_settings.build_clear_access_cookie();
    let clear_rt = state.cookie_settings.build_clear_refresh_cookie();

    Ok((
        StatusCode::OK,
        AppendHeaders([(SET_COOKIE, clear_at), (SET_COOKIE, clear_rt)]),
        Json(StatusResponse {
            status: String::from("ok"),
        }),
    ))
}

/// `GET /auth/session`
///
/// Returns `{ user_id, device_id, stage }` for an active Stage 1 or Stage 2 session.
pub async fn session_handler(SessionAuth(session): SessionAuth) -> Json<SessionResponse> {
    Json(SessionResponse {
        user_id: session.user_id,
        device_id: session.device_id,
        stage: session.stage,
    })
}

/// `GET /auth/devices`
///
/// Lists all devices owned by the authenticated Stage 2 user.
pub async fn list_devices_handler(
    State(state): State<Arc<AppState>>,
    FullAuth(session): FullAuth,
) -> Result<Json<DevicesListResponse>, ApiError> {
    let rows = list_user_devices(&state.pool, &session.user_id)
        .await
        .map_err(|_| ApiError::InternalError)?;

    let devices = rows
        .into_iter()
        .map(|row| DeviceResponse {
            id: row.id,
            name_enc: row.name_enc.map(|b| URL_SAFE_NO_PAD.encode(b)),
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            revoked_at: row.revoked_at,
        })
        .collect();

    Ok(Json(DevicesListResponse { devices }))
}

/// `DELETE /auth/devices/{id}`
///
/// Revokes an active device owned by the authenticated Stage 2 user and kills all its sessions.
/// Nonexistent devices and devices owned by other users return the exact same `404`.
pub async fn delete_device_handler(
    State(state): State<Arc<AppState>>,
    FullAuth(session): FullAuth,
    Path(device_id): Path<String>,
) -> Result<Json<StatusResponse>, ApiError> {
    let parsed_uuid = parse_uuid_str(&device_id).ok_or(ApiError::NotFound)?;
    let canonical_device_id = format_uuid(&parsed_uuid);

    let revoked = revoke_device_and_sessions(&state.pool, &session.user_id, &canonical_device_id)
        .await
        .map_err(|_| ApiError::InternalError)?;

    if !revoked {
        return Err(ApiError::NotFound);
    }

    Ok(Json(StatusResponse {
        status: String::from("ok"),
    }))
}
