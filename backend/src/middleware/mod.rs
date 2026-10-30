//! HTTP security middleware enforcing configurable per-route request-body size limits
//! (16 KiB default) and canonical security headers defined in `/security/headers/security-headers.json`.

use std::{collections::HashMap, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Default maximum request body size across all API routes (16 KiB).
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;

/// Alias for [`DEFAULT_MAX_REQUEST_BODY_BYTES`] (16 KiB).
pub const MAX_REQUEST_BODY_BYTES: usize = DEFAULT_MAX_REQUEST_BODY_BYTES;

/// Per-route request body size configuration with a 16 KiB default.
///
/// By default every route is capped at [`DEFAULT_MAX_REQUEST_BODY_BYTES`] (16 KiB).
/// Individual routes may deliberately raise (or lower) their limit via
/// [`RouteBodyLimits::set_route_limit`] or [`crate::route_with_body_limit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteBodyLimits {
    default_limit: usize,
    per_route: HashMap<String, usize>,
}

impl Default for RouteBodyLimits {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteBodyLimits {
    /// Creates a new configuration with [`DEFAULT_MAX_REQUEST_BODY_BYTES`] (16 KiB) as the default.
    pub fn new() -> Self {
        Self {
            default_limit: DEFAULT_MAX_REQUEST_BODY_BYTES,
            per_route: HashMap::new(),
        }
    }

    /// Creates a configuration with a custom default limit in bytes.
    pub fn with_default_limit(default_limit: usize) -> Self {
        Self {
            default_limit,
            per_route: HashMap::new(),
        }
    }

    /// Registers a deliberate request-body size limit (in bytes) for a specific route path.
    pub fn set_route_limit(&mut self, path: impl Into<String>, max_bytes: usize) -> &mut Self {
        self.per_route.insert(path.into(), max_bytes);
        self
    }

    /// Builder-style helper to register a per-route body size limit (in bytes).
    pub fn with_route_limit(mut self, path: impl Into<String>, max_bytes: usize) -> Self {
        self.set_route_limit(path, max_bytes);
        self
    }

    /// Returns the configured default limit in bytes (16 KiB unless customized).
    pub fn default_limit(&self) -> usize {
        self.default_limit
    }

    /// Returns the effective body limit in bytes for `path`
    /// (the route-specific override if present, otherwise [`Self::default_limit`]).
    pub fn limit_for_path(&self, path: &str) -> usize {
        self.per_route
            .get(path)
            .copied()
            .unwrap_or(self.default_limit)
    }

    /// Returns the highest limit across the default and all registered per-route overrides,
    /// used to configure Axum's extractor-level `DefaultBodyLimit`.
    pub fn max_configured_limit(&self) -> usize {
        self.per_route
            .values()
            .copied()
            .fold(self.default_limit, usize::max)
    }
}

/// Canonical security headers mirrored from `/security/headers/security-headers.json`.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("cache-control", "no-store"),
    ("x-frame-options", "DENY"),
];

/// Attaches all canonical security headers to an outgoing HTTP [`Response`].
pub fn apply_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    for &(name, value) in SECURITY_HEADERS {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }
}

/// Enforces `max_body_bytes` on the incoming request (checking both `Content-Length`
/// and the streamed body via [`to_bytes`]) and attaches all canonical security headers
/// to the resulting response.
pub async fn enforce_limit_and_headers(
    request: Request,
    next: Next,
    max_body_bytes: usize,
) -> Response {
    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH) {
        let declared_len = content_length
            .to_str()
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok());

        match declared_len {
            Some(len) if len > max_body_bytes => {
                let mut response = (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"request_too_large"}"#,
                )
                    .into_response();
                apply_security_headers(&mut response);
                return response;
            }
            None => {
                let mut response = (
                    StatusCode::BAD_REQUEST,
                    [(header::CONTENT_TYPE, "application/json")],
                    r#"{"error":"invalid_request"}"#,
                )
                    .into_response();
                apply_security_headers(&mut response);
                return response;
            }
            Some(_) => {}
        }
    }

    let (parts, body) = request.into_parts();
    match to_bytes(body, max_body_bytes).await {
        Ok(bytes) => {
            let rebuilt_request = Request::from_parts(parts, Body::from(bytes));
            let mut response = next.run(rebuilt_request).await;
            apply_security_headers(&mut response);
            response
        }
        Err(_) => {
            let mut response = (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"request_too_large"}"#,
            )
                .into_response();
            apply_security_headers(&mut response);
            response
        }
    }
}

/// Route-aware middleware that resolves the effective body limit for the request URI path
/// from [`RouteBodyLimits`] (defaulting to 16 KiB) and attaches all security headers.
pub async fn security_middleware_with_limits(
    State(limits): State<Arc<RouteBodyLimits>>,
    request: Request,
    next: Next,
) -> Response {
    let max_body_bytes = limits.limit_for_path(request.uri().path());
    enforce_limit_and_headers(request, next, max_body_bytes).await
}

/// Default middleware enforcing [`DEFAULT_MAX_REQUEST_BODY_BYTES`] (16 KiB)
/// and attaching all canonical security headers to every response.
pub async fn security_middleware(request: Request, next: Next) -> Response {
    enforce_limit_and_headers(request, next, DEFAULT_MAX_REQUEST_BODY_BYTES).await
}
