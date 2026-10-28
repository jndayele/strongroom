//! HTTP security middleware enforcing strict request-body size limits
//! and canonical security headers defined in `/security/headers/security-headers.json`.

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{header, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Strict maximum request body size for the API (16 KiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;

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

/// Middleware that enforces [`MAX_REQUEST_BODY_BYTES`] on every incoming request
/// (both via `Content-Length` pre-check and stream consumption limit) and attaches
/// all canonical security headers to every response (including `413`, `404`, and `405`).
pub async fn security_middleware(request: Request, next: Next) -> Response {
    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH) {
        let declared_len = content_length
            .to_str()
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok());

        match declared_len {
            Some(len) if len > MAX_REQUEST_BODY_BYTES => {
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
    match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
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
