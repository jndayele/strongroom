//! HTTP route handlers (Phase 0 skeleton: `GET /health` only).

use axum::{
    http::{header, StatusCode},
    response::IntoResponse,
};

/// `GET /health` liveness endpoint.
pub async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"status":"ok"}"#,
    )
}
