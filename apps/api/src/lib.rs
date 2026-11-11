#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod db;

use axum::extract::DefaultBodyLimit;
use axum::extract::Request;
use axum::http::header::{CACHE_CONTROL, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::handlers::{
    auth_logging_middleware, login_finish_handler, login_start_handler, signup_finish_handler,
    signup_start_handler, AppState,
};

/// Maximum allowed HTTP request body size (16 KiB).
pub const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: String::from("ok"),
    })
}

async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    response
}

pub fn build_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(security_headers_middleware))
}

pub fn build_router_with_state(state: Arc<AppState>) -> Router {
    let auth_router = Router::new()
        .route("/signup/start", post(signup_start_handler))
        .route("/signup/finish", post(signup_finish_handler))
        .route("/login/start", post(login_start_handler))
        .route("/login/finish", post(login_finish_handler))
        .layer(middleware::from_fn(auth_logging_middleware))
        .with_state(state);

    Router::new()
        .route("/healthz", get(healthz))
        .nest("/auth", auth_router)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(security_headers_middleware))
}
