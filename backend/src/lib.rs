#![forbid(unsafe_code)]

//! Strongroom backend library crate (Phase 0 skeleton).

pub mod auth;
pub mod db;
pub mod middleware;
pub mod routes;

use axum::{extract::DefaultBodyLimit, middleware::from_fn, routing::get, Router};

use crate::middleware::{security_middleware, MAX_REQUEST_BODY_BYTES};
use crate::routes::health;

/// Builds the Axum application router with strict request-body limits
/// and mandatory security headers on every response.
pub fn build_app() -> Router {
    Router::new()
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(from_fn(security_middleware))
}
