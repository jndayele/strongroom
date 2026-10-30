#![forbid(unsafe_code)]

//! Strongroom backend library crate (Phase 0 skeleton).

pub mod auth;
pub mod db;
pub mod middleware;
pub mod routes;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    middleware::from_fn_with_state,
    routing::{get, MethodRouter},
    Router,
};

use crate::middleware::{security_middleware_with_limits, RouteBodyLimits};
use crate::routes::health;

/// Registers a route with a deliberate per-route request-body limit (in bytes),
/// overriding the 16 KiB default for `path`.
pub fn route_with_body_limit(
    router: Router,
    path: &str,
    method_router: MethodRouter,
    max_bytes: usize,
    limits: &mut RouteBodyLimits,
) -> Router {
    limits.set_route_limit(path, max_bytes);
    router.route(path, method_router.layer(DefaultBodyLimit::max(max_bytes)))
}

/// Wraps an Axum [`Router`] with the configured [`RouteBodyLimits`] (16 KiB default)
/// and attaches mandatory security headers to every response.
pub fn finalize_router_with_limits(router: Router, limits: RouteBodyLimits) -> Router {
    let extractor_cap = limits.max_configured_limit();
    router
        .layer(DefaultBodyLimit::max(extractor_cap))
        .layer(from_fn_with_state(
            Arc::new(limits),
            security_middleware_with_limits,
        ))
}

/// Builds the default Axum application router with the 16 KiB default request-body limit
/// and mandatory security headers on every response.
pub fn build_app() -> Router {
    let limits = RouteBodyLimits::new();
    let router = Router::new().route("/health", get(health));
    finalize_router_with_limits(router, limits)
}
