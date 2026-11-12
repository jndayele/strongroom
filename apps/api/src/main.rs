#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::sync::Arc;
use strongroom_api::auth::handlers::AppState;
use strongroom_api::build_router_with_state;
use strongroom_api::config::AppConfig;
use strongroom_api::db::connect_pool;
use tokio::net::TcpListener;
use tracing::Level;

fn log_level_from_env() -> Level {
    match env::var("LOG_LEVEL") {
        Ok(val) => match val.trim().to_ascii_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" | "warning" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        },
        Err(_) => Level::INFO,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_max_level(log_level_from_env())
        .with_ansi(false)
        .with_target(false)
        .init();

    let config = AppConfig::from_env()?;
    let addr = config.socket_addr();
    let pool = connect_pool(&config.database_url).await?;
    let state = Arc::new(AppState::new(
        pool,
        config.opaque_server_setup,
        config.credential_id_key,
        config.email_hash_key,
        config.app_origin,
        config.dev_insecure_cookies,
    ));

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "starting strongroom-api server");

    let app = build_router_with_state(state);
    axum::serve(listener, app).await?;

    Ok(())
}
