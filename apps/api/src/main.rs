#![forbid(unsafe_code)]

use std::error::Error;
use strongroom_api::build_router;
use strongroom_api::config::AppConfig;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let config = AppConfig::from_env()?;
    let addr = config.socket_addr();

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "starting strongroom-api server");

    let app = build_router();
    axum::serve(listener, app).await?;

    Ok(())
}
