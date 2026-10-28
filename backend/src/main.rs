#![forbid(unsafe_code)]

use std::{env, io, net::SocketAddr};
use strongroom_backend::build_app;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let host = env::var("HOST").unwrap_or_else(|_| String::from("0.0.0.0"));
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(3000);

    let bind_target = format!("{host}:{port}");
    let addr: SocketAddr = bind_target.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid HOST or PORT configuration",
        )
    })?;

    let listener = TcpListener::bind(addr).await?;
    let app = build_app();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
