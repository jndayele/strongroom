#![forbid(unsafe_code)]

use std::error::Error;
use strongroom_api::{build_router, HealthResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn healthz_returns_ok_and_security_headers() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_router();

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;
    let raw_response = String::from_utf8(buffer)?;

    let (headers_section, body_section) = raw_response
        .split_once("\r\n\r\n")
        .ok_or("missing HTTP header/body separator")?;

    let headers_lower = headers_section.to_ascii_lowercase();
    assert!(headers_section.starts_with("HTTP/1.1 200 OK"));
    assert!(headers_lower.contains("x-content-type-options: nosniff"));
    assert!(headers_lower.contains("referrer-policy: no-referrer"));
    assert!(headers_lower.contains("cache-control: no-store"));

    let parsed: HealthResponse = serde_json::from_str(body_section.trim())?;
    assert_eq!(
        parsed,
        HealthResponse {
            status: String::from("ok"),
        }
    );

    server_handle.abort();
    Ok(())
}
