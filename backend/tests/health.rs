#![forbid(unsafe_code)]

use std::{collections::HashMap, error::Error, net::SocketAddr};
use strongroom_backend::{
    build_app, finalize_router_with_limits,
    middleware::{
        RouteBodyLimits, DEFAULT_MAX_REQUEST_BODY_BYTES, MAX_REQUEST_BODY_BYTES, SECURITY_HEADERS,
    },
    route_with_body_limit,
    routes::health,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct RawHttpResponse {
    status_line: String,
    headers: HashMap<String, String>,
    body: String,
}

async fn spawn_router(app: axum::Router) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

async fn spawn_test_server() -> Result<SocketAddr, Box<dyn Error>> {
    spawn_router(build_app()).await
}

async fn send_raw_http_request(
    addr: SocketAddr,
    raw_request: &[u8],
) -> Result<RawHttpResponse, Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(raw_request).await?;

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;
    let raw_text = String::from_utf8(buffer)?;

    let (head, body) = raw_text
        .split_once("\r\n\r\n")
        .ok_or("Missing HTTP header/body separator")?;

    let mut lines = head.lines();
    let status_line = lines.next().ok_or("Missing HTTP status line")?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    Ok(RawHttpResponse {
        status_line,
        headers,
        body: body.to_string(),
    })
}

fn assert_all_security_headers_present(
    headers: &HashMap<String, String>,
) -> Result<(), Box<dyn Error>> {
    for &(expected_name, expected_value) in SECURITY_HEADERS {
        let actual_value = headers
            .get(expected_name)
            .ok_or_else(|| format!("Missing required security header: {expected_name}"))?;
        assert_eq!(
            actual_value, expected_value,
            "Header mismatch for {expected_name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn get_health_returns_200_and_all_security_headers() -> Result<(), Box<dyn Error>> {
    let addr = spawn_test_server().await?;
    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let response = send_raw_http_request(addr, request).await?;
    assert!(
        response.status_line.starts_with("HTTP/1.1 200 OK"),
        "Unexpected status line: {}",
        response.status_line
    );
    assert_eq!(response.body, r#"{"status":"ok"}"#);
    assert_eq!(
        response.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_all_security_headers_present(&response.headers)?;
    Ok(())
}

#[tokio::test]
async fn unknown_route_returns_404_with_all_security_headers() -> Result<(), Box<dyn Error>> {
    let addr = spawn_test_server().await?;
    let request = b"GET /unknown-route HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let response = send_raw_http_request(addr, request).await?;
    assert!(
        response.status_line.starts_with("HTTP/1.1 404 Not Found"),
        "Unexpected status line: {}",
        response.status_line
    );
    assert_all_security_headers_present(&response.headers)?;
    Ok(())
}

#[tokio::test]
async fn wrong_method_returns_405_with_all_security_headers() -> Result<(), Box<dyn Error>> {
    let addr = spawn_test_server().await?;
    let request = b"DELETE /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    let response = send_raw_http_request(addr, request).await?;
    assert!(
        response
            .status_line
            .starts_with("HTTP/1.1 405 Method Not Allowed"),
        "Unexpected status line: {}",
        response.status_line
    );
    assert_all_security_headers_present(&response.headers)?;
    Ok(())
}

#[tokio::test]
async fn oversized_request_body_is_rejected_with_413_and_security_headers(
) -> Result<(), Box<dyn Error>> {
    let addr = spawn_test_server().await?;
    assert_eq!(DEFAULT_MAX_REQUEST_BODY_BYTES, 16 * 1024);
    let oversized_len = MAX_REQUEST_BODY_BYTES + 1024;
    let body = vec![b'a'; oversized_len];
    let mut request = format!(
        "POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: {oversized_len}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(&body);

    let response = send_raw_http_request(addr, &request).await?;
    assert!(
        response
            .status_line
            .starts_with("HTTP/1.1 413 Payload Too Large"),
        "Unexpected status line: {}",
        response.status_line
    );
    assert_eq!(response.body, r#"{"error":"request_too_large"}"#);
    assert_all_security_headers_present(&response.headers)?;
    Ok(())
}

#[tokio::test]
async fn oversized_chunked_stream_is_rejected_with_413_and_security_headers(
) -> Result<(), Box<dyn Error>> {
    let addr = spawn_test_server().await?;
    let chunk_size = MAX_REQUEST_BODY_BYTES + 512;
    let chunk_payload = "x".repeat(chunk_size);
    let raw_request = format!(
        "POST /health HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n",
        chunk_size, chunk_payload
    );

    let response = send_raw_http_request(addr, raw_request.as_bytes()).await?;
    assert!(
        response
            .status_line
            .starts_with("HTTP/1.1 413 Payload Too Large"),
        "Unexpected status line: {}",
        response.status_line
    );
    assert_eq!(response.body, r#"{"error":"request_too_large"}"#);
    assert_all_security_headers_present(&response.headers)?;
    Ok(())
}

#[tokio::test]
async fn per_route_body_limit_override_allows_larger_body_only_on_configured_route(
) -> Result<(), Box<dyn Error>> {
    let raised_limit = 32 * 1024; // 32 KiB for a specific route
    let mut limits = RouteBodyLimits::new();
    assert_eq!(limits.default_limit(), 16 * 1024);

    let router = axum::Router::new().route("/health", axum::routing::get(health));
    let router = route_with_body_limit(
        router,
        "/large-upload-test",
        axum::routing::post(|body: axum::body::Bytes| async move {
            format!("{{\"received\":{}}}", body.len())
        }),
        raised_limit,
        &mut limits,
    );
    let app = finalize_router_with_limits(router, limits);
    let addr = spawn_router(app).await?;

    // 1. A 24 KiB body (> 16 KiB default, <= 32 KiB override) succeeds on /large-upload-test
    let body_24k = vec![b'b'; 24 * 1024];
    let mut req_allowed = format!(
        "POST /large-upload-test HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_24k.len()
    )
    .into_bytes();
    req_allowed.extend_from_slice(&body_24k);

    let res_allowed = send_raw_http_request(addr, &req_allowed).await?;
    assert!(
        res_allowed.status_line.starts_with("HTTP/1.1 200 OK"),
        "Expected 200 OK on route with raised limit, got: {}",
        res_allowed.status_line
    );
    assert_eq!(res_allowed.body, r#"{"received":24576}"#);
    assert_all_security_headers_present(&res_allowed.headers)?;

    // 2. The exact same 24 KiB body is still rejected with 413 on /health (which uses the 16 KiB default)
    let mut req_default_rejected = format!(
        "GET /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_24k.len()
    )
    .into_bytes();
    req_default_rejected.extend_from_slice(&body_24k);

    let res_default_rejected = send_raw_http_request(addr, &req_default_rejected).await?;
    assert!(
        res_default_rejected
            .status_line
            .starts_with("HTTP/1.1 413 Payload Too Large"),
        "Expected 413 on default route for 24 KiB body, got: {}",
        res_default_rejected.status_line
    );
    assert_all_security_headers_present(&res_default_rejected.headers)?;

    // 3. A 33 KiB body (> 32 KiB override) is rejected with 413 on /large-upload-test
    let body_33k = vec![b'c'; 33 * 1024];
    let mut req_over_raised = format!(
        "POST /large-upload-test HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_33k.len()
    )
    .into_bytes();
    req_over_raised.extend_from_slice(&body_33k);

    let res_over_raised = send_raw_http_request(addr, &req_over_raised).await?;
    assert!(
        res_over_raised
            .status_line
            .starts_with("HTTP/1.1 413 Payload Too Large"),
        "Expected 413 when exceeding custom 32 KiB limit, got: {}",
        res_over_raised.status_line
    );
    assert_all_security_headers_present(&res_over_raised.headers)?;

    Ok(())
}
