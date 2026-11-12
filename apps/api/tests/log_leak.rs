#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use strongroom_api::auth::handlers::{
    AppState, LoginFinishRequest, LoginStartRequest, LoginStartResponse, SessionResponse,
    SignupFinishRequest, SignupStartRequest, SignupStartResponse,
};
use strongroom_api::auth::sessions::upgrade_session_after_mfa;
use strongroom_api::build_router_with_state;
use strongroom_api::config::{CredentialIdKey, EmailHashKey, OpaqueServerSetup};
use strongroom_api::db::connect_pool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tracing_subscriber::fmt::MakeWriter;

struct TestClientSuite;

impl CipherSuite for TestClientSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

fn test_ksf() -> Result<Argon2<'static>, Box<dyn Error>> {
    let params = Params::new(32, 1, 1, None).map_err(|e| format!("argon2 params error: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn b64_decode(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| format!("base64 decode error: {e}").into())
}

#[derive(Clone, Default)]
struct LogBuffer {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl LogBuffer {
    fn snapshot(&self) -> String {
        let guard = self
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        String::from_utf8_lossy(&guard).into_owned()
    }
}

struct LogBufferWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for LogBufferWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .bytes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogBufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogBufferWriter {
            bytes: Arc::clone(&self.bytes),
        }
    }
}

fn app_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| {
        String::from("postgres://vault_app:local_app_password_only@127.0.0.1:5432/vault_dev")
    })
}

fn migrator_database_url() -> String {
    env::var("MIGRATOR_DATABASE_URL").unwrap_or_else(|_| {
        String::from(
            "postgres://vault_migrator:local_migrator_password_only@127.0.0.1:5432/vault_dev",
        )
    })
}

struct TestServer {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, Vec<String>, Vec<u8>), Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut req_head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    for (k, v) in extra_headers {
        req_head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        req_head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req_head.push_str("Connection: close\r\n\r\n");

    stream.write_all(req_head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;

    let sep_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing HTTP header/body separator")?;
    let headers_str = std::str::from_utf8(&raw[..sep_pos])?;
    let body_bytes = raw[sep_pos + 4..].to_vec();

    let mut lines = headers_str.lines();
    let status_line = lines.next().ok_or("missing HTTP status line")?;
    let mut parts = status_line.split_whitespace();
    let _http_ver = parts.next().ok_or("missing HTTP version")?;
    let status_code: u16 = parts.next().ok_or("missing status code")?.parse()?;

    let mut set_cookies = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("set-cookie") {
                set_cookies.push(v.trim().to_string());
            }
        }
    }

    Ok((status_code, set_cookies, body_bytes))
}

fn extract_cookie_val(set_cookies: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    for hdr in set_cookies {
        if let Some(rest) = hdr.strip_prefix(&prefix) {
            return Some(rest.split(';').next().unwrap_or("").to_string());
        }
    }
    None
}

async fn http_post(
    addr: SocketAddr,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let mut headers = Vec::new();
    if let Some(ct) = content_type {
        headers.push(("Content-Type", ct));
    }
    let (status, _, resp_body) = http_request(addr, "POST", path, &headers, body).await?;
    Ok((status, resp_body))
}

async fn http_post_json<T: serde::Serialize>(
    addr: SocketAddr,
    path: &str,
    payload: &T,
) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let body = serde_json::to_vec(payload)?;
    http_post(addr, path, Some("application/json"), &body).await
}

#[tokio::test]
async fn tracing_output_never_leaks_emails_base64_login_id_or_secrets() -> Result<(), Box<dyn Error>>
{
    let log_buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_target(false)
        .with_writer(log_buffer.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let status = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env("MIGRATOR_DATABASE_URL", migrator_database_url())
        .status()?;
    if !status.success() {
        return Err(format!("migrate binary failed with status: {status}").into());
    }

    let pool = connect_pool(&app_database_url()).await?;
    let migrator_pool = connect_pool(&migrator_database_url()).await?;
    let setup = OpaqueServerSetup::generate();
    let cred_key = CredentialIdKey::from_bytes([0x3A; 32]);
    let email_key = EmailHashKey::from_bytes([0x7C; 32]);

    let setup_b64 = URL_SAFE_NO_PAD.encode(setup.to_bytes());
    let cred_key_b64 = URL_SAFE_NO_PAD.encode(cred_key.as_bytes());
    let email_key_b64 = URL_SAFE_NO_PAD.encode(email_key.as_bytes());

    let state = Arc::new(AppState::new(
        pool.clone(),
        setup,
        cred_key,
        email_key,
        String::from("https://app.strongroom.example"),
        false,
    ));
    tracing::debug!(state = ?state, "initialized app state for log leak test");

    let app = build_router_with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let server = TestServer { addr, handle };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let known_email_raw = format!("  Alice.LogLeak.{nanos}@Example.COM ");
    let known_email_canon = format!("alice.logleak.{nanos}@example.com");
    let unknown_email = format!("unknown.logleak.{nanos}@example.com");
    let non_ascii_email = format!("alité.logleak.{nanos}@example.com");
    let password = b"LogLeakTestPassword!2026";
    let wrong_password = b"WrongLogLeakPassword!999";

    let mut forbidden: Vec<(&'static str, String)> = vec![
        ("opaque_server_setup", setup_b64),
        ("credential_id_key", cred_key_b64),
        ("email_hash_key", email_key_b64),
        ("known_email_raw", known_email_raw.clone()),
        ("known_email_canon", known_email_canon.clone()),
        ("unknown_email", unknown_email.clone()),
        ("non_ascii_email", non_ascii_email.clone()),
        ("password", String::from_utf8_lossy(password).into_owned()),
    ];

    let mut rng = OsRng;
    let ksf = test_ksf()?;

    // 1. Full signup flow (start + finish)
    let client_reg_start = ClientRegistration::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client registration start failed")?;
    let reg_req_b64 = URL_SAFE_NO_PAD.encode(client_reg_start.message.serialize());
    forbidden.push(("signup_registration_request", reg_req_b64.clone()));

    let (st, body) = http_post_json(
        server.addr,
        "/auth/signup/start",
        &SignupStartRequest {
            email: known_email_raw.clone(),
            registration_request: reg_req_b64,
        },
    )
    .await?;
    assert_eq!(st, 200);
    let signup_start_resp: SignupStartResponse = serde_json::from_slice(&body)?;
    forbidden.push((
        "signup_registration_response",
        signup_start_resp.registration_response.clone(),
    ));

    let reg_resp = RegistrationResponse::<TestClientSuite>::deserialize(&b64_decode(
        &signup_start_resp.registration_response,
    )?)
    .map_err(|_| "deserialize RegistrationResponse failed")?;
    let client_reg_finish = client_reg_start
        .state
        .finish(
            &mut rng,
            password,
            reg_resp,
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "client registration finish failed")?;

    let record_b64 = URL_SAFE_NO_PAD.encode(client_reg_finish.message.serialize());
    let wrapped_km_b64 = URL_SAFE_NO_PAD.encode([0xA1u8; 48]);
    let wrapped_ks_b64 = URL_SAFE_NO_PAD.encode([0xB2u8; 48]);
    forbidden.push(("registration_record", record_b64.clone()));
    forbidden.push(("wrapped_km", wrapped_km_b64.clone()));
    forbidden.push(("wrapped_ks_master", wrapped_ks_b64.clone()));

    let (st, _) = http_post_json(
        server.addr,
        "/auth/signup/finish",
        &SignupFinishRequest {
            email: known_email_raw,
            registration_record: record_b64,
            wrapped_km: wrapped_km_b64,
            wrapped_ks_master: wrapped_ks_b64,
        },
    )
    .await?;
    assert_eq!(st, 200);

    // 2. Full login flow (start + finish -> 200)
    let client_login_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;
    let login_cred_req_b64 = URL_SAFE_NO_PAD.encode(client_login_start.message.serialize());
    forbidden.push(("login_credential_request", login_cred_req_b64.clone()));

    let (st, body) = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: known_email_canon.clone(),
            credential_request: login_cred_req_b64,
        },
    )
    .await?;
    assert_eq!(st, 200);
    let login_start_resp: LoginStartResponse = serde_json::from_slice(&body)?;
    forbidden.push(("known_login_id", login_start_resp.login_id.clone()));
    forbidden.push((
        "login_credential_response",
        login_start_resp.credential_response.clone(),
    ));

    let cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &login_start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize CredentialResponse failed")?;
    let client_login_finish = client_login_start
        .state
        .finish(
            &mut rng,
            password,
            cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "client login finish failed")?;
    let finalization_b64 = URL_SAFE_NO_PAD.encode(client_login_finish.message.serialize());
    forbidden.push(("credential_finalization", finalization_b64.clone()));

    let finish_req = LoginFinishRequest {
        login_id: login_start_resp.login_id,
        credential_finalization: finalization_b64.clone(),
        device_id: None,
    };
    let finish_body = serde_json::to_vec(&finish_req)?;
    let (st, finish_cookies, _) = http_request(
        server.addr,
        "POST",
        "/auth/login/finish",
        &[("Content-Type", "application/json")],
        &finish_body,
    )
    .await?;
    assert_eq!(st, 200);

    let stage1_at =
        extract_cookie_val(&finish_cookies, "__Host-at").ok_or("missing stage-1 __Host-at")?;
    let stage1_at_raw = b64_decode(&stage1_at)?;
    let stage1_at_hash: [u8; 32] = Sha256::digest(&stage1_at_raw).into();
    forbidden.push(("stage1_access_token", stage1_at.clone()));
    forbidden.push(("stage1_cookie_hdr", format!("__Host-at={stage1_at}")));
    forbidden.push((
        "stage1_access_hash_b64",
        URL_SAFE_NO_PAD.encode(stage1_at_hash),
    ));

    // 2b. Exercise session, upgrade_session_after_mfa, devices, refresh, and logout
    let (st, _, sess_bytes) = http_request(
        server.addr,
        "GET",
        "/auth/session",
        &[("Cookie", &format!("__Host-at={stage1_at}"))],
        b"",
    )
    .await?;
    assert_eq!(st, 200);
    let sess_resp: SessionResponse = serde_json::from_slice(&sess_bytes)?;
    let session_id: String =
        sqlx::query_scalar("SELECT id::text FROM sessions WHERE access_hash = $1")
            .bind(&stage1_at_hash[..])
            .fetch_one(&migrator_pool)
            .await?;

    let pair = upgrade_session_after_mfa(&pool, &sess_resp.user_id, &session_id)
        .await
        .map_err(|_| "upgrade_session_after_mfa failed")?;
    let stage2_at = pair.access_token.to_base64url();
    let stage2_rt = pair.refresh_token.to_base64url();
    forbidden.push(("stage2_access_token", stage2_at.clone()));
    forbidden.push(("stage2_refresh_token", stage2_rt.clone()));
    forbidden.push((
        "stage2_access_hash_b64",
        URL_SAFE_NO_PAD.encode(pair.access_token.sha256()),
    ));
    forbidden.push((
        "stage2_refresh_hash_b64",
        URL_SAFE_NO_PAD.encode(pair.refresh_token.sha256()),
    ));

    let (st, _, _) = http_request(
        server.addr,
        "GET",
        "/auth/devices",
        &[("Cookie", &format!("__Host-at={stage2_at}"))],
        b"",
    )
    .await?;
    assert_eq!(st, 200);

    let (st, refresh_cookies, _) = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={stage2_rt}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(st, 200);
    let refreshed_at =
        extract_cookie_val(&refresh_cookies, "__Host-at").ok_or("missing refreshed at")?;
    let refreshed_rt =
        extract_cookie_val(&refresh_cookies, "__Host-rt").ok_or("missing refreshed rt")?;
    forbidden.push(("refreshed_access_token", refreshed_at.clone()));
    forbidden.push(("refreshed_refresh_token", refreshed_rt.clone()));
    forbidden.push(("refreshed_cookie_hdr", format!("__Host-at={refreshed_at}")));

    let (st, _, _) = http_request(
        server.addr,
        "POST",
        "/auth/logout",
        &[
            ("Cookie", &format!("__Host-at={refreshed_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(st, 200);

    // 3. Failure cases:
    // 3a. Replayed login_id -> 401
    let (st, _) = http_post_json(server.addr, "/auth/login/finish", &finish_req).await?;
    assert_eq!(st, 401);

    // 3b. Wrong password / tampered finalization -> 401
    let wrong_start = ClientLogin::<TestClientSuite>::start(&mut rng, wrong_password)
        .map_err(|_| "wrong client login start failed")?;
    let wrong_req_b64 = URL_SAFE_NO_PAD.encode(wrong_start.message.serialize());
    forbidden.push(("wrong_credential_request", wrong_req_b64.clone()));

    let (st, body) = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: known_email_canon,
            credential_request: wrong_req_b64,
        },
    )
    .await?;
    assert_eq!(st, 200);
    let wrong_start_resp: LoginStartResponse = serde_json::from_slice(&body)?;
    forbidden.push(("wrong_login_id", wrong_start_resp.login_id.clone()));
    forbidden.push((
        "wrong_credential_response",
        wrong_start_resp.credential_response.clone(),
    ));

    let (st, _) = http_post_json(
        server.addr,
        "/auth/login/finish",
        &LoginFinishRequest {
            login_id: wrong_start_resp.login_id,
            credential_finalization: finalization_b64.clone(),
            device_id: None,
        },
    )
    .await?;
    assert_eq!(st, 401);

    // 3c. Unknown email -> 200 start, 401 finish
    let unknown_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "unknown client login start failed")?;
    let unknown_req_b64 = URL_SAFE_NO_PAD.encode(unknown_start.message.serialize());
    forbidden.push(("unknown_credential_request", unknown_req_b64.clone()));

    let (st, body) = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: unknown_email,
            credential_request: unknown_req_b64,
        },
    )
    .await?;
    assert_eq!(st, 200);
    let unknown_start_resp: LoginStartResponse = serde_json::from_slice(&body)?;
    forbidden.push(("unknown_login_id", unknown_start_resp.login_id.clone()));
    forbidden.push((
        "unknown_credential_response",
        unknown_start_resp.credential_response.clone(),
    ));

    let (st, _) = http_post_json(
        server.addr,
        "/auth/login/finish",
        &LoginFinishRequest {
            login_id: unknown_start_resp.login_id,
            credential_finalization: finalization_b64,
            device_id: None,
        },
    )
    .await?;
    assert_eq!(st, 401);

    // 3d. Non-ASCII email -> 400
    let bad_b64_marker = String::from("NonAsciiMarkerBase64PayloadValue12345");
    forbidden.push(("non_ascii_b64_marker", bad_b64_marker.clone()));
    let (st, _) = http_post_json(
        server.addr,
        "/auth/signup/start",
        &SignupStartRequest {
            email: non_ascii_email,
            registration_request: bad_b64_marker,
        },
    )
    .await?;
    assert_eq!(st, 400);

    // 3e. Unknown JSON field -> 400
    let unknown_field_b64 = String::from("UnknownFieldMarkerBase64Payload98765");
    forbidden.push(("unknown_field_b64_marker", unknown_field_b64.clone()));
    let unknown_field_json = format!(
        "{{\"email\":\"bad.field.{nanos}@example.com\",\"registration_request\":\"{unknown_field_b64}\",\"extra\":true}}"
    );
    forbidden.push((
        "unknown_field_email",
        format!("bad.field.{nanos}@example.com"),
    ));
    let (st, _) = http_post(
        server.addr,
        "/auth/signup/start",
        Some("application/json"),
        unknown_field_json.as_bytes(),
    )
    .await?;
    assert_eq!(st, 400);

    // 3f. Missing Content-Type -> 400
    let (st, _) = http_post(
        server.addr,
        "/auth/signup/start",
        None,
        unknown_field_json.as_bytes(),
    )
    .await?;
    assert_eq!(st, 400);

    // 3g. Oversized body -> 413
    let oversized_marker = "Z".repeat(17 * 1024);
    let oversized_json = format!(
        "{{\"email\":\"oversized.{nanos}@example.com\",\"registration_request\":\"{oversized_marker}\"}}"
    );
    forbidden.push(("oversized_email", format!("oversized.{nanos}@example.com")));
    forbidden.push(("oversized_marker", String::from("ZZZZZZZZZZZZZZZZ")));
    let (st, _) = http_post(
        server.addr,
        "/auth/signup/start",
        Some("application/json"),
        oversized_json.as_bytes(),
    )
    .await?;
    assert_eq!(st, 413);

    // Inspect captured tracing logs
    let captured_logs = log_buffer.snapshot();
    println!(
        "=== CAPTURED TRACING LOGS START ===\n{captured_logs}=== CAPTURED TRACING LOGS END ==="
    );

    assert!(captured_logs.contains("auth.signup.start"));
    assert!(captured_logs.contains("auth.signup.finish"));
    assert!(captured_logs.contains("auth.login.start"));
    assert!(captured_logs.contains("auth.login.finish"));
    assert!(captured_logs.contains("auth.session"));
    assert!(captured_logs.contains("auth.devices.list"));
    assert!(captured_logs.contains("auth.refresh"));
    assert!(captured_logs.contains("auth.logout"));
    assert!(captured_logs.contains("status=200"));
    assert!(captured_logs.contains("status=400"));
    assert!(captured_logs.contains("status=401"));
    assert!(captured_logs.contains("status=413"));
    assert!(!captured_logs.contains("rows_returned"));
    assert!(!captured_logs.contains("rows_affected"));

    for (label, value) in &forbidden {
        assert!(
            !captured_logs.contains(value.as_str()),
            "sensitive value '{label}' leaked into tracing logs"
        );
    }

    Ok(())
}
