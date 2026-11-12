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
use sqlx::{PgPool, Row};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use strongroom_api::auth::handlers::{
    AppState, DeviceResponse, DevicesListResponse, LoginFinishRequest, LoginFinishResponse,
    LoginStartRequest, LoginStartResponse, SessionResponse, SignupFinishRequest,
    SignupStartRequest, SignupStartResponse, StatusResponse,
};
use strongroom_api::auth::sessions::upgrade_session_after_mfa;
use strongroom_api::build_router_with_state;
use strongroom_api::config::{CredentialIdKey, EmailHashKey, OpaqueServerSetup};
use strongroom_api::db::connect_pool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

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
    state: Arc<AppState>,
    migrator_pool: PgPool,
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_test_server_with_opts(
    app_origin: &str,
    dev_insecure_cookies: bool,
) -> Result<TestServer, Box<dyn Error>> {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env("MIGRATOR_DATABASE_URL", migrator_database_url())
        .status()?;

    if !status.success() {
        return Err(format!("migrate binary failed with status: {status}").into());
    }

    let pool = connect_pool(&app_database_url()).await?;
    let migrator_pool = connect_pool(&migrator_database_url()).await?;
    let setup = OpaqueServerSetup::generate();
    let cred_key = CredentialIdKey::from_bytes([0x41; 32]);
    let email_key = EmailHashKey::from_bytes([0x82; 32]);

    let state = Arc::new(AppState::new(
        pool,
        setup,
        cred_key,
        email_key,
        String::from(app_origin),
        dev_insecure_cookies,
    ));
    let app = build_router_with_state(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(TestServer {
        addr,
        state,
        migrator_pool,
        handle,
    })
}

async fn spawn_test_server() -> Result<TestServer, Box<dyn Error>> {
    spawn_test_server_with_opts("https://app.strongroom.example", false).await
}

fn unique_test_email(prefix: &str) -> Result<String, Box<dyn Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{prefix}.{nanos}@example.com"))
}

struct RawHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RawHttpResponse {
    fn header_values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn first_header(&self, name: &str) -> Option<&str> {
        self.header_values(name).into_iter().next()
    }

    fn set_cookies(&self) -> Vec<&str> {
        self.header_values("set-cookie")
    }
}

async fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> Result<RawHttpResponse, Box<dyn Error>> {
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

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok(RawHttpResponse {
        status: status_code,
        headers,
        body: body_bytes,
    })
}

async fn http_post_json<T: serde::Serialize>(
    addr: SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
    payload: &T,
) -> Result<RawHttpResponse, Box<dyn Error>> {
    let body = serde_json::to_vec(payload)?;
    let mut headers = Vec::with_capacity(extra_headers.len() + 1);
    headers.push(("Content-Type", "application/json"));
    headers.extend_from_slice(extra_headers);
    http_request(addr, "POST", path, &headers, &body).await
}

fn extract_cookie_value(set_cookie_headers: &[&str], cookie_name: &str) -> Option<String> {
    let prefix = format!("{cookie_name}=");
    for hdr in set_cookie_headers {
        if let Some(rest) = hdr.strip_prefix(&prefix) {
            let val = rest.split(';').next().unwrap_or("");
            return Some(val.to_string());
        }
    }
    None
}

async fn signup_and_login_stage1(
    addr: SocketAddr,
    email: &str,
    password: &[u8],
    device_id: Option<&str>,
) -> Result<(RawHttpResponse, String), Box<dyn Error>> {
    let mut rng = OsRng;
    let ksf = test_ksf()?;

    // Signup
    let reg_start = ClientRegistration::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client reg start failed")?;
    let reg_start_http = http_post_json(
        addr,
        "/auth/signup/start",
        &[],
        &SignupStartRequest {
            email: String::from(email),
            registration_request: URL_SAFE_NO_PAD.encode(reg_start.message.serialize()),
        },
    )
    .await?;
    assert_eq!(reg_start_http.status, 200);
    let reg_start_resp: SignupStartResponse = serde_json::from_slice(&reg_start_http.body)?;
    let reg_resp = RegistrationResponse::<TestClientSuite>::deserialize(&b64_decode(
        &reg_start_resp.registration_response,
    )?)
    .map_err(|_| "reg resp deserialize failed")?;
    let reg_finish = reg_start
        .state
        .finish(
            &mut rng,
            password,
            reg_resp,
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "client reg finish failed")?;

    let reg_finish_http = http_post_json(
        addr,
        "/auth/signup/finish",
        &[],
        &SignupFinishRequest {
            email: String::from(email),
            registration_record: URL_SAFE_NO_PAD.encode(reg_finish.message.serialize()),
            wrapped_km: URL_SAFE_NO_PAD.encode([0xAAu8; 48]),
            wrapped_ks_master: URL_SAFE_NO_PAD.encode([0xBBu8; 48]),
        },
    )
    .await?;
    assert_eq!(reg_finish_http.status, 200);

    // Login
    login_stage1_existing_user(addr, email, password, device_id).await
}

async fn login_stage1_existing_user(
    addr: SocketAddr,
    email: &str,
    password: &[u8],
    device_id: Option<&str>,
) -> Result<(RawHttpResponse, String), Box<dyn Error>> {
    let mut rng = OsRng;
    let ksf = test_ksf()?;

    let login_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;
    let login_start_http = http_post_json(
        addr,
        "/auth/login/start",
        &[],
        &LoginStartRequest {
            email: String::from(email),
            credential_request: URL_SAFE_NO_PAD.encode(login_start.message.serialize()),
        },
    )
    .await?;
    assert_eq!(login_start_http.status, 200);
    let login_start_resp: LoginStartResponse = serde_json::from_slice(&login_start_http.body)?;
    let cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &login_start_resp.credential_response,
    )?)
    .map_err(|_| "cred resp deserialize failed")?;
    let login_finish = login_start
        .state
        .finish(
            &mut rng,
            password,
            cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "client login finish failed")?;

    let login_finish_http = http_post_json(
        addr,
        "/auth/login/finish",
        &[],
        &LoginFinishRequest {
            login_id: login_start_resp.login_id,
            credential_finalization: URL_SAFE_NO_PAD.encode(login_finish.message.serialize()),
            device_id: device_id.map(String::from),
        },
    )
    .await?;
    assert_eq!(login_finish_http.status, 200);
    let parsed: LoginFinishResponse = serde_json::from_slice(&login_finish_http.body)?;
    assert_eq!(parsed.status, "mfa_required");

    let cookie_val = extract_cookie_value(&login_finish_http.set_cookies(), "__Host-at")
        .ok_or("missing __Host-at cookie on login/finish")?;

    Ok((login_finish_http, cookie_val))
}

async fn get_session_info(
    addr: SocketAddr,
    cookie_header: &str,
) -> Result<(u16, Vec<u8>), Box<dyn Error>> {
    let resp = http_request(
        addr,
        "GET",
        "/auth/session",
        &[("Cookie", cookie_header)],
        b"",
    )
    .await?;
    Ok((resp.status, resp.body))
}

async fn find_session_id_by_access_token(
    pool: &PgPool,
    access_token: &str,
) -> Result<String, Box<dyn Error>> {
    let raw = b64_decode(access_token)?;
    let hash: [u8; 32] = Sha256::digest(&raw).into();
    let id: String = sqlx::query_scalar("SELECT id::text FROM sessions WHERE access_hash = $1")
        .bind(&hash[..])
        .fetch_one(pool)
        .await?;
    Ok(id)
}

#[tokio::test]
async fn stage1_to_stage2_cookies_attributes_and_db_stores_no_raw_tokens(
) -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email = unique_test_email("s1s2.alice")?;
    let password = b"StageOneAndTwoPassword!99";

    let (login_resp, stage1_at) =
        signup_and_login_stage1(server.addr, &email, password, None).await?;

    // 1. Stage-1 cookie has exact required attributes: __Host-at, HttpOnly, Secure, SameSite=Strict, Path=/, NO Domain, NO __Host-rt.
    let set_cookies = login_resp.set_cookies();
    assert_eq!(set_cookies.len(), 1);
    let stage1_cookie_hdr = set_cookies[0];
    assert_eq!(
        stage1_cookie_hdr,
        format!("__Host-at={stage1_at}; HttpOnly; Secure; SameSite=Strict; Path=/")
    );
    assert!(!stage1_cookie_hdr.to_ascii_lowercase().contains("domain="));
    assert_eq!(extract_cookie_value(&set_cookies, "__Host-rt"), None);

    // 2. Stage 1 works on /auth/session -> {user_id, device_id, stage: 1}
    let stage1_cookie = format!("__Host-at={stage1_at}");
    let (sess_status, sess_body) = get_session_info(server.addr, &stage1_cookie).await?;
    assert_eq!(sess_status, 200);
    let sess_info: SessionResponse = serde_json::from_slice(&sess_body)?;
    assert_eq!(sess_info.stage, 1);

    // 3. Stage 1 CANNOT call Stage 2 routes (GET /auth/devices, DELETE /auth/devices/{id})
    let devices_resp = http_request(
        server.addr,
        "GET",
        "/auth/devices",
        &[("Cookie", &stage1_cookie)],
        b"",
    )
    .await?;
    assert_eq!(devices_resp.status, 403);

    let del_resp = http_request(
        server.addr,
        "DELETE",
        &format!("/auth/devices/{}", sess_info.device_id),
        &[("Cookie", &stage1_cookie), ("X-Vault-CSRF", "1")],
        b"",
    )
    .await?;
    assert_eq!(del_resp.status, 403);

    // Stage 1 has no refresh token; passing stage1_at as __Host-rt fails with uniform 401.
    let fake_refresh = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={stage1_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(fake_refresh.status, 401);
    assert_eq!(fake_refresh.body, b"{\"error\":\"authentication_failed\"}");

    // 4. Upgrade to Stage 2 directly via upgrade_session_after_mfa(...)
    let session_id = find_session_id_by_access_token(&server.migrator_pool, &stage1_at).await?;
    let pair = upgrade_session_after_mfa(&server.state.pool, &sess_info.user_id, &session_id)
        .await
        .map_err(|_| "upgrade_session_after_mfa failed")?;
    let stage2_at = pair.access_token.to_base64url();
    let stage2_rt = pair.refresh_token.to_base64url();

    // Old Stage-1 token no longer works
    let (old_status, old_body) = get_session_info(server.addr, &stage1_cookie).await?;
    assert_eq!(old_status, 401);
    assert_eq!(old_body, b"{\"error\":\"authentication_failed\"}");

    // New Stage-2 cookies work on /auth/session and /auth/devices
    let stage2_cookie = format!("__Host-at={stage2_at}");
    let (new_status, new_body) = get_session_info(server.addr, &stage2_cookie).await?;
    assert_eq!(new_status, 200);
    let new_info: SessionResponse = serde_json::from_slice(&new_body)?;
    assert_eq!(new_info.stage, 2);
    assert_eq!(new_info.user_id, sess_info.user_id);
    assert_eq!(new_info.device_id, sess_info.device_id);

    let devices_ok = http_request(
        server.addr,
        "GET",
        "/auth/devices",
        &[("Cookie", &stage2_cookie)],
        b"",
    )
    .await?;
    assert_eq!(devices_ok.status, 200);
    let dev_list: DevicesListResponse = serde_json::from_slice(&devices_ok.body)?;
    assert_eq!(dev_list.devices.len(), 1);
    assert_eq!(dev_list.devices[0].id, sess_info.device_id);
    assert_eq!(dev_list.devices[0].name_enc, None);

    // 5. DB inspection: NO raw token value appears in ANY column of sessions or devices
    let session_rows = sqlx::query(
        r#"
        SELECT
            id::text, user_id::text, device_id::text, family_id::text,
            stage::text, encode(access_hash, 'hex') AS access_hex,
            COALESCE(encode(refresh_hash, 'hex'), '') AS refresh_hex
        FROM sessions
        WHERE user_id = $1::text::uuid
        "#,
    )
    .bind(&sess_info.user_id)
    .fetch_all(&server.migrator_pool)
    .await?;
    assert_eq!(session_rows.len(), 1);

    let stage1_raw_hex: String = b64_decode(&stage1_at)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let stage2_at_hex: String = b64_decode(&stage2_at)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let stage2_rt_hex: String = b64_decode(&stage2_rt)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    for row in &session_rows {
        for col_idx in 0..7 {
            let cell: String = row.try_get(col_idx)?;
            for forbidden in [
                stage1_at.as_str(),
                stage2_at.as_str(),
                stage2_rt.as_str(),
                stage1_raw_hex.as_str(),
                stage2_at_hex.as_str(),
                stage2_rt_hex.as_str(),
            ] {
                assert!(
                    !cell.contains(forbidden),
                    "raw token material leaked into sessions column {col_idx}"
                );
            }
        }
    }

    // 6. Verify dev_insecure_cookies=true switch omits Secure and __Host- while keeping HttpOnly; SameSite=Strict; Path=/
    let dev_server = spawn_test_server_with_opts("http://localhost:5173", true).await?;
    let dev_email = unique_test_email("dev.cookie")?;
    let mut rng = OsRng;
    let ksf = test_ksf()?;
    let reg_start = ClientRegistration::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client reg start failed")?;
    let rs = http_post_json(
        dev_server.addr,
        "/auth/signup/start",
        &[],
        &SignupStartRequest {
            email: dev_email.clone(),
            registration_request: URL_SAFE_NO_PAD.encode(reg_start.message.serialize()),
        },
    )
    .await?;
    let rs_resp: SignupStartResponse = serde_json::from_slice(&rs.body)?;
    let reg_resp = RegistrationResponse::<TestClientSuite>::deserialize(&b64_decode(
        &rs_resp.registration_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    let rf = reg_start
        .state
        .finish(
            &mut rng,
            password,
            reg_resp,
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "finish failed")?;
    let _ = http_post_json(
        dev_server.addr,
        "/auth/signup/finish",
        &[],
        &SignupFinishRequest {
            email: dev_email.clone(),
            registration_record: URL_SAFE_NO_PAD.encode(rf.message.serialize()),
            wrapped_km: URL_SAFE_NO_PAD.encode([0x11u8; 48]),
            wrapped_ks_master: URL_SAFE_NO_PAD.encode([0x22u8; 48]),
        },
    )
    .await?;
    let ls = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "login start failed")?;
    let ls_http = http_post_json(
        dev_server.addr,
        "/auth/login/start",
        &[],
        &LoginStartRequest {
            email: dev_email,
            credential_request: URL_SAFE_NO_PAD.encode(ls.message.serialize()),
        },
    )
    .await?;
    let ls_resp: LoginStartResponse = serde_json::from_slice(&ls_http.body)?;
    let cr = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &ls_resp.credential_response,
    )?)
    .map_err(|_| "cred deserialize failed")?;
    let lf = ls
        .state
        .finish(
            &mut rng,
            password,
            cr,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "login finish failed")?;
    let lf_http = http_post_json(
        dev_server.addr,
        "/auth/login/finish",
        &[],
        &LoginFinishRequest {
            login_id: ls_resp.login_id,
            credential_finalization: URL_SAFE_NO_PAD.encode(lf.message.serialize()),
            device_id: None,
        },
    )
    .await?;
    assert_eq!(lf_http.status, 200);
    let dev_cookies = lf_http.set_cookies();
    assert_eq!(dev_cookies.len(), 1);
    assert!(dev_cookies[0].starts_with("at="));
    assert!(!dev_cookies[0].contains("Secure"));
    assert!(dev_cookies[0].contains("HttpOnly; SameSite=Strict; Path=/"));
    assert!(!dev_cookies[0].to_ascii_lowercase().contains("domain="));

    Ok(())
}

#[tokio::test]
async fn refresh_rotation_and_reuse_detection_revokes_entire_family() -> Result<(), Box<dyn Error>>
{
    let server = spawn_test_server().await?;
    let email = unique_test_email("refresh.reuse")?;
    let password = b"RefreshRotationPassword!88";

    let (_, stage1_at) = signup_and_login_stage1(server.addr, &email, password, None).await?;
    let (_, sess_body) = get_session_info(server.addr, &format!("__Host-at={stage1_at}")).await?;
    let sess_info: SessionResponse = serde_json::from_slice(&sess_body)?;
    let session_id = find_session_id_by_access_token(&server.migrator_pool, &stage1_at).await?;

    let pair1 = upgrade_session_after_mfa(&server.state.pool, &sess_info.user_id, &session_id)
        .await
        .map_err(|_| "upgrade failed")?;
    let at1 = pair1.access_token.to_base64url();
    let rt1 = pair1.refresh_token.to_base64url();

    // 1. First refresh rotation succeeds and sets both __Host-at and __Host-rt with Secure attributes.
    let refresh1 = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt1}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(refresh1.status, 200);
    let r1_cookies = refresh1.set_cookies();
    assert_eq!(r1_cookies.len(), 2);
    let at2 = extract_cookie_value(&r1_cookies, "__Host-at").ok_or("missing __Host-at")?;
    let rt2 = extract_cookie_value(&r1_cookies, "__Host-rt").ok_or("missing __Host-rt")?;
    assert_ne!(at1, at2);
    assert_ne!(rt1, rt2);
    for hdr in &r1_cookies {
        assert!(hdr.contains("HttpOnly; Secure; SameSite=Strict; Path=/"));
        assert!(!hdr.to_ascii_lowercase().contains("domain="));
    }

    // Old access token at1 is superseded; new access token at2 works.
    assert_eq!(
        get_session_info(server.addr, &format!("__Host-at={at1}"))
            .await?
            .0,
        401
    );
    assert_eq!(
        get_session_info(server.addr, &format!("__Host-at={at2}"))
            .await?
            .0,
        200
    );

    // 2. Second rotation works (rt2 -> at3, rt3)
    let refresh2 = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt2}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(refresh2.status, 200);
    let r2_cookies = refresh2.set_cookies();
    let at3 = extract_cookie_value(&r2_cookies, "__Host-at").ok_or("missing __Host-at")?;
    let rt3 = extract_cookie_value(&r2_cookies, "__Host-rt").ok_or("missing __Host-rt")?;

    // Baseline unknown token 401 body for byte-identical comparison
    let unknown_tok = URL_SAFE_NO_PAD.encode([0xFEu8; 32]);
    let unknown_resp = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={unknown_tok}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(unknown_resp.status, 401);

    // 3. REUSE of old token rt1 -> uniform 401 AND revokes the ENTIRE family (including rt3 and at3)!
    let reuse_resp = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt1}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(reuse_resp.status, 401);
    assert_eq!(reuse_resp.body, unknown_resp.body);
    assert!(reuse_resp.set_cookies().is_empty());

    // Now the newest refresh token rt3 AND newest access token at3 are BOTH revoked!
    let newest_rt_after_reuse = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt3}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(newest_rt_after_reuse.status, 401);
    assert_eq!(newest_rt_after_reuse.body, unknown_resp.body);

    let (newest_at_status, newest_at_body) =
        get_session_info(server.addr, &format!("__Host-at={at3}")).await?;
    assert_eq!(newest_at_status, 401);
    assert_eq!(newest_at_body, unknown_resp.body);

    Ok(())
}

#[tokio::test]
async fn expiry_enforcement_stage1_5m_stage2_10m_idle_24h_absolute_7d() -> Result<(), Box<dyn Error>>
{
    let server = spawn_test_server().await?;
    let email = unique_test_email("expiry.alice")?;
    let password = b"ExpiryTestPassword!77";

    // 1. Stage 1 access expiry (5 minutes)
    let (_, s1_at) = signup_and_login_stage1(server.addr, &email, password, None).await?;
    let s1_id = find_session_id_by_access_token(&server.migrator_pool, &s1_at).await?;

    let s1_within_5m: bool = sqlx::query_scalar(
        "SELECT access_expires_at > now() + interval '4 minutes' AND access_expires_at <= now() + interval '5 minutes 5 seconds' FROM sessions WHERE id = $1::text::uuid",
    )
    .bind(&s1_id)
    .fetch_one(&server.migrator_pool)
    .await?;
    assert!(
        s1_within_5m,
        "Stage 1 access token should expire in ~5 minutes"
    );

    sqlx::query("UPDATE sessions SET access_expires_at = now() - interval '1 second' WHERE id = $1::text::uuid")
        .bind(&s1_id)
        .execute(&server.migrator_pool)
        .await?;
    let (s1_exp_status, s1_exp_body) =
        get_session_info(server.addr, &format!("__Host-at={s1_at}")).await?;
    assert_eq!(s1_exp_status, 401);
    assert_eq!(s1_exp_body, b"{\"error\":\"authentication_failed\"}");

    // 2. Stage 2 access expiry (10 minutes), idle expiry (24 hours), absolute expiry (7 days)
    let (_, s1_at_2) = login_stage1_existing_user(server.addr, &email, password, None).await?;
    let (_, sess_body) = get_session_info(server.addr, &format!("__Host-at={s1_at_2}")).await?;
    let sess_info: SessionResponse = serde_json::from_slice(&sess_body)?;
    let s2_id = find_session_id_by_access_token(&server.migrator_pool, &s1_at_2).await?;

    let pair = upgrade_session_after_mfa(&server.state.pool, &sess_info.user_id, &s2_id)
        .await
        .map_err(|_| "upgrade failed")?;
    let at = pair.access_token.to_base64url();
    let rt = pair.refresh_token.to_base64url();

    let s2_bounds_ok: bool = sqlx::query_scalar(
        r#"
        SELECT
            access_expires_at > now() + interval '9 minutes' AND access_expires_at <= now() + interval '10 minutes 5 seconds'
            AND idle_expires_at > now() + interval '23 hours 59 minutes' AND idle_expires_at <= now() + interval '24 hours 5 seconds'
            AND refresh_expires_at > now() + interval '6 days 23 hours' AND refresh_expires_at <= now() + interval '7 days 5 seconds'
        FROM sessions WHERE id = $1::text::uuid
        "#,
    )
    .bind(&s2_id)
    .fetch_one(&server.migrator_pool)
    .await?;
    assert!(s2_bounds_ok, "Stage 2 expiries must match 10m / 24h / 7d");

    // Rewind access_expires_at (10m) -> /auth/session fails 401, but /auth/refresh still works!
    sqlx::query("UPDATE sessions SET access_expires_at = now() - interval '1 second' WHERE id = $1::text::uuid")
        .bind(&s2_id)
        .execute(&server.migrator_pool)
        .await?;
    let (at_exp_status, at_exp_body) =
        get_session_info(server.addr, &format!("__Host-at={at}")).await?;
    assert_eq!(at_exp_status, 401);
    assert_eq!(at_exp_body, s1_exp_body);

    let refreshed = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(refreshed.status, 200);
    let r_cookies = refreshed.set_cookies();
    let at2 = extract_cookie_value(&r_cookies, "__Host-at").ok_or("missing at2")?;
    let rt2 = extract_cookie_value(&r_cookies, "__Host-rt").ok_or("missing rt2")?;
    let s2_refreshed_id = find_session_id_by_access_token(&server.migrator_pool, &at2).await?;

    // Rewind idle_expires_at (24h) -> BOTH /auth/session AND /auth/refresh return uniform 401
    sqlx::query("UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE id = $1::text::uuid")
        .bind(&s2_refreshed_id)
        .execute(&server.migrator_pool)
        .await?;
    let (idle_at_status, idle_at_body) =
        get_session_info(server.addr, &format!("__Host-at={at2}")).await?;
    assert_eq!(idle_at_status, 401);
    assert_eq!(idle_at_body, s1_exp_body);

    let idle_rt_resp = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt2}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(idle_rt_resp.status, 401);
    assert_eq!(idle_rt_resp.body, s1_exp_body);

    // Restore idle_expires_at, rewind refresh_expires_at (7d absolute ceiling) -> BOTH fail with 401
    sqlx::query(
        "UPDATE sessions SET idle_expires_at = now() + interval '24 hours', refresh_expires_at = now() - interval '1 second' WHERE id = $1::text::uuid",
    )
    .bind(&s2_refreshed_id)
    .execute(&server.migrator_pool)
    .await?;

    let (abs_at_status, abs_at_body) =
        get_session_info(server.addr, &format!("__Host-at={at2}")).await?;
    assert_eq!(abs_at_status, 401);
    assert_eq!(abs_at_body, s1_exp_body);

    let abs_rt_resp = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={rt2}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(abs_rt_resp.status, 401);
    assert_eq!(abs_rt_resp.body, s1_exp_body);

    Ok(())
}

#[tokio::test]
async fn device_reuse_revocation_and_cross_user_isolation() -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email_a = unique_test_email("dev.alice")?;
    let email_b = unique_test_email("dev.bob")?;
    let pw_a = b"AliceDevicePassword!11";
    let pw_b = b"BobDevicePassword!22";

    // User A logs in -> device D_A1
    let (_, a1_s1) = signup_and_login_stage1(server.addr, &email_a, pw_a, None).await?;
    let (_, a1_sess_body) = get_session_info(server.addr, &format!("__Host-at={a1_s1}")).await?;
    let a1_sess: SessionResponse = serde_json::from_slice(&a1_sess_body)?;
    let d_a1 = a1_sess.device_id.clone();

    // User A logs in again passing device_id = D_A1 -> reuses D_A1
    let (_, a1_reused_s1) =
        login_stage1_existing_user(server.addr, &email_a, pw_a, Some(&d_a1)).await?;
    let (_, a1_reused_body) =
        get_session_info(server.addr, &format!("__Host-at={a1_reused_s1}")).await?;
    let a1_reused_sess: SessionResponse = serde_json::from_slice(&a1_reused_body)?;
    assert_eq!(a1_reused_sess.device_id, d_a1);

    // User B logs in passing User A's device_id = D_A1 -> must NOT reuse D_A1! Creates new D_B1
    let (_, b1_s1) = signup_and_login_stage1(server.addr, &email_b, pw_b, Some(&d_a1)).await?;
    let (_, b1_sess_body) = get_session_info(server.addr, &format!("__Host-at={b1_s1}")).await?;
    let b1_sess: SessionResponse = serde_json::from_slice(&b1_sess_body)?;
    let d_b1 = b1_sess.device_id.clone();
    assert_ne!(d_b1, d_a1);

    // User A logs in on second device D_A2
    let (_, a2_s1) = login_stage1_existing_user(server.addr, &email_a, pw_a, None).await?;
    let (_, a2_sess_body) = get_session_info(server.addr, &format!("__Host-at={a2_s1}")).await?;
    let a2_sess: SessionResponse = serde_json::from_slice(&a2_sess_body)?;
    let d_a2 = a2_sess.device_id.clone();
    assert_ne!(d_a2, d_a1);

    // Upgrade A's sessions (on D_A1 and D_A2) to Stage 2
    let a1_sid = find_session_id_by_access_token(&server.migrator_pool, &a1_s1).await?;
    let a1_pair = upgrade_session_after_mfa(&server.state.pool, &a1_sess.user_id, &a1_sid)
        .await
        .map_err(|_| "upgrade a1 failed")?;

    let a1_reused_sid =
        find_session_id_by_access_token(&server.migrator_pool, &a1_reused_s1).await?;
    let a1_reused_pair =
        upgrade_session_after_mfa(&server.state.pool, &a1_sess.user_id, &a1_reused_sid)
            .await
            .map_err(|_| "upgrade a1_reused failed")?;

    let a2_sid = find_session_id_by_access_token(&server.migrator_pool, &a2_s1).await?;
    let a2_pair = upgrade_session_after_mfa(&server.state.pool, &a2_sess.user_id, &a2_sid)
        .await
        .map_err(|_| "upgrade a2 failed")?;
    let a2_at = a2_pair.access_token.to_base64url();

    // User A lists devices -> sees ONLY D_A1 and D_A2, never D_B1
    let list_a = http_request(
        server.addr,
        "GET",
        "/auth/devices",
        &[("Cookie", &format!("__Host-at={a2_at}"))],
        b"",
    )
    .await?;
    assert_eq!(list_a.status, 200);
    let dev_list_a: DevicesListResponse = serde_json::from_slice(&list_a.body)?;
    let a_ids: Vec<&str> = dev_list_a.devices.iter().map(|d| d.id.as_str()).collect();
    assert_eq!(a_ids.len(), 2);
    assert!(a_ids.contains(&d_a1.as_str()));
    assert!(a_ids.contains(&d_a2.as_str()));
    assert!(!a_ids.contains(&d_b1.as_str()));

    // User A tries to delete User B's device vs nonexistent UUID -> exact same 404 body
    let del_other = http_request(
        server.addr,
        "DELETE",
        &format!("/auth/devices/{d_b1}"),
        &[
            ("Cookie", &format!("__Host-at={a2_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    let del_missing = http_request(
        server.addr,
        "DELETE",
        "/auth/devices/00000000-0000-0000-0000-000000000000",
        &[
            ("Cookie", &format!("__Host-at={a2_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(del_other.status, 404);
    assert_eq!(del_missing.status, 404);
    assert_eq!(del_other.body, del_missing.body);

    // User A revokes D_A1 -> kills ALL sessions on D_A1 (both access and refresh!)
    let del_a1 = http_request(
        server.addr,
        "DELETE",
        &format!("/auth/devices/{d_a1}"),
        &[
            ("Cookie", &format!("__Host-at={a2_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(del_a1.status, 200);

    for dead_at in [
        a1_pair.access_token.to_base64url(),
        a1_reused_pair.access_token.to_base64url(),
    ] {
        let (st, _) = get_session_info(server.addr, &format!("__Host-at={dead_at}")).await?;
        assert_eq!(st, 401);
    }
    for dead_rt in [
        a1_pair.refresh_token.to_base64url(),
        a1_reused_pair.refresh_token.to_base64url(),
    ] {
        let resp = http_request(
            server.addr,
            "POST",
            "/auth/refresh",
            &[
                ("Cookie", &format!("__Host-rt={dead_rt}")),
                ("X-Vault-CSRF", "1"),
            ],
            b"",
        )
        .await?;
        assert_eq!(resp.status, 401);
    }

    // D_A2 session still works, and listing shows D_A1 has revoked_at != None
    assert_eq!(
        get_session_info(server.addr, &format!("__Host-at={a2_at}"))
            .await?
            .0,
        200
    );
    let list_a_after = http_request(
        server.addr,
        "GET",
        "/auth/devices",
        &[("Cookie", &format!("__Host-at={a2_at}"))],
        b"",
    )
    .await?;
    let dev_list_after: DevicesListResponse = serde_json::from_slice(&list_a_after.body)?;
    let d_a1_entry: &DeviceResponse = dev_list_after
        .devices
        .iter()
        .find(|d| d.id == d_a1)
        .ok_or("expected D_A1 in list")?;
    assert!(d_a1_entry.revoked_at.is_some());

    // User A logging in again passing revoked D_A1 creates a brand new device D_A3 != D_A1
    let (_, a3_s1) = login_stage1_existing_user(server.addr, &email_a, pw_a, Some(&d_a1)).await?;
    let (_, a3_sess_body) = get_session_info(server.addr, &format!("__Host-at={a3_s1}")).await?;
    let a3_sess: SessionResponse = serde_json::from_slice(&a3_sess_body)?;
    assert_ne!(a3_sess.device_id, d_a1);

    Ok(())
}

#[tokio::test]
async fn logout_revokes_family_and_clears_cookies() -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email = unique_test_email("logout.alice")?;
    let password = b"LogoutPassword!123";

    // Stage 1 logout works
    let (_, s1_at) = signup_and_login_stage1(server.addr, &email, password, None).await?;
    let s1_logout = http_request(
        server.addr,
        "POST",
        "/auth/logout",
        &[
            ("Cookie", &format!("__Host-at={s1_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(s1_logout.status, 200);
    let parsed: StatusResponse = serde_json::from_slice(&s1_logout.body)?;
    assert_eq!(parsed.status, "ok");
    let clear_cookies = s1_logout.set_cookies();
    assert_eq!(clear_cookies.len(), 2);
    assert!(clear_cookies
        .iter()
        .any(|c| c.starts_with("__Host-at=;") && c.contains("Max-Age=0") && c.contains("Secure")));
    assert!(clear_cookies
        .iter()
        .any(|c| c.starts_with("__Host-rt=;") && c.contains("Max-Age=0") && c.contains("Secure")));

    assert_eq!(
        get_session_info(server.addr, &format!("__Host-at={s1_at}"))
            .await?
            .0,
        401
    );

    // Stage 2 logout revokes family (both access and refresh fail afterwards)
    let (_, s1_at_2) = login_stage1_existing_user(server.addr, &email, password, None).await?;
    let (_, sess_body) = get_session_info(server.addr, &format!("__Host-at={s1_at_2}")).await?;
    let sess: SessionResponse = serde_json::from_slice(&sess_body)?;
    let sid = find_session_id_by_access_token(&server.migrator_pool, &s1_at_2).await?;
    let pair = upgrade_session_after_mfa(&server.state.pool, &sess.user_id, &sid)
        .await
        .map_err(|_| "upgrade failed")?;
    let s2_at = pair.access_token.to_base64url();
    let s2_rt = pair.refresh_token.to_base64url();

    let s2_logout = http_request(
        server.addr,
        "POST",
        "/auth/logout",
        &[
            ("Cookie", &format!("__Host-at={s2_at}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(s2_logout.status, 200);
    assert_eq!(
        get_session_info(server.addr, &format!("__Host-at={s2_at}"))
            .await?
            .0,
        401
    );
    let rt_after_logout = http_request(
        server.addr,
        "POST",
        "/auth/refresh",
        &[
            ("Cookie", &format!("__Host-rt={s2_rt}")),
            ("X-Vault-CSRF", "1"),
        ],
        b"",
    )
    .await?;
    assert_eq!(rt_after_logout.status, 401);

    Ok(())
}

#[tokio::test]
async fn csrf_and_cors_enforcement() -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email = unique_test_email("csrf.cors")?;
    let password = b"CsrfCorsPassword!99";

    let (_, s1_at) = signup_and_login_stage1(server.addr, &email, password, None).await?;
    let (_, sess_body) = get_session_info(server.addr, &format!("__Host-at={s1_at}")).await?;
    let sess: SessionResponse = serde_json::from_slice(&sess_body)?;
    let sid = find_session_id_by_access_token(&server.migrator_pool, &s1_at).await?;
    let pair = upgrade_session_after_mfa(&server.state.pool, &sess.user_id, &sid)
        .await
        .map_err(|_| "upgrade failed")?;
    let s2_at = pair.access_token.to_base64url();
    let s2_rt = pair.refresh_token.to_base64url();

    // 1. CSRF: missing or wrong X-Vault-CSRF on mutating authenticated routes -> 403
    for (method, path, cookie) in [
        ("POST", "/auth/refresh", format!("__Host-rt={s2_rt}")),
        ("POST", "/auth/logout", format!("__Host-at={s2_at}")),
        (
            "DELETE",
            &format!("/auth/devices/{}", sess.device_id),
            format!("__Host-at={s2_at}"),
        ),
    ] {
        let missing = http_request(server.addr, method, path, &[("Cookie", &cookie)], b"").await?;
        assert_eq!(
            missing.status, 403,
            "expected 403 for missing CSRF on {method} {path}"
        );

        let wrong = http_request(
            server.addr,
            method,
            path,
            &[("Cookie", &cookie), ("X-Vault-CSRF", "0")],
            b"",
        )
        .await?;
        assert_eq!(
            wrong.status, 403,
            "expected 403 for wrong CSRF on {method} {path}"
        );
    }

    // 2. CORS: allowed origin gets exact headers; disallowed origin gets none; preflight works.
    let allowed_origin = "https://app.strongroom.example";
    let evil_origin = "https://evil.example";

    let allowed_get = http_request(
        server.addr,
        "GET",
        "/auth/session",
        &[
            ("Origin", allowed_origin),
            ("Cookie", &format!("__Host-at={s2_at}")),
        ],
        b"",
    )
    .await?;
    assert_eq!(allowed_get.status, 200);
    assert_eq!(
        allowed_get.first_header("access-control-allow-origin"),
        Some(allowed_origin)
    );
    assert_eq!(
        allowed_get.first_header("access-control-allow-credentials"),
        Some("true")
    );
    assert_eq!(allowed_get.first_header("vary"), Some("Origin"));

    let evil_get = http_request(
        server.addr,
        "GET",
        "/auth/session",
        &[
            ("Origin", evil_origin),
            ("Cookie", &format!("__Host-at={s2_at}")),
        ],
        b"",
    )
    .await?;
    assert_eq!(evil_get.status, 200);
    assert_eq!(evil_get.first_header("access-control-allow-origin"), None);
    assert_eq!(
        evil_get.first_header("access-control-allow-credentials"),
        None
    );
    assert_eq!(evil_get.first_header("vary"), Some("Origin"));

    // Preflight OPTIONS
    let allowed_preflight = http_request(
        server.addr,
        "OPTIONS",
        "/auth/logout",
        &[
            ("Origin", allowed_origin),
            ("Access-Control-Request-Method", "POST"),
            (
                "Access-Control-Request-Headers",
                "Content-Type, X-Vault-CSRF",
            ),
        ],
        b"",
    )
    .await?;
    assert_eq!(allowed_preflight.status, 204);
    assert_eq!(
        allowed_preflight.first_header("access-control-allow-origin"),
        Some(allowed_origin)
    );
    assert_eq!(
        allowed_preflight.first_header("access-control-allow-credentials"),
        Some("true")
    );
    assert_eq!(
        allowed_preflight.first_header("access-control-allow-methods"),
        Some("GET, POST, DELETE, OPTIONS")
    );
    assert_eq!(
        allowed_preflight.first_header("access-control-allow-headers"),
        Some("Content-Type, X-Vault-CSRF")
    );

    let evil_preflight = http_request(
        server.addr,
        "OPTIONS",
        "/auth/logout",
        &[
            ("Origin", evil_origin),
            ("Access-Control-Request-Method", "POST"),
        ],
        b"",
    )
    .await?;
    assert_eq!(evil_preflight.status, 204);
    assert_eq!(
        evil_preflight.first_header("access-control-allow-origin"),
        None
    );
    assert_eq!(
        evil_preflight.first_header("access-control-allow-credentials"),
        None
    );
    assert_eq!(
        evil_preflight.first_header("access-control-allow-methods"),
        None
    );
    assert_eq!(
        evil_preflight.first_header("access-control-allow-headers"),
        None
    );

    Ok(())
}
