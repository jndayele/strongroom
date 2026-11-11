#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use strongroom_api::auth::email::{canonicalize_email, email_hash};
use strongroom_api::auth::handlers::{
    AppState, ErrorBody, LoginFinishRequest, LoginFinishResponse, LoginStartRequest,
    LoginStartResponse, SignupFinishRequest, SignupFinishResponse, SignupStartRequest,
    SignupStartResponse, DEFAULT_KDF_PARAMS,
};
use strongroom_api::build_router_with_state;
use strongroom_api::config::{CredentialIdKey, EmailHashKey, OpaqueServerSetup};
use strongroom_api::db::{connect_pool, get_user_by_email_hash};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Test-only client cipher suite matching `@serenity-kit/opaque` (Ristretto255 + TripleDH + Argon2id).
struct TestClientSuite;

impl CipherSuite for TestClientSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

fn test_ksf() -> Result<Argon2<'static>, Box<dyn Error>> {
    // Small Argon2id parameters (32 KiB, 1 iteration, parallelism 1) for fast integration tests.
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
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn_test_server() -> Result<TestServer, Box<dyn Error>> {
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_migrate"))
        .env("MIGRATOR_DATABASE_URL", migrator_database_url())
        .status()?;

    if !status.success() {
        return Err(format!("migrate binary failed with status: {status}").into());
    }

    let pool = connect_pool(&app_database_url()).await?;
    let setup = OpaqueServerSetup::generate();
    let cred_key = CredentialIdKey::from_bytes([0x41; 32]);
    let email_key = EmailHashKey::from_bytes([0x82; 32]);

    let state = Arc::new(AppState::new(pool, setup, cred_key, email_key));
    let app = build_router_with_state(Arc::clone(&state));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    Ok(TestServer {
        addr,
        state,
        handle,
    })
}

fn unique_test_email(prefix: &str) -> Result<String, Box<dyn Error>> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{prefix}.{nanos}@example.com"))
}

struct RawHttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn http_post(
    addr: SocketAddr,
    path: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<RawHttpResponse, Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    let ct_header = match content_type {
        Some(ct) => format!("Content-Type: {ct}\r\n"),
        None => String::new(),
    };
    let req_head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{ct_header}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    stream.write_all(req_head.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;

    let sep_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing HTTP header/body separator")?;
    let headers_str = std::str::from_utf8(&raw[..sep_pos])?;
    let body_bytes = raw[sep_pos + 4..].to_vec();

    let status_line = headers_str
        .lines()
        .next()
        .ok_or("missing HTTP status line")?;
    let mut parts = status_line.split_whitespace();
    let _http_ver = parts.next().ok_or("missing HTTP version")?;
    let status_code: u16 = parts.next().ok_or("missing status code")?.parse()?;

    Ok(RawHttpResponse {
        status: status_code,
        body: body_bytes,
    })
}

async fn http_post_json<T: serde::Serialize>(
    addr: SocketAddr,
    path: &str,
    payload: &T,
) -> Result<RawHttpResponse, Box<dyn Error>> {
    let body = serde_json::to_vec(payload)?;
    http_post(addr, path, Some("application/json"), &body).await
}

/// Runs a full client registration flow over HTTP and returns the client's 64-byte `export_key`.
async fn client_signup_over_http(
    addr: SocketAddr,
    email: &str,
    password: &[u8],
    wrapped_km: &[u8],
    wrapped_ks_master: &[u8],
) -> Result<(Vec<u8>, RawHttpResponse), Box<dyn Error>> {
    let mut rng = OsRng;
    let ksf = test_ksf()?;

    let client_reg_start = ClientRegistration::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client registration start failed")?;
    let reg_req_b64 = URL_SAFE_NO_PAD.encode(client_reg_start.message.serialize());

    let start_http = http_post_json(
        addr,
        "/auth/signup/start",
        &SignupStartRequest {
            email: String::from(email),
            registration_request: reg_req_b64,
        },
    )
    .await?;
    assert_eq!(start_http.status, 200);

    let start_resp: SignupStartResponse = serde_json::from_slice(&start_http.body)?;
    assert_eq!(start_resp.kdf_params, DEFAULT_KDF_PARAMS);

    let reg_resp_bytes = b64_decode(&start_resp.registration_response)?;
    let reg_resp = RegistrationResponse::<TestClientSuite>::deserialize(&reg_resp_bytes)
        .map_err(|_| "failed to deserialize RegistrationResponse")?;

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
    let export_key = client_reg_finish.export_key.to_vec();

    let finish_http = http_post_json(
        addr,
        "/auth/signup/finish",
        &SignupFinishRequest {
            email: String::from(email),
            registration_record: record_b64,
            wrapped_km: URL_SAFE_NO_PAD.encode(wrapped_km),
            wrapped_ks_master: URL_SAFE_NO_PAD.encode(wrapped_ks_master),
        },
    )
    .await?;

    Ok((export_key, finish_http))
}

#[tokio::test]
async fn full_signup_and_login_flow_and_db_row_inspection() -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email = unique_test_email("alice.fullflow")?;
    let password = b"CorrectHorseBatteryStaple!99";
    let wrapped_km = [0xAAu8; 60];
    let wrapped_ks_master = [0xBBu8; 60];

    // 1. Signup start + finish -> 200 {"status":"ok"}
    let (reg_export_key, finish_http) = client_signup_over_http(
        server.addr,
        &email,
        password,
        &wrapped_km,
        &wrapped_ks_master,
    )
    .await?;
    assert_eq!(finish_http.status, 200);
    let signup_resp: SignupFinishResponse = serde_json::from_slice(&finish_http.body)?;
    assert_eq!(signup_resp.status, "ok");

    // 2. Login start + finish -> 200 {"status":"password_verified"}
    let mut rng = OsRng;
    let ksf = test_ksf()?;
    let client_login_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;

    let login_start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: email.clone(),
            credential_request: URL_SAFE_NO_PAD.encode(client_login_start.message.serialize()),
        },
    )
    .await?;
    assert_eq!(login_start_http.status, 200);
    let login_start_resp: LoginStartResponse = serde_json::from_slice(&login_start_http.body)?;
    assert_eq!(login_start_resp.kdf_params, DEFAULT_KDF_PARAMS);

    let cred_resp_bytes = b64_decode(&login_start_resp.credential_response)?;
    let cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&cred_resp_bytes)
        .map_err(|_| "failed to deserialize CredentialResponse")?;

    let client_login_finish = client_login_start
        .state
        .finish(
            &mut rng,
            password,
            cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "client login finish failed")?;

    assert_eq!(
        client_login_finish.export_key.as_slice(),
        reg_export_key.as_slice()
    );

    let login_finish_http = http_post_json(
        server.addr,
        "/auth/login/finish",
        &LoginFinishRequest {
            login_id: login_start_resp.login_id,
            credential_finalization: URL_SAFE_NO_PAD
                .encode(client_login_finish.message.serialize()),
        },
    )
    .await?;
    assert_eq!(login_finish_http.status, 200);
    let login_finish_resp: LoginFinishResponse = serde_json::from_slice(&login_finish_http.body)?;
    assert_eq!(login_finish_resp.status, "password_verified");
    assert_eq!(
        login_finish_http.body,
        b"{\"status\":\"password_verified\"}"
    );

    // 3. Inspect the users row in Postgres: no plaintext email, no password, and no export_key.
    let canon = canonicalize_email(&email)?;
    let expected_hash = email_hash(&server.state.email_hash_key, &canon);
    let user_row = get_user_by_email_hash(&server.state.pool, &expected_hash)
        .await?
        .ok_or("expected user row in database")?;

    assert_eq!(user_row.email_enc, None);
    assert_eq!(user_row.wrapped_km, wrapped_km);
    assert_eq!(user_row.wrapped_ks_master, wrapped_ks_master);
    assert_eq!(user_row.key_version, 1);

    let export_key_b64 = URL_SAFE_NO_PAD.encode(&reg_export_key);
    let all_stored_blobs: [&[u8]; 5] = [
        &user_row.email_hash,
        &user_row.opaque_record,
        &user_row.wrapped_km,
        &user_row.wrapped_ks_master,
        &user_row.kdf_params,
    ];

    for blob in all_stored_blobs {
        assert_ne!(blob, email.as_bytes());
        assert_ne!(blob, password);
        assert_ne!(blob, reg_export_key.as_slice());
        assert!(!blob
            .windows(email.len())
            .any(|window| window == email.as_bytes()));
        assert!(!blob
            .windows(password.len())
            .any(|window| window == password));
        assert!(!blob
            .windows(reg_export_key.len())
            .any(|window| window == reg_export_key.as_slice()));
        assert!(!blob
            .windows(export_key_b64.len())
            .any(|window| window == export_key_b64.as_bytes()));
    }

    Ok(())
}

#[tokio::test]
async fn wrong_password_and_unknown_email_return_byte_identical_401_and_same_login_start_shape(
) -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let known_email = unique_test_email("bob.known")?;
    let unknown_email = unique_test_email("bob.unknown")?;
    let password = b"BobCorrectPassword!123";
    let wrong_password = b"BobWrongPassword!999";

    let (_, finish_http) = client_signup_over_http(
        server.addr,
        &known_email,
        password,
        &[0x11; 48],
        &[0x22; 48],
    )
    .await?;
    assert_eq!(finish_http.status, 200);

    let mut rng = OsRng;
    let ksf = test_ksf()?;

    // 1. Known vs unknown email on login/start: same status, same JSON keys, same credential_response length, same kdf_params.
    let known_client_start = ClientLogin::<TestClientSuite>::start(&mut rng, wrong_password)
        .map_err(|_| "client login start failed")?;
    let known_start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: known_email.clone(),
            credential_request: URL_SAFE_NO_PAD.encode(known_client_start.message.serialize()),
        },
    )
    .await?;

    let unknown_client_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;
    let unknown_start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: unknown_email,
            credential_request: URL_SAFE_NO_PAD.encode(unknown_client_start.message.serialize()),
        },
    )
    .await?;

    assert_eq!(known_start_http.status, 200);
    assert_eq!(unknown_start_http.status, 200);

    let known_json_val: serde_json::Value = serde_json::from_slice(&known_start_http.body)?;
    let unknown_json_val: serde_json::Value = serde_json::from_slice(&unknown_start_http.body)?;
    let known_keys: BTreeSet<&String> = known_json_val
        .as_object()
        .ok_or("expected JSON object")?
        .keys()
        .collect();
    let unknown_keys: BTreeSet<&String> = unknown_json_val
        .as_object()
        .ok_or("expected JSON object")?
        .keys()
        .collect();
    assert_eq!(known_keys, unknown_keys);

    let known_start_resp: LoginStartResponse = serde_json::from_slice(&known_start_http.body)?;
    let unknown_start_resp: LoginStartResponse = serde_json::from_slice(&unknown_start_http.body)?;

    assert_eq!(
        known_start_resp.credential_response.len(),
        unknown_start_resp.credential_response.len()
    );
    assert_eq!(known_start_resp.credential_response.len(), 427);
    assert_eq!(
        known_start_resp.login_id.len(),
        unknown_start_resp.login_id.len()
    );
    assert_eq!(known_start_resp.kdf_params, unknown_start_resp.kdf_params);
    assert_eq!(known_start_resp.kdf_params, DEFAULT_KDF_PARAMS);

    // Client local finishLogin fails for both wrong password and unknown email dummy response.
    let known_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &known_start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    assert!(known_client_start
        .state
        .finish(
            &mut rng,
            wrong_password,
            known_cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .is_err());

    let unknown_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &unknown_start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    assert!(unknown_client_start
        .state
        .finish(
            &mut rng,
            password,
            unknown_cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .is_err());

    // 2. Produce a valid-shaped 64-byte CredentialFinalization and send it for both the wrong-password
    //    known-user session and the unknown-email dummy session: both must return 401 with byte-identical bodies.
    let valid_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;
    let valid_start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: known_email,
            credential_request: URL_SAFE_NO_PAD.encode(valid_start.message.serialize()),
        },
    )
    .await?;
    let valid_start_resp: LoginStartResponse = serde_json::from_slice(&valid_start_http.body)?;
    let valid_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &valid_start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    let valid_finish = valid_start
        .state
        .finish(
            &mut rng,
            password,
            valid_cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "valid finish failed")?;
    let forged_finalization_b64 = URL_SAFE_NO_PAD.encode(valid_finish.message.serialize());

    let wrong_pw_finish_http = http_post_json(
        server.addr,
        "/auth/login/finish",
        &LoginFinishRequest {
            login_id: known_start_resp.login_id,
            credential_finalization: forged_finalization_b64.clone(),
        },
    )
    .await?;

    let unknown_email_finish_http = http_post_json(
        server.addr,
        "/auth/login/finish",
        &LoginFinishRequest {
            login_id: unknown_start_resp.login_id,
            credential_finalization: forged_finalization_b64,
        },
    )
    .await?;

    assert_eq!(wrong_pw_finish_http.status, 401);
    assert_eq!(unknown_email_finish_http.status, 401);
    assert_eq!(wrong_pw_finish_http.body, unknown_email_finish_http.body);
    assert_eq!(
        wrong_pw_finish_http.body,
        b"{\"error\":\"authentication_failed\"}"
    );

    Ok(())
}

#[tokio::test]
async fn second_signup_finish_for_same_email_does_not_overwrite() -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email = unique_test_email("carol.nooverwrite")?;
    let first_password = b"FirstPasswordWins!111";
    let second_password = b"SecondPasswordIgnored!222";
    let first_km = [0x10u8; 48];
    let first_ks = [0x20u8; 48];
    let second_km = [0x90u8; 48];
    let second_ks = [0xA0u8; 48];

    // 1. First signup
    let (_, first_finish_http) =
        client_signup_over_http(server.addr, &email, first_password, &first_km, &first_ks).await?;
    assert_eq!(first_finish_http.status, 200);

    // 2. Second signup for the same email (using uppercase/whitespace variant to verify canonicalization too)
    let messy_same_email = format!("  {} \n", email.to_ascii_uppercase());
    let (_, second_finish_http) = client_signup_over_http(
        server.addr,
        &messy_same_email,
        second_password,
        &second_km,
        &second_ks,
    )
    .await?;
    assert_eq!(second_finish_http.status, 200);
    assert_eq!(first_finish_http.body, second_finish_http.body);

    // 3. First password still logs in -> 200 password_verified
    let mut rng = OsRng;
    let ksf = test_ksf()?;

    let login1_start = ClientLogin::<TestClientSuite>::start(&mut rng, first_password)
        .map_err(|_| "client login start failed")?;
    let login1_start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: email.clone(),
            credential_request: URL_SAFE_NO_PAD.encode(login1_start.message.serialize()),
        },
    )
    .await?;
    let login1_start_resp: LoginStartResponse = serde_json::from_slice(&login1_start_http.body)?;
    let login1_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &login1_start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    let login1_finish = login1_start
        .state
        .finish(
            &mut rng,
            first_password,
            login1_cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "expected first password client finish to succeed")?;

    let login1_finish_http = http_post_json(
        server.addr,
        "/auth/login/finish",
        &LoginFinishRequest {
            login_id: login1_start_resp.login_id,
            credential_finalization: URL_SAFE_NO_PAD.encode(login1_finish.message.serialize()),
        },
    )
    .await?;
    assert_eq!(login1_finish_http.status, 200);

    // 4. Second password does NOT log in
    let login2_start = ClientLogin::<TestClientSuite>::start(&mut rng, second_password)
        .map_err(|_| "client login start failed")?;
    let login2_start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: email.clone(),
            credential_request: URL_SAFE_NO_PAD.encode(login2_start.message.serialize()),
        },
    )
    .await?;
    let login2_start_resp: LoginStartResponse = serde_json::from_slice(&login2_start_http.body)?;
    let login2_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &login2_start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    let login2_finish_res = login2_start.state.finish(
        &mut rng,
        second_password,
        login2_cred_resp,
        ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
    );
    assert!(
        login2_finish_res.is_err(),
        "expected second password to fail envelope opening because the first record was preserved"
    );

    // Stored wrapped keys in DB must still be the first signup's keys.
    let canon = canonicalize_email(&email)?;
    let expected_hash = email_hash(&server.state.email_hash_key, &canon);
    let stored_user = get_user_by_email_hash(&server.state.pool, &expected_hash)
        .await?
        .ok_or("expected user row")?;
    assert_eq!(stored_user.wrapped_km, first_km);
    assert_eq!(stored_user.wrapped_ks_master, first_ks);

    Ok(())
}

#[tokio::test]
async fn replay_unknown_field_oversized_body_and_non_ascii_email_are_rejected(
) -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let email = unique_test_email("dave.validation")?;
    let password = b"DaveValidationPassword!42";

    let (_, finish_http) =
        client_signup_over_http(server.addr, &email, password, &[0x33; 48], &[0x44; 48]).await?;
    assert_eq!(finish_http.status, 200);

    // 1. Replayed login_id -> 401
    let mut rng = OsRng;
    let ksf = test_ksf()?;
    let client_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;
    let start_http = http_post_json(
        server.addr,
        "/auth/login/start",
        &LoginStartRequest {
            email: email.clone(),
            credential_request: URL_SAFE_NO_PAD.encode(client_start.message.serialize()),
        },
    )
    .await?;
    let start_resp: LoginStartResponse = serde_json::from_slice(&start_http.body)?;
    let cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&b64_decode(
        &start_resp.credential_response,
    )?)
    .map_err(|_| "deserialize failed")?;
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password,
            cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .map_err(|_| "client login finish failed")?;

    let finish_req = LoginFinishRequest {
        login_id: start_resp.login_id,
        credential_finalization: URL_SAFE_NO_PAD.encode(client_finish.message.serialize()),
    };

    let first_attempt = http_post_json(server.addr, "/auth/login/finish", &finish_req).await?;
    assert_eq!(first_attempt.status, 200);

    let replay_attempt = http_post_json(server.addr, "/auth/login/finish", &finish_req).await?;
    assert_eq!(replay_attempt.status, 401);
    assert_eq!(
        replay_attempt.body,
        b"{\"error\":\"authentication_failed\"}"
    );

    // 2. Unknown JSON field -> 400 {"error":"invalid_request"}
    let unknown_field_body =
        br#"{"email":"dave@example.com","registration_request":"AAAA","unexpected":true}"#;
    let unknown_field_http = http_post(
        server.addr,
        "/auth/signup/start",
        Some("application/json"),
        unknown_field_body,
    )
    .await?;
    assert_eq!(unknown_field_http.status, 400);
    let err_body: ErrorBody = serde_json::from_slice(&unknown_field_http.body)?;
    assert_eq!(err_body.error, "invalid_request");

    // 3. Missing Content-Type: application/json -> 400 {"error":"invalid_request"}
    let missing_ct_http = http_post(
        server.addr,
        "/auth/signup/start",
        None,
        br#"{"email":"dave@example.com","registration_request":"AAAA"}"#,
    )
    .await?;
    assert_eq!(missing_ct_http.status, 400);
    assert_eq!(missing_ct_http.body, b"{\"error\":\"invalid_request\"}");

    // 4. Oversized body (> 16 KiB) -> rejected (413 Payload Too Large)
    let large_string = "A".repeat(17 * 1024);
    let oversized_json =
        format!("{{\"email\":\"dave@example.com\",\"registration_request\":\"{large_string}\"}}");
    let oversized_http = http_post(
        server.addr,
        "/auth/signup/start",
        Some("application/json"),
        oversized_json.as_bytes(),
    )
    .await?;
    assert!(
        oversized_http.status == 413 || oversized_http.status == 400,
        "expected oversized body to be rejected with 413 or 400, got {}",
        oversized_http.status
    );

    // 5. Non-ASCII email -> 400 {"error":"invalid_request"}
    let non_ascii_http = http_post_json(
        server.addr,
        "/auth/signup/start",
        &SignupStartRequest {
            email: String::from("alité@example.com"),
            registration_request: URL_SAFE_NO_PAD.encode(client_start.message.serialize()),
        },
    )
    .await?;
    assert_eq!(non_ascii_http.status, 400);
    assert_eq!(non_ascii_http.body, b"{\"error\":\"invalid_request\"}");

    Ok(())
}

fn median_duration(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    let mid = samples.len() / 2;
    samples.get(mid).copied().unwrap_or(Duration::ZERO)
}

#[tokio::test]
#[ignore]
async fn login_start_timing_known_vs_unknown_email_ratio_under_two() -> Result<(), Box<dyn Error>> {
    let server = spawn_test_server().await?;
    let known_email = unique_test_email("timing.known")?;
    let unknown_email = unique_test_email("timing.unknown")?;
    let password = b"TimingTestPassword!2026";

    let (_, finish_http) = client_signup_over_http(
        server.addr,
        &known_email,
        password,
        &[0x55; 48],
        &[0x66; 48],
    )
    .await?;
    assert_eq!(finish_http.status, 200);

    let mut rng = OsRng;
    let sample_client_start = ClientLogin::<TestClientSuite>::start(&mut rng, password)
        .map_err(|_| "client login start failed")?;
    let cred_req_b64 = URL_SAFE_NO_PAD.encode(sample_client_start.message.serialize());

    let known_req_bytes = serde_json::to_vec(&LoginStartRequest {
        email: known_email,
        credential_request: cred_req_b64.clone(),
    })?;
    let unknown_req_bytes = serde_json::to_vec(&LoginStartRequest {
        email: unknown_email,
        credential_request: cred_req_b64,
    })?;

    // Warm up connection pool and routes before measuring.
    for _ in 0..3 {
        let _ = http_post(
            server.addr,
            "/auth/login/start",
            Some("application/json"),
            &known_req_bytes,
        )
        .await?;
        let _ = http_post(
            server.addr,
            "/auth/login/start",
            Some("application/json"),
            &unknown_req_bytes,
        )
        .await?;
    }

    let iterations = 50usize;
    let mut known_samples = Vec::with_capacity(iterations);
    let mut unknown_samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let t_known = Instant::now();
        let resp_k = http_post(
            server.addr,
            "/auth/login/start",
            Some("application/json"),
            &known_req_bytes,
        )
        .await?;
        known_samples.push(t_known.elapsed());
        assert_eq!(resp_k.status, 200);

        let t_unknown = Instant::now();
        let resp_u = http_post(
            server.addr,
            "/auth/login/start",
            Some("application/json"),
            &unknown_req_bytes,
        )
        .await?;
        unknown_samples.push(t_unknown.elapsed());
        assert_eq!(resp_u.status, 200);
    }

    let known_median = median_duration(known_samples);
    let unknown_median = median_duration(unknown_samples);

    let known_secs = known_median.as_secs_f64();
    let unknown_secs = unknown_median.as_secs_f64();
    let ratio = if known_secs >= unknown_secs {
        known_secs / unknown_secs.max(1e-9)
    } else {
        unknown_secs / known_secs.max(1e-9)
    };

    println!(
        "login/start timing (50 calls each): known_median = {:?}, unknown_median = {:?}, ratio = {:.3}",
        known_median, unknown_median, ratio
    );

    assert!(
        ratio < 2.0,
        "expected median timing ratio between known ({known_median:?}) and unknown ({unknown_median:?}) to be < 2.0, got {ratio:.3}"
    );

    Ok(())
}
