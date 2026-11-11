#![forbid(unsafe_code)]

use opaque_ke::{
    CipherSuite, CredentialFinalization, CredentialRequest, RegistrationRequest,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
};
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;

use crate::config::OpaqueServerSetup;

/// Production OPAQUE cipher suite for the Rust server.
///
/// # SECURITY WARNING — SERVER-ONLY CIPHER SUITE
/// This suite configures `Ksf = opaque_ke::ksf::Identity` ONLY because the OPAQUE server
/// never executes the Key Stretching Function (KSF) during registration or login (RFC 9807 §3.3).
/// Using `Identity` avoids compiling Argon2 into the production server binary.
///
/// **NEVER use `ServerSuite` for client-side operations (`ClientRegistration` or `ClientLogin`)!**
/// Client operations MUST use Argon2id (`@serenity-kit/opaque` in the browser, or `TestClientSuite`
/// in Rust unit tests).
pub struct ServerSuite;

impl CipherSuite for ServerSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// Uniform authentication error returned by all OPAQUE and pending-login operations.
///
/// Deliberately carries no inner cause or distinguishing message so callers and HTTP handlers
/// cannot accidentally leak why an authentication step failed (e.g., unknown email vs. wrong
/// password vs. tampered MAC vs. expired login ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("authentication failed")
    }
}

impl Error for AuthError {}

/// Opaque wrapper around `opaque_ke::ServerLogin<ServerSuite>` for an in-progress login ceremony.
/// Never prints protocol secrets in `Debug` output.
#[derive(Clone)]
pub struct ServerLoginState {
    inner: ServerLogin<ServerSuite>,
}

impl fmt::Debug for ServerLoginState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Step 1 of OPAQUE registration: evaluates the blinded OPRF request and returns the serialized
/// `RegistrationResponse` bytes (`64` bytes for Ristretto255).
pub fn registration_start(
    setup: &OpaqueServerSetup,
    credential_id: &[u8],
    request_bytes: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let request =
        RegistrationRequest::<ServerSuite>::deserialize(request_bytes).map_err(|_| AuthError)?;
    let result = ServerRegistration::<ServerSuite>::start(setup.as_inner(), request, credential_id)
        .map_err(|_| AuthError)?;
    Ok(result.message.serialize().to_vec())
}

/// Step 2 of OPAQUE registration: validates that `upload_bytes` deserializes as a well-formed
/// `RegistrationUpload`, finishes server registration, and returns the serialized
/// `ServerRegistration` record bytes (`192` bytes for Ristretto255) ready for database storage.
pub fn registration_finish(upload_bytes: &[u8]) -> Result<Vec<u8>, AuthError> {
    let upload =
        RegistrationUpload::<ServerSuite>::deserialize(upload_bytes).map_err(|_| AuthError)?;
    let record = ServerRegistration::<ServerSuite>::finish(upload);
    Ok(record.serialize().to_vec())
}

/// Step 1 of OPAQUE login: starts a server login ceremony.
///
/// - When `record_bytes` is `Some(bytes)`, deserializes the user's stored `ServerRegistration`.
/// - When `record_bytes` is `None` (unknown email), passes `None` to `ServerLogin::start`, which
///   unconditionally generates a dummy `ServerRegistration` and selects between the two in
///   constant time (`subtle::CtOption`), deriving the deterministic per-credential OPRF key from
///   `setup` and `credential_id` and running the full 3DH key exchange.
/// - Both paths execute the same code path and produce an identically sized 320-byte response.
pub fn login_start(
    setup: &OpaqueServerSetup,
    credential_id: &[u8],
    record_bytes: Option<&[u8]>,
    request_bytes: &[u8],
) -> Result<(ServerLoginState, Vec<u8>), AuthError> {
    let request =
        CredentialRequest::<ServerSuite>::deserialize(request_bytes).map_err(|_| AuthError)?;

    let password_file = match record_bytes {
        Some(bytes) => {
            Some(ServerRegistration::<ServerSuite>::deserialize(bytes).map_err(|_| AuthError)?)
        }
        None => None,
    };

    let mut rng = OsRng;
    let result = ServerLogin::<ServerSuite>::start(
        &mut rng,
        setup.as_inner(),
        password_file,
        request,
        credential_id,
        ServerLoginParameters::default(),
    )
    .map_err(|_| AuthError)?;

    Ok((
        ServerLoginState {
            inner: result.state,
        },
        result.message.serialize().to_vec(),
    ))
}

/// Step 2 of OPAQUE login: verifies the client's `CredentialFinalization` MAC against the
/// in-progress `ServerLoginState`.
pub fn login_finish(
    login_state: ServerLoginState,
    finalization_bytes: &[u8],
) -> Result<(), AuthError> {
    let finalization = CredentialFinalization::<ServerSuite>::deserialize(finalization_bytes)
        .map_err(|_| AuthError)?;
    let _result = login_state
        .inner
        .finish(finalization, ServerLoginParameters::default())
        .map_err(|_| AuthError)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::email::{canonicalize_email, credential_identifier};
    use crate::auth::pending::{PendingLoginStore, Uuid, LOGIN_STATE_TTL, MAX_PENDING_LOGINS};
    use crate::config::CredentialIdKey;
    use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    };
    use std::time::{Duration, Instant};

    /// Test-only client cipher suite matching `@serenity-kit/opaque` (Ristretto255 + TripleDH + Argon2id).
    /// Messages between `TestClientSuite` and `ServerSuite` are exchanged strictly as raw serialized bytes.
    struct TestClientSuite;

    impl CipherSuite for TestClientSuite {
        type OprfCs = opaque_ke::Ristretto255;
        type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
        type Ksf = Argon2<'static>;
    }

    fn test_ksf() -> Result<Argon2<'static>, AuthError> {
        // Small Argon2id parameters (32 KiB, 1 iteration, parallelism 1) for fast unit tests.
        let params = Params::new(32, 1, 1, None).map_err(|_| AuthError)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Helper that runs a full client+server registration over serialized bytes and returns
    /// `(stored_record_bytes, registration_export_key)`.
    fn register_user_bytes(
        setup: &OpaqueServerSetup,
        cred_id: &[u8; 32],
        password: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AuthError> {
        let mut rng = OsRng;
        let ksf = test_ksf()?;

        // Client starts registration -> serialized request bytes
        let client_start = ClientRegistration::<TestClientSuite>::start(&mut rng, password)
            .map_err(|_| AuthError)?;
        let req_bytes: Vec<u8> = client_start.message.serialize().to_vec();

        // Server processes serialized request bytes -> serialized response bytes
        let resp_bytes: Vec<u8> = registration_start(setup, cred_id, &req_bytes)?;

        // Client deserializes response bytes and finishes registration -> serialized upload bytes
        let reg_response = RegistrationResponse::<TestClientSuite>::deserialize(&resp_bytes)
            .map_err(|_| AuthError)?;
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                password,
                reg_response,
                ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| AuthError)?;
        let upload_bytes: Vec<u8> = client_finish.message.serialize().to_vec();
        let export_key: Vec<u8> = client_finish.export_key.to_vec();

        // Server validates and converts upload bytes into stored record bytes
        let record_bytes: Vec<u8> = registration_finish(&upload_bytes)?;

        Ok((record_bytes, export_key))
    }

    #[test]
    fn full_registration_and_login_succeeds_with_identical_export_key() -> Result<(), AuthError> {
        let setup = OpaqueServerSetup::generate();
        let cred_key = CredentialIdKey::from_bytes([0x55; 32]);
        let canon = canonicalize_email("alice@example.com").map_err(|_| AuthError)?;
        let cred_id = credential_identifier(&cred_key, &canon);
        let password = b"correct-horse-battery-staple";

        let (stored_record_bytes, reg_export_key) =
            register_user_bytes(&setup, &cred_id, password)?;

        let mut rng = OsRng;
        let ksf = test_ksf()?;

        // Client starts login -> serialized request bytes
        let client_login_start =
            ClientLogin::<TestClientSuite>::start(&mut rng, password).map_err(|_| AuthError)?;
        let login_req_bytes: Vec<u8> = client_login_start.message.serialize().to_vec();

        // Server processes login_start with stored record bytes -> serialized response bytes
        let (server_state, login_resp_bytes) = login_start(
            &setup,
            &cred_id,
            Some(&stored_record_bytes),
            &login_req_bytes,
        )?;

        // Client deserializes response bytes and finishes login -> serialized finalization bytes
        let cred_response = CredentialResponse::<TestClientSuite>::deserialize(&login_resp_bytes)
            .map_err(|_| AuthError)?;
        let client_login_finish = client_login_start
            .state
            .finish(
                &mut rng,
                password,
                cred_response,
                ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| AuthError)?;
        let finalization_bytes: Vec<u8> = client_login_finish.message.serialize().to_vec();
        let login_export_key: Vec<u8> = client_login_finish.export_key.to_vec();

        // Server verifies finalization bytes
        login_finish(server_state, &finalization_bytes)?;

        // Export key at registration and login must be identical (64 bytes for Sha512)
        assert_eq!(reg_export_key.len(), 64);
        assert_eq!(reg_export_key, login_export_key);

        Ok(())
    }

    #[test]
    fn wrong_password_and_tampered_finalization_fail() -> Result<(), AuthError> {
        let setup = OpaqueServerSetup::generate();
        let cred_key = CredentialIdKey::from_bytes([0x66; 32]);
        let canon = canonicalize_email("bob@example.com").map_err(|_| AuthError)?;
        let cred_id = credential_identifier(&cred_key, &canon);
        let password = b"correct-password";
        let wrong_password = b"wrong-password";

        let (stored_record_bytes, _) = register_user_bytes(&setup, &cred_id, password)?;

        let mut rng = OsRng;
        let ksf = test_ksf()?;

        // 1. Wrong password fails at client finish (envelope open fails)
        let client_wrong_start = ClientLogin::<TestClientSuite>::start(&mut rng, wrong_password)
            .map_err(|_| AuthError)?;
        let wrong_req_bytes: Vec<u8> = client_wrong_start.message.serialize().to_vec();

        let (_server_state_wrong, wrong_resp_bytes) = login_start(
            &setup,
            &cred_id,
            Some(&stored_record_bytes),
            &wrong_req_bytes,
        )?;
        let wrong_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&wrong_resp_bytes)
            .map_err(|_| AuthError)?;

        let client_wrong_finish = client_wrong_start.state.finish(
            &mut rng,
            wrong_password,
            wrong_cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        );
        assert!(
            client_wrong_finish.is_err(),
            "expected client finishLogin to fail when given the wrong password"
        );

        // 2. Tampered finalization fails at the server with uniform AuthError
        let client_valid_start =
            ClientLogin::<TestClientSuite>::start(&mut rng, password).map_err(|_| AuthError)?;
        let valid_req_bytes: Vec<u8> = client_valid_start.message.serialize().to_vec();

        let (server_state_tampered, valid_resp_bytes) = login_start(
            &setup,
            &cred_id,
            Some(&stored_record_bytes),
            &valid_req_bytes,
        )?;
        let valid_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&valid_resp_bytes)
            .map_err(|_| AuthError)?;

        let client_valid_finish = client_valid_start
            .state
            .finish(
                &mut rng,
                password,
                valid_cred_resp,
                ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| AuthError)?;

        let mut tampered_finalization: Vec<u8> = client_valid_finish.message.serialize().to_vec();
        if let Some(first_byte) = tampered_finalization.first_mut() {
            *first_byte ^= 0x01;
        }

        let tampered_res = login_finish(server_state_tampered, &tampered_finalization);
        assert_eq!(tampered_res, Err(AuthError));

        Ok(())
    }

    #[test]
    fn unknown_email_none_path_matches_response_size_and_fails_uniformly() -> Result<(), AuthError>
    {
        let setup = OpaqueServerSetup::generate();
        let cred_key = CredentialIdKey::from_bytes([0x77; 32]);

        let known_canon = canonicalize_email("known@example.com").map_err(|_| AuthError)?;
        let known_cred_id = credential_identifier(&cred_key, &known_canon);
        let password = b"test-password-123";
        let (known_record_bytes, _) = register_user_bytes(&setup, &known_cred_id, password)?;

        let unknown_canon = canonicalize_email("unknown@example.com").map_err(|_| AuthError)?;
        let unknown_cred_id = credential_identifier(&cred_key, &unknown_canon);

        let mut rng = OsRng;
        let ksf = test_ksf()?;

        // Start login for known user
        let known_client_start =
            ClientLogin::<TestClientSuite>::start(&mut rng, password).map_err(|_| AuthError)?;
        let known_req_bytes: Vec<u8> = known_client_start.message.serialize().to_vec();
        let (known_server_state, known_resp_bytes) = login_start(
            &setup,
            &known_cred_id,
            Some(&known_record_bytes),
            &known_req_bytes,
        )?;

        // Start login for unknown user (record_bytes = None)
        let unknown_client_start =
            ClientLogin::<TestClientSuite>::start(&mut rng, password).map_err(|_| AuthError)?;
        let unknown_req_bytes: Vec<u8> = unknown_client_start.message.serialize().to_vec();
        let (dummy_server_state, unknown_resp_bytes) =
            login_start(&setup, &unknown_cred_id, None, &unknown_req_bytes)?;

        // 1. Response byte length is identical for known and unknown emails (320 bytes).
        assert_eq!(known_resp_bytes.len(), 320);
        assert_eq!(unknown_resp_bytes.len(), known_resp_bytes.len());

        // 2. Client's finish fails with generic error on the dummy response.
        let unknown_cred_resp =
            CredentialResponse::<TestClientSuite>::deserialize(&unknown_resp_bytes)
                .map_err(|_| AuthError)?;
        let unknown_client_finish = unknown_client_start.state.finish(
            &mut rng,
            password,
            unknown_cred_resp,
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        );
        assert!(
            unknown_client_finish.is_err(),
            "expected client finishLogin to fail on dummy response for unknown email"
        );

        // 3. Produce a real-shaped finalization message (from the known session) and pass it to
        //    the server's dummy login state: login_finish on the dummy state fails with the same uniform AuthError.
        let known_cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&known_resp_bytes)
            .map_err(|_| AuthError)?;
        let known_client_finish = known_client_start
            .state
            .finish(
                &mut rng,
                password,
                known_cred_resp,
                ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| AuthError)?;
        let forged_finalization_bytes: Vec<u8> = known_client_finish.message.serialize().to_vec();

        let dummy_finish_res = login_finish(dummy_server_state, &forged_finalization_bytes);
        assert_eq!(dummy_finish_res, Err(AuthError));

        // Verify the known state still succeeds with its legitimate finalization.
        login_finish(known_server_state, &forged_finalization_bytes)?;

        Ok(())
    }

    #[test]
    fn registration_record_survives_serialize_store_deserialize() -> Result<(), AuthError> {
        let setup = OpaqueServerSetup::generate();
        let cred_key = CredentialIdKey::from_bytes([0x88; 32]);
        let canon = canonicalize_email("persist@example.com").map_err(|_| AuthError)?;
        let cred_id = credential_identifier(&cred_key, &canon);
        let password = b"persisted-password";

        // 1. Register and obtain serialized record bytes
        let (record_bytes, reg_export_key) = register_user_bytes(&setup, &cred_id, password)?;
        assert_eq!(record_bytes.len(), 192);

        // 2. Simulate database storage (clone into fresh Vec<u8>, deserialize and re-serialize)
        let stored_in_db: Vec<u8> = record_bytes.clone();
        let deserialized =
            ServerRegistration::<ServerSuite>::deserialize(&stored_in_db).map_err(|_| AuthError)?;
        let roundtripped_bytes: Vec<u8> = deserialized.serialize().to_vec();
        assert_eq!(stored_in_db, roundtripped_bytes);

        // 3. Complete a full login against the round-tripped bytes
        let mut rng = OsRng;
        let ksf = test_ksf()?;
        let client_start =
            ClientLogin::<TestClientSuite>::start(&mut rng, password).map_err(|_| AuthError)?;
        let req_bytes: Vec<u8> = client_start.message.serialize().to_vec();

        let (server_state, resp_bytes) =
            login_start(&setup, &cred_id, Some(&roundtripped_bytes), &req_bytes)?;
        let cred_resp = CredentialResponse::<TestClientSuite>::deserialize(&resp_bytes)
            .map_err(|_| AuthError)?;
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                password,
                cred_resp,
                ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| AuthError)?;

        login_finish(server_state, &client_finish.message.serialize())?;
        assert_eq!(
            client_finish.export_key.as_slice(),
            reg_export_key.as_slice()
        );

        Ok(())
    }

    #[test]
    fn pending_login_store_enforces_expiry_single_use_and_capacity_cap() -> Result<(), AuthError> {
        let setup = OpaqueServerSetup::generate();
        let cred_id = [0xAAu8; 32];
        let mut rng = OsRng;

        let client_start =
            ClientLogin::<TestClientSuite>::start(&mut rng, b"pw").map_err(|_| AuthError)?;
        let req_bytes: Vec<u8> = client_start.message.serialize().to_vec();
        let (sample_state, _) = login_start(&setup, &cred_id, None, &req_bytes)?;

        let store = PendingLoginStore::new();
        let t0 = Instant::now();
        let user_uuid = Uuid::from_bytes([0x12; 16]);

        // 1. Replay test: take() succeeds once and rejects a second take() with the same login_id.
        let login_id = store.insert(sample_state.clone(), Some(user_uuid), t0)?;
        let (_taken_state, taken_user) = store.take(&login_id, t0 + Duration::from_secs(5))?;
        assert_eq!(taken_user, Some(user_uuid));

        let replay_res = store.take(&login_id, t0 + Duration::from_secs(6));
        assert_eq!(replay_res.err(), Some(AuthError));

        // 2. Expiry test: state taken at or after 60-second TTL is rejected.
        let expired_id = store.insert(sample_state.clone(), None, t0)?;
        let expired_res = store.take(&expired_id, t0 + LOGIN_STATE_TTL);
        assert_eq!(expired_res.err(), Some(AuthError));

        // 3. Hard cap test: fill store to MAX_PENDING_LOGINS (10,000) at t0.
        for _ in 0..MAX_PENDING_LOGINS {
            store.insert(sample_state.clone(), None, t0)?;
        }
        assert_eq!(store.len()?, MAX_PENDING_LOGINS);

        // Next insert while all 10,000 are still unexpired must be rejected.
        let overflow_res = store.insert(sample_state.clone(), None, t0 + Duration::from_secs(30));
        assert_eq!(overflow_res, Err(AuthError));
        assert_eq!(store.len()?, MAX_PENDING_LOGINS);

        // Once TTL has elapsed, insert() purges expired entries first and succeeds.
        let after_ttl = t0 + LOGIN_STATE_TTL + Duration::from_secs(1);
        let fresh_id = store.insert(sample_state, Some(user_uuid), after_ttl)?;
        assert_eq!(store.len()?, 1);
        let (_, recovered_user) = store.take(&fresh_id, after_ttl)?;
        assert_eq!(recovered_user, Some(user_uuid));

        Ok(())
    }
}
