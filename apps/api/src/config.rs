#![forbid(unsafe_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use opaque_ke::ServerSetup;
use std::env;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use crate::auth::opaque::ServerSuite;

/// Expected byte length of the decoded `OPAQUE_SERVER_SETUP` secret.
pub const OPAQUE_SERVER_SETUP_LEN: usize = 128;

/// Expected byte length of the decoded `CREDENTIAL_ID_KEY` secret.
pub const CREDENTIAL_ID_KEY_LEN: usize = 32;

/// Expected byte length of the decoded `EMAIL_HASH_KEY` secret.
pub const EMAIL_HASH_KEY_LEN: usize = 32;

/// Wrapper around `opaque_ke::ServerSetup<ServerSuite>`.
/// Never prints secret material in `Debug` output.
#[derive(Clone)]
pub struct OpaqueServerSetup {
    inner: ServerSetup<ServerSuite>,
}

impl OpaqueServerSetup {
    /// Deserializes and validates a 128-byte OPAQUE `ServerSetup`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() != OPAQUE_SERVER_SETUP_LEN {
            return Err(ConfigError::InvalidSecretLength {
                name: "OPAQUE_SERVER_SETUP",
                expected: OPAQUE_SERVER_SETUP_LEN,
                actual: bytes.len(),
            });
        }
        let inner = ServerSetup::<ServerSuite>::deserialize(bytes)
            .map_err(|_| ConfigError::InvalidOpaqueServerSetup)?;
        Ok(Self { inner })
    }

    /// Generates a fresh random `OpaqueServerSetup` using `OsRng`.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            inner: ServerSetup::<ServerSuite>::new(&mut rng),
        }
    }

    /// Borrows the inner `opaque_ke::ServerSetup<ServerSuite>`.
    pub fn as_inner(&self) -> &ServerSetup<ServerSuite> {
        &self.inner
    }

    /// Serializes the setup into its 128-byte representation.
    pub fn to_bytes(&self) -> [u8; OPAQUE_SERVER_SETUP_LEN] {
        let serialized = self.inner.serialize();
        let mut out = [0u8; OPAQUE_SERVER_SETUP_LEN];
        out.copy_from_slice(&serialized);
        out
    }
}

impl PartialEq for OpaqueServerSetup {
    fn eq(&self, other: &Self) -> bool {
        self.inner.serialize() == other.inner.serialize()
    }
}

impl Eq for OpaqueServerSetup {}

impl fmt::Debug for OpaqueServerSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// 32-byte HMAC key used exclusively to derive OPAQUE `credential_identifier` values.
/// Never prints secret material in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialIdKey([u8; CREDENTIAL_ID_KEY_LEN]);

impl CredentialIdKey {
    pub fn from_bytes(bytes: [u8; CREDENTIAL_ID_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, ConfigError> {
        if slice.len() != CREDENTIAL_ID_KEY_LEN {
            return Err(ConfigError::InvalidSecretLength {
                name: "CREDENTIAL_ID_KEY",
                expected: CREDENTIAL_ID_KEY_LEN,
                actual: slice.len(),
            });
        }
        let mut out = [0u8; CREDENTIAL_ID_KEY_LEN];
        out.copy_from_slice(slice);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; CREDENTIAL_ID_KEY_LEN] {
        &self.0
    }
}

impl Drop for CredentialIdKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for CredentialIdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// 32-byte HMAC key used exclusively to compute `users.email_hash` database lookup keys.
/// Never prints secret material in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct EmailHashKey([u8; EMAIL_HASH_KEY_LEN]);

impl EmailHashKey {
    pub fn from_bytes(bytes: [u8; EMAIL_HASH_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, ConfigError> {
        if slice.len() != EMAIL_HASH_KEY_LEN {
            return Err(ConfigError::InvalidSecretLength {
                name: "EMAIL_HASH_KEY",
                expected: EMAIL_HASH_KEY_LEN,
                actual: slice.len(),
            });
        }
        let mut out = [0u8; EMAIL_HASH_KEY_LEN];
        out.copy_from_slice(slice);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; EMAIL_HASH_KEY_LEN] {
        &self.0
    }
}

impl Drop for EmailHashKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for EmailHashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AppConfig {
    pub host: IpAddr,
    pub port: u16,
    pub database_url: String,
    pub opaque_server_setup: OpaqueServerSetup,
    pub credential_id_key: CredentialIdKey,
    pub email_hash_key: EmailHashKey,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database_url", &"[redacted]")
            .field("opaque_server_setup", &self.opaque_server_setup)
            .field("credential_id_key", &self.credential_id_key)
            .field("email_hash_key", &self.email_hash_key)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    MissingVar(&'static str),
    InvalidHost(String),
    InvalidPort(String),
    InvalidSecretEncoding(&'static str),
    InvalidSecretLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    InvalidOpaqueServerSetup,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar(name) => write!(f, "missing required environment variable: {name}"),
            Self::InvalidHost(val) => write!(f, "invalid API_HOST value: {val}"),
            Self::InvalidPort(val) => write!(f, "invalid API_PORT value: {val}"),
            Self::InvalidSecretEncoding(name) => {
                write!(
                    f,
                    "invalid base64url encoding for environment variable: {name}"
                )
            }
            Self::InvalidSecretLength {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid byte length for {name}: expected {expected} bytes, got {actual} bytes"
                )
            }
            Self::InvalidOpaqueServerSetup => {
                write!(
                    f,
                    "invalid OPAQUE_SERVER_SETUP: failed to deserialize ServerSetup"
                )
            }
        }
    }
}

impl Error for ConfigError {}

fn decode_required_secret<F>(lookup: &F, name: &'static str) -> Result<Vec<u8>, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let raw = lookup(name).ok_or(ConfigError::MissingVar(name))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::MissingVar(name));
    }
    let unpadded = trimmed.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(unpadded)
        .map_err(|_| ConfigError::InvalidSecretEncoding(name))
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| env::var(key).ok())
    }

    pub fn from_lookup<F>(lookup: F) -> Result<Self, ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let host_raw = lookup("API_HOST").unwrap_or_else(|| String::from("127.0.0.1"));
        let host = host_raw
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::InvalidHost(host_raw))?;

        let port_raw = lookup("API_PORT").unwrap_or_else(|| String::from("8080"));
        let port = port_raw
            .parse::<u16>()
            .map_err(|_| ConfigError::InvalidPort(port_raw))?;

        let database_url = lookup("DATABASE_URL").ok_or(ConfigError::MissingVar("DATABASE_URL"))?;
        if database_url.trim().is_empty() {
            return Err(ConfigError::MissingVar("DATABASE_URL"));
        }

        let setup_bytes = decode_required_secret(&lookup, "OPAQUE_SERVER_SETUP")?;
        let opaque_server_setup = OpaqueServerSetup::from_bytes(&setup_bytes)?;

        let cred_key_bytes = decode_required_secret(&lookup, "CREDENTIAL_ID_KEY")?;
        let credential_id_key = CredentialIdKey::from_slice(&cred_key_bytes)?;

        let email_key_bytes = decode_required_secret(&lookup, "EMAIL_HASH_KEY")?;
        let email_hash_key = EmailHashKey::from_slice(&email_key_bytes)?;

        Ok(Self {
            host,
            port,
            database_url,
            opaque_server_setup,
            credential_id_key,
            email_hash_key,
        })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_env_lookup(key: &str) -> Option<String> {
        let setup = OpaqueServerSetup::generate();
        let setup_b64 = URL_SAFE_NO_PAD.encode(setup.to_bytes());
        let cred_b64 = URL_SAFE_NO_PAD.encode([0x42u8; 32]);
        let email_b64 = URL_SAFE_NO_PAD.encode([0x99u8; 32]);

        match key {
            "API_HOST" => Some(String::from("127.0.0.1")),
            "API_PORT" => Some(String::from("8080")),
            "DATABASE_URL" => Some(String::from("postgres://user:pass@127.0.0.1:5432/db")),
            "OPAQUE_SERVER_SETUP" => Some(setup_b64),
            "CREDENTIAL_ID_KEY" => Some(cred_b64),
            "EMAIL_HASH_KEY" => Some(email_b64),
            _ => None,
        }
    }

    #[test]
    fn valid_config_loads_and_redacts_secrets_in_debug() -> Result<(), ConfigError> {
        let cfg = AppConfig::from_lookup(valid_env_lookup)?;
        assert_eq!(cfg.port, 8080);

        let debug_str = format!("{cfg:?}");
        assert!(debug_str.contains("[redacted]"));
        assert!(!debug_str.contains("postgres://"));
        assert_eq!(format!("{:?}", cfg.opaque_server_setup), "[redacted]");
        assert_eq!(format!("{:?}", cfg.credential_id_key), "[redacted]");
        assert_eq!(format!("{:?}", cfg.email_hash_key), "[redacted]");
        Ok(())
    }

    #[test]
    fn missing_or_wrong_length_secrets_fail_fast() {
        for required in [
            "DATABASE_URL",
            "OPAQUE_SERVER_SETUP",
            "CREDENTIAL_ID_KEY",
            "EMAIL_HASH_KEY",
        ] {
            let res = AppConfig::from_lookup(|k| {
                if k == required {
                    None
                } else {
                    valid_env_lookup(k)
                }
            });
            assert_eq!(res, Err(ConfigError::MissingVar(required)));
        }

        // Wrong byte length for OPAQUE_SERVER_SETUP (32 bytes instead of 128)
        let short_setup = URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        let res_setup_len = AppConfig::from_lookup(|k| {
            if k == "OPAQUE_SERVER_SETUP" {
                Some(short_setup.clone())
            } else {
                valid_env_lookup(k)
            }
        });
        assert_eq!(
            res_setup_len,
            Err(ConfigError::InvalidSecretLength {
                name: "OPAQUE_SERVER_SETUP",
                expected: 128,
                actual: 32,
            })
        );

        // Wrong byte length for CREDENTIAL_ID_KEY (16 bytes instead of 32)
        let short_cred = URL_SAFE_NO_PAD.encode([0x22u8; 16]);
        let res_cred_len = AppConfig::from_lookup(|k| {
            if k == "CREDENTIAL_ID_KEY" {
                Some(short_cred.clone())
            } else {
                valid_env_lookup(k)
            }
        });
        assert_eq!(
            res_cred_len,
            Err(ConfigError::InvalidSecretLength {
                name: "CREDENTIAL_ID_KEY",
                expected: 32,
                actual: 16,
            })
        );

        // Wrong byte length for EMAIL_HASH_KEY (64 bytes instead of 32)
        let long_email_key = URL_SAFE_NO_PAD.encode([0x33u8; 64]);
        let res_email_len = AppConfig::from_lookup(|k| {
            if k == "EMAIL_HASH_KEY" {
                Some(long_email_key.clone())
            } else {
                valid_env_lookup(k)
            }
        });
        assert_eq!(
            res_email_len,
            Err(ConfigError::InvalidSecretLength {
                name: "EMAIL_HASH_KEY",
                expected: 32,
                actual: 64,
            })
        );

        // Invalid base64url encoding
        let res_bad_b64 = AppConfig::from_lookup(|k| {
            if k == "CREDENTIAL_ID_KEY" {
                Some(String::from("not valid base64url!!!"))
            } else {
                valid_env_lookup(k)
            }
        });
        assert_eq!(
            res_bad_b64,
            Err(ConfigError::InvalidSecretEncoding("CREDENTIAL_ID_KEY"))
        );
    }
}
