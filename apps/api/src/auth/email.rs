#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;
use std::fmt;

use crate::config::{CredentialIdKey, EmailHashKey};

/// Maximum valid email length (RFC 5321).
pub const MAX_EMAIL_LEN: usize = 254;

type HmacSha256 = Hmac<Sha256>;

/// Uniform error returned when an email address fails validation.
/// Note: Never includes the email input in error messages to prevent PII leaks in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailError {
    Empty,
    TooLong,
    NonAscii,
    ControlOrWhitespace,
    MissingOrMultipleAt,
    EmptyLocalPart,
    EmptyDomain,
}

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "email must not be empty"),
            Self::TooLong => write!(
                f,
                "email exceeds maximum length of {MAX_EMAIL_LEN} characters"
            ),
            Self::NonAscii => write!(f, "email must contain only ASCII characters"),
            Self::ControlOrWhitespace => {
                write!(f, "email must not contain whitespace or control characters")
            }
            Self::MissingOrMultipleAt => write!(f, "email must contain exactly one '@'"),
            Self::EmptyLocalPart => write!(f, "email local part must not be empty"),
            Self::EmptyDomain => write!(f, "email domain must not be empty"),
        }
    }
}

impl Error for EmailError {}

/// Canonicalizes an email address for deterministic hashing and OPAQUE credential derivation:
/// 1. Trims leading and trailing whitespace.
/// 2. Rejects empty strings.
/// 3. Requires ASCII-only characters (v1 limitation; rejects non-ASCII).
/// 4. Enforces a maximum length of 254 characters.
/// 5. Rejects any internal whitespace or ASCII control characters.
/// 6. Requires exactly one `@` with non-empty local part and non-empty domain.
/// 7. Converts all characters to ASCII lowercase.
pub fn canonicalize_email(raw: &str) -> Result<String, EmailError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(EmailError::Empty);
    }
    if !trimmed.is_ascii() {
        return Err(EmailError::NonAscii);
    }
    if trimmed.len() > MAX_EMAIL_LEN {
        return Err(EmailError::TooLong);
    }
    if trimmed
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(EmailError::ControlOrWhitespace);
    }

    let mut parts = trimmed.split('@');
    let local = parts.next().ok_or(EmailError::MissingOrMultipleAt)?;
    let domain = parts.next().ok_or(EmailError::MissingOrMultipleAt)?;
    if parts.next().is_some() {
        return Err(EmailError::MissingOrMultipleAt);
    }

    if local.is_empty() {
        return Err(EmailError::EmptyLocalPart);
    }
    if domain.is_empty() {
        return Err(EmailError::EmptyDomain);
    }

    Ok(trimmed.to_ascii_lowercase())
}

/// Computes `HMAC-SHA-256(EMAIL_HASH_KEY, canonical_email)` for database lookups (`users.email_hash`).
pub fn email_hash(key: &EmailHashKey, canonical_email: &str) -> [u8; 32] {
    hmac_sha256(key.as_bytes(), canonical_email.as_bytes())
}

/// Computes `HMAC-SHA-256(CREDENTIAL_ID_KEY, canonical_email)` for the OPAQUE `credential_identifier`.
pub fn credential_identifier(key: &CredentialIdKey, canonical_email: &str) -> [u8; 32] {
    hmac_sha256(key.as_bytes(), canonical_email.as_bytes())
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    // HMAC-SHA-256 accepts keys of any length; a 32-byte key is always valid,
    // but we handle the Result without unwrap/expect per project rules.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0u8; 32];
    };
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct EmailVectorFile {
        cases: Vec<EmailVectorCase>,
    }

    #[derive(Deserialize)]
    struct EmailVectorCase {
        input: String,
        expected: Option<String>,
        error: Option<String>,
    }

    fn parse_expected_error(name: &str) -> Result<EmailError, String> {
        match name {
            "Empty" => Ok(EmailError::Empty),
            "TooLong" => Ok(EmailError::TooLong),
            "NonAscii" => Ok(EmailError::NonAscii),
            "ControlOrWhitespace" => Ok(EmailError::ControlOrWhitespace),
            "MissingOrMultipleAt" => Ok(EmailError::MissingOrMultipleAt),
            "EmptyLocalPart" => Ok(EmailError::EmptyLocalPart),
            "EmptyDomain" => Ok(EmailError::EmptyDomain),
            other => Err(format!(
                "unknown EmailError variant in test vectors: {other}"
            )),
        }
    }

    #[test]
    fn canonicalize_and_hmac_consistency_and_domain_separation() {
        let raw_messy = "  Alice.Smith@Example.COM\n";
        let raw_clean = "alice.smith@example.com";

        let canon_messy = canonicalize_email(raw_messy);
        let canon_clean = canonicalize_email(raw_clean);
        assert_eq!(canon_messy, Ok(String::from("alice.smith@example.com")));
        assert_eq!(canon_messy, canon_clean);

        let canon = canon_clean.unwrap_or_default();
        let email_key = EmailHashKey::from_bytes([0x11; 32]);
        let cred_key = CredentialIdKey::from_bytes([0x22; 32]);

        let hash_from_messy = email_hash(&email_key, &canon_messy.unwrap_or_default());
        let hash_from_clean = email_hash(&email_key, &canon);
        assert_eq!(hash_from_messy, hash_from_clean);

        let cred_from_messy = credential_identifier(&cred_key, &canon);
        let cred_from_clean = credential_identifier(&cred_key, raw_clean);
        assert_eq!(cred_from_messy, cred_from_clean);

        // Different keys produce distinct outputs for the same canonical email.
        assert_ne!(hash_from_clean, cred_from_clean);
    }

    #[test]
    fn shared_email_test_vectors_match_specification() -> Result<(), Box<dyn Error>> {
        let raw_json = include_str!("../../../../docs/test-vectors/email.json");
        let vectors: EmailVectorFile = serde_json::from_str(raw_json)?;
        assert!(!vectors.cases.is_empty());

        for case in vectors.cases {
            let actual = canonicalize_email(&case.input);
            match (case.expected, case.error) {
                (Some(expected), None) => {
                    assert_eq!(
                        actual,
                        Ok(expected),
                        "expected input {:?} to canonicalize cleanly",
                        case.input
                    );
                }
                (None, Some(err_name)) => {
                    let expected_err = parse_expected_error(&err_name)?;
                    assert_eq!(
                        actual,
                        Err(expected_err),
                        "expected input {:?} to fail with {expected_err:?}, got {actual:?}",
                        case.input
                    );
                }
                _ => {
                    return Err(format!(
                        "invalid test vector entry for input {:?}: must set exactly one of expected or error",
                        case.input
                    )
                    .into());
                }
            }
        }

        Ok(())
    }
}
