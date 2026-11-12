#![forbid(unsafe_code)]

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Maximum total byte length permitted across all `Cookie` request headers (4 KiB).
pub const MAX_COOKIE_HEADER_BYTES: usize = 4096;

/// Expected base64url string length of a 32-byte opaque token without padding.
pub const TOKEN_B64_LEN: usize = 43;

/// Controls cookie security attributes and names.
///
/// By default (`dev_insecure_cookies == false`), cookies use the `__Host-` prefix
/// (`__Host-at`, `__Host-rt`) and ALWAYS include `HttpOnly; Secure; SameSite=Strict; Path=/`
/// with NO `Domain` attribute.
///
/// When `dev_insecure_cookies == true` (for local plain-HTTP `http://localhost` development only),
/// `Secure` and the `__Host-` prefix are omitted (`at`, `rt`) because browsers drop `__Host-`
/// cookies that lack `Secure`. `HttpOnly`, `SameSite=Strict`, `Path=/`, and the absence of
/// `Domain` remain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CookieSettings {
    pub dev_insecure_cookies: bool,
}

impl CookieSettings {
    pub const fn new(dev_insecure_cookies: bool) -> Self {
        Self {
            dev_insecure_cookies,
        }
    }

    pub const fn access_cookie_name(&self) -> &'static str {
        if self.dev_insecure_cookies {
            "at"
        } else {
            "__Host-at"
        }
    }

    pub const fn refresh_cookie_name(&self) -> &'static str {
        if self.dev_insecure_cookies {
            "rt"
        } else {
            "__Host-rt"
        }
    }

    pub const fn is_secure(&self) -> bool {
        !self.dev_insecure_cookies
    }

    /// Builds a `Set-Cookie` header value for the access token.
    pub fn build_access_cookie(&self, token: &str) -> Result<HeaderValue, CookieError> {
        self.build_token_cookie(self.access_cookie_name(), token)
    }

    /// Builds a `Set-Cookie` header value for the refresh token.
    pub fn build_refresh_cookie(&self, token: &str) -> Result<HeaderValue, CookieError> {
        self.build_token_cookie(self.refresh_cookie_name(), token)
    }

    /// Builds a `Set-Cookie` header value that clears the access token cookie immediately.
    pub fn build_clear_access_cookie(&self) -> HeaderValue {
        self.build_clear_cookie(self.access_cookie_name())
    }

    /// Builds a `Set-Cookie` header value that clears the refresh token cookie immediately.
    pub fn build_clear_refresh_cookie(&self) -> HeaderValue {
        self.build_clear_cookie(self.refresh_cookie_name())
    }

    fn build_token_cookie(&self, name: &str, token: &str) -> Result<HeaderValue, CookieError> {
        if !is_canonical_token_str(token) {
            return Err(CookieError::InvalidTokenValue);
        }

        let raw = if self.dev_insecure_cookies {
            format!("{name}={token}; HttpOnly; SameSite=Strict; Path=/")
        } else {
            format!("{name}={token}; HttpOnly; Secure; SameSite=Strict; Path=/")
        };

        HeaderValue::from_str(&raw).map_err(|_| CookieError::InvalidTokenValue)
    }

    fn build_clear_cookie(&self, name: &str) -> HeaderValue {
        if self.dev_insecure_cookies {
            let raw = format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
            // Cookie name and static attributes are guaranteed valid ASCII HeaderValue bytes.
            HeaderValue::from_str(&raw)
                .unwrap_or_else(|_| HeaderValue::from_static("at=; Max-Age=0"))
        } else {
            let raw = format!("{name}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0");
            HeaderValue::from_str(&raw)
                .unwrap_or_else(|_| HeaderValue::from_static("__Host-at=; Secure; Max-Age=0"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieError {
    Empty,
    Oversized,
    Malformed,
    Duplicate,
    InvalidTokenValue,
}

fn is_valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            matches!(
                b,
                b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
        })
}

fn is_valid_cookie_octet(b: u8) -> bool {
    // RFC 6265 cookie-octet: US-ASCII characters excluding CTLs, whitespace, DQUOTE, comma, semicolon, backslash.
    matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
}

fn is_valid_cookie_value(val: &str) -> bool {
    val.bytes().all(is_valid_cookie_octet)
}

fn is_canonical_token_str(token: &str) -> bool {
    if token.len() != TOKEN_B64_LEN {
        return false;
    }
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(token) else {
        return false;
    };
    let Ok(arr): Result<[u8; 32], _> = bytes.try_into() else {
        return false;
    };
    URL_SAFE_NO_PAD.encode(arr) == token
}

/// Parses a single `Cookie` header string into `(name, value)` pairs.
/// Rejects empty, oversized, malformed, and duplicate-named cookies.
pub fn parse_cookie_header_str(raw: &str) -> Result<Vec<(&str, &str)>, CookieError> {
    if raw.len() > MAX_COOKIE_HEADER_BYTES {
        return Err(CookieError::Oversized);
    }
    if raw.trim().is_empty() {
        return Err(CookieError::Empty);
    }
    if !raw.is_ascii() || raw.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err(CookieError::Malformed);
    }

    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for segment in raw.split(';') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            return Err(CookieError::Malformed);
        }
        let Some((name, val)) = trimmed.split_once('=') else {
            return Err(CookieError::Malformed);
        };
        if !is_valid_cookie_name(name) || !is_valid_cookie_value(val) {
            return Err(CookieError::Malformed);
        }
        if pairs.iter().any(|(existing, _)| *existing == name) {
            return Err(CookieError::Duplicate);
        }
        pairs.push((name, val));
    }

    Ok(pairs)
}

/// Parses all `Cookie` headers in an HTTP `HeaderMap`.
/// Returns an empty vector if no `Cookie` header is present.
/// Rejects empty, oversized, malformed, or duplicate cookies (even across multiple `Cookie` headers).
pub fn parse_cookie_headers(headers: &HeaderMap) -> Result<Vec<(&str, &str)>, CookieError> {
    let mut all_pairs: Vec<(&str, &str)> = Vec::new();
    let mut total_bytes: usize = 0;

    for header_val in headers.get_all(COOKIE) {
        let Ok(raw) = header_val.to_str() else {
            return Err(CookieError::Malformed);
        };
        total_bytes = total_bytes.saturating_add(raw.len());
        if total_bytes > MAX_COOKIE_HEADER_BYTES {
            return Err(CookieError::Oversized);
        }
        let parsed = parse_cookie_header_str(raw)?;
        for (name, val) in parsed {
            if all_pairs.iter().any(|(existing, _)| *existing == name) {
                return Err(CookieError::Duplicate);
            }
            all_pairs.push((name, val));
        }
    }

    Ok(all_pairs)
}

/// Extracts and strictly decodes a 32-byte base64url token cookie by name.
/// Returns `None` if no `Cookie` header is present, the cookie is missing, the header
/// is malformed/duplicate/oversized/empty, or the value is not a canonical 32-byte token.
pub fn extract_token_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<[u8; 32]> {
    let pairs = parse_cookie_headers(headers).ok()?;
    let (_, val) = pairs.into_iter().find(|(name, _)| *name == cookie_name)?;
    if val.len() != TOKEN_B64_LEN {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(val).ok()?;
    let arr: [u8; 32] = decoded.try_into().ok()?;
    if URL_SAFE_NO_PAD.encode(arr) != val {
        return None;
    }
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn sample_token(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 32])
    }

    #[test]
    fn default_cookies_always_have_host_prefix_secure_httponly_samesite_path_and_no_domain(
    ) -> Result<(), Box<dyn Error>> {
        let settings = CookieSettings::default();
        assert!(settings.is_secure());
        assert_eq!(settings.access_cookie_name(), "__Host-at");
        assert_eq!(settings.refresh_cookie_name(), "__Host-rt");

        let at_tok = sample_token(0x11);
        let rt_tok = sample_token(0x22);

        let at_hdr = settings
            .build_access_cookie(&at_tok)
            .map_err(|_| "valid access token failed")?;
        let at_str = at_hdr.to_str()?;
        assert_eq!(
            at_str,
            format!("__Host-at={at_tok}; HttpOnly; Secure; SameSite=Strict; Path=/")
        );
        assert!(!at_str.to_ascii_lowercase().contains("domain="));

        let rt_hdr = settings
            .build_refresh_cookie(&rt_tok)
            .map_err(|_| "valid refresh token failed")?;
        let rt_str = rt_hdr.to_str()?;
        assert_eq!(
            rt_str,
            format!("__Host-rt={rt_tok}; HttpOnly; Secure; SameSite=Strict; Path=/")
        );
        assert!(!rt_str.to_ascii_lowercase().contains("domain="));

        let clear_at = settings.build_clear_access_cookie();
        assert_eq!(
            clear_at.to_str()?,
            "__Host-at=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        );
        let clear_rt = settings.build_clear_refresh_cookie();
        assert_eq!(
            clear_rt.to_str()?,
            "__Host-rt=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
        );
        Ok(())
    }

    #[test]
    fn dev_insecure_switch_omits_secure_and_host_prefix_while_keeping_other_attributes(
    ) -> Result<(), Box<dyn Error>> {
        let settings = CookieSettings::new(true);
        assert!(!settings.is_secure());
        assert_eq!(settings.access_cookie_name(), "at");
        assert_eq!(settings.refresh_cookie_name(), "rt");

        let at_tok = sample_token(0x33);
        let at_hdr = settings
            .build_access_cookie(&at_tok)
            .map_err(|_| "valid access token failed")?;
        let at_str = at_hdr.to_str()?;
        assert_eq!(
            at_str,
            format!("at={at_tok}; HttpOnly; SameSite=Strict; Path=/")
        );
        assert!(!at_str.contains("Secure"));
        assert!(!at_str.contains("__Host-"));
        assert!(!at_str.to_ascii_lowercase().contains("domain="));

        let clear_rt = settings.build_clear_refresh_cookie();
        assert_eq!(
            clear_rt.to_str()?,
            "rt=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        );
        Ok(())
    }

    #[test]
    fn cookie_parser_rejects_empty_oversized_malformed_and_duplicate_headers() {
        // Empty
        assert_eq!(parse_cookie_header_str(""), Err(CookieError::Empty));
        assert_eq!(parse_cookie_header_str("   \t  "), Err(CookieError::Empty));

        // Oversized (> 4096 bytes)
        let big_val = "a".repeat(MAX_COOKIE_HEADER_BYTES + 1);
        let big_header = format!("__Host-at={big_val}");
        assert_eq!(
            parse_cookie_header_str(&big_header),
            Err(CookieError::Oversized)
        );

        // Malformed cases
        for malformed in [
            "no_equals_sign",
            "=missing_name",
            "__Host-at=abc; ",
            "__Host-at=abc;;__Host-rt=def",
            "bad name=abc",
            "__Host-at=val with space",
            "__Host-at=\"quoted\"",
            "__Host-at=val,comma",
            "__Host-at=val\\slash",
            "__Host-at=abc\r\ndef",
            "__Host-at=café",
        ] {
            assert_eq!(
                parse_cookie_header_str(malformed),
                Err(CookieError::Malformed),
                "expected Malformed for: {malformed:?}"
            );
        }

        // Duplicate in single header
        assert_eq!(
            parse_cookie_header_str("__Host-at=aaa; __Host-at=bbb"),
            Err(CookieError::Duplicate)
        );

        // Duplicate across two Cookie header lines
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("__Host-at=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        headers.append(
            COOKIE,
            HeaderValue::from_static("__Host-at=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );
        assert_eq!(parse_cookie_headers(&headers), Err(CookieError::Duplicate));
        assert_eq!(extract_token_cookie(&headers, "__Host-at"), None);
    }

    #[test]
    fn cookie_parser_accepts_valid_tokens_and_rejects_non_canonical_tokens(
    ) -> Result<(), Box<dyn Error>> {
        let tok_a = sample_token(0x44);
        let tok_b = sample_token(0x55);

        let mut headers = HeaderMap::new();
        let combined = format!("__Host-at={tok_a}; __Host-rt={tok_b}");
        headers.insert(COOKIE, HeaderValue::from_str(&combined)?);

        assert_eq!(
            extract_token_cookie(&headers, "__Host-at"),
            Some([0x44u8; 32])
        );
        assert_eq!(
            extract_token_cookie(&headers, "__Host-rt"),
            Some([0x55u8; 32])
        );
        assert_eq!(extract_token_cookie(&headers, "other"), None);

        // Non-canonical 43-char base64url (non-zero unused trailing bits) must be rejected.
        // Byte 31 is 0x00, 43rd char for 32 zero bytes is 'A'; changing last char to 'B' sets unused bits.
        let mut non_canonical = sample_token(0x00);
        non_canonical.pop();
        non_canonical.push('B');
        let mut bad_headers = HeaderMap::new();
        bad_headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("__Host-at={non_canonical}"))?,
        );
        assert_eq!(extract_token_cookie(&bad_headers, "__Host-at"), None);
        Ok(())
    }
}
