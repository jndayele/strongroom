# Strongroom Pre-Release Security Checklist

*Derived from [`/docs/PRD.md`](../../docs/PRD.md) (Sections 4–19) and [`/docs/SECURITY_RULES.MD`](../../docs/SECURITY_RULES.MD).*

## 1. Zero-Knowledge & Cryptography (PRD Sections 5, 6, 13, 14)

- [ ] **F1 (Decryption-Impossibility Gate):** Automated test verifies that a full dump of PostgreSQL plus all server environment secrets cannot decrypt `wrapped_km`, `wrapped_ks_master`, `meta_blob`, or `secret_blob`.
- [ ] **Secret Key Enforcement:** 128-bit random Secret Key (`A3-XXXXXX-XXXXXX-XXXXX`) generated via `crypto.getRandomValues` at signup; Emergency Kit PDF downloaded client-side; user confirmed saving it by typing the last 4 characters.
- [ ] **Argon2id Floor:** OPAQUE client/server configured with Argon2id memory >= 64 MiB, iterations >= 3, parallelism = 1.
- [ ] **Key Separation:** `KEK = HKDF-SHA-256(export_key, secret_key, "vault-kek-v1")`; `K_m` and `K_s` are distinct 256-bit keys; `K_s` is never held in memory for more than 30 seconds during reveal.
- [ ] **Per-Item Keys & Nonces:** Every item uses a unique random 256-bit item key and fresh 96-bit GCM nonce via native WebCrypto (`AES-256-GCM`).
- [ ] **AAD Binding:** All ciphertexts bind `user_id || item_id || key_version || schema_version` in GCM AAD; tests verify tampering or cross-user/cross-item swaps fail decryption.
- [ ] **Encrypted Metadata & Padding:** Titles, URLs, usernames, notes, device names, and passkey names are encrypted; `meta_blob` and `secret_blob` are padded to 256-byte buckets (`padded_size`).
- [ ] **F4 (WebAuthn PRF Gate):** Automated test verifies that bypassing the UI prompt without a WebAuthn PRF output fails to decrypt `secret_blob`.
- [ ] **Known-Answer & Property Tests:** Cryptographic unit tests against standard test vectors, property-based tests for versioned envelopes, and parser fuzzing pass.

## 2. Authentication, Sessions & Anti-Enumeration (PRD Sections 6, 7, 13)

- [ ] **F2 (Anti-Enumeration Gate):** OPAQUE login requests for unknown emails are indistinguishable in payload and timing from registered emails.
- [ ] **Mandatory 2FA:** Every account enforces WebAuthn (passkey/security key, preferred) or TOTP at login, with 10 single-use hashed recovery codes issued once.
- [ ] **Hardened Cookies & Tokens:** Short-lived access token (10 minutes) in `__Host-` cookie (`HttpOnly; Secure; SameSite=Strict; Path=/`); rotating refresh token (7 days max, 24 hours idle) stored as hash only, with automatic session-family revocation on replay.
- [ ] **CSRF & CORS:** Custom CSRF header required on all mutating endpoints; CORS locked strictly to `https://app.<domain>`.
- [ ] **Throttling:** Per-IP and per-account sliding windows, exponential backoff, lockout after 10 failures, and Cloudflare edge rate limits on `/auth/*`.

## 3. Client-Side & Web-Delivery Hardening (PRD Sections 8, 9)

- [ ] **Key Storage Hygiene:** All in-memory keys are non-extractable `CryptoKey` objects where supported; zero keys or secrets in `localStorage`, `sessionStorage`, cookies, or URLs.
- [ ] **Auto-Lock & Ephemeral UI:** Auto-lock after 5 minutes idle (configurable down to 1 minute, never off), on logout, and on tab close; revealed passwords hide after 15 seconds; clipboard clears after 30 seconds.
- [ ] **Strict CSP & Trusted Types:** CSP matches [`/security/headers/security-headers.json`](../headers/security-headers.json) (`default-src 'none'`, `require-trusted-types-for 'script'`, no `unsafe-inline` or `unsafe-eval`).
- [ ] **Static Analysis Rules:** ESLint bans `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `eval`, `Math.random`, and explicit `any`.
- [ ] **Self-Hosted & SRI:** Zero third-party scripts, fonts, analytics, or CAPTCHAs; Subresource Integrity (SRI) hashes present on all built script and style tags.
- [ ] **Reproducible Build Hash:** Release build artifact hash published in the signed git tag and public transparency page.

## 4. Backend, Database & Infrastructure (PRD Sections 10, 12)

- [ ] **Memory & Type Safety:** `#![forbid(unsafe_code)]` enabled in all crate roots; `cargo clippy -- -D warnings` passes with zero warnings.
- [ ] **SQLx & Row Ownership:** Compile-time checked parameterized queries only; every user data query enforces `WHERE user_id = $session_user`; cross-user access tests pass.
- [ ] **Least-Privilege DB Roles:** Application DB role cannot `ALTER` or `DROP` schema; migrations run under a separate role; Render Postgres restricted to private network IP allowlist with encryption at rest and PITR enabled.
- [ ] **Container Hardening:** Multi-stage Docker build to `gcr.io/distroless/cc-debian12:nonroot`, running as non-root (`65532:65532`) with a read-only root filesystem; scanned and signed in CI.
- [ ] **Zero-Secret Logging:** Logs never contain request bodies, plaintext emails, tokens, keys, or ciphertexts; identifiers and IPs are hashed.

## 5. Supply Chain, Audit & Launch Readiness (PRD Sections 11, 14, 15, 16)

- [ ] **Supply Chain Gates:** All dependencies pinned to exact versions, reviewed after a 14-day cooling period; `npm ci --ignore-scripts`, `osv-scanner`, `gitleaks`, `cargo deny`, `cargo audit`, and `cargo vet` pass in CI; SBOM generated for release.
- [ ] **Third-Party Security Audit:** Independent cryptography and web application audit completed; zero open high or critical findings; audit report published.
- [ ] **Incident & Restore Drills:** Quarterly database restore drill and incident response kill-switch test completed and documented.
- [ ] **Disclosure & Legal:** `SECURITY.md` and `/.well-known/security.txt` live with real contact details; privacy policy and terms published; Data Protection Act, 2012 (Act 843) compliance verified.
