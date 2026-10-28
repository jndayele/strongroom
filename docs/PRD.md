# Password Vault: Product Requirements Document

*Version 1.0 (locked for build). Solo founder. Web app first. Zero-knowledge by design.*

## 1. Product summary

A web-based password vault where users store credentials that only they can read. All encryption happens in the user's browser. The server stores only ciphertext and can never read, reset, or recover a user's data. Revealing any password requires fresh proof of presence through biometrics or a passkey, backed cryptographically and not just by a UI gate.

**Promise to users:** *If we are hacked, subpoenaed, or acquired, your passwords stay unreadable.*

## 2. Goals and non-goals

### Goals

1. Zero-knowledge: the server never holds anything that can decrypt user data.
2. A database leak plus a server-secret leak still cannot be brute-forced, even against weak master passwords.
3. Biometric/passkey gating that is enforced by cryptography, with a safe fallback where unsupported.
4. A minimal attack surface and a minimal dependency count.
5. Transparent, publishable security design that can be independently audited.

### Non-goals for v1

- Shared vaults, teams, or family plans
- Browser autofill and a browser extension (planned for v2)
- File attachments
- SSO or social login (never: it would break the key model)
- Server-side password recovery (never)
- Any third-party analytics, ads, or trackers (never)

## 3. Locked technology decisions

| Area | Decision | Why |
| --- | --- | --- |
| Frontend | TypeScript (strict mode), React, Vite | Your choice; strict TS catches crypto-handling bugs early |
| Backend language | **Rust** with **Axum** | Memory-safe, tiny dependency surface compared with npm, single static binary, and it uses the same OPAQUE core (`opaque-ke`) that the browser client runs through WASM, so there is no cross-implementation protocol risk |
| Database | **PostgreSQL** on Render (managed), accessed via **SQLx** with compile-time checked queries | Encryption at rest, point-in-time recovery, private networking |
| Hosting | **Render** (static site for the frontend, Docker web service for the API, managed Postgres) | Your choice; keeps operations simple for one person |
| Edge | **Cloudflare** in front of both domains (DNS, WAF, DDoS, edge rate limits) | Render has no built-in WAF; Cloudflare covers it |
| Password-based auth | **OPAQUE** (RFC 9807) via `opaque-ke` (server) and `@serenity-kit/opaque` (client WASM) | Server never receives the password, and is immune to pre-computation attacks after a leak |
| Bulk encryption | **AES-256-GCM** via native **WebCrypto** | No crypto dependency to compromise; supports non-extractable keys |
| Key derivation | **Argon2id** inside OPAQUE (memory 64 MiB, 3 iterations, parallelism 1 as the minimum floor); **HKDF-SHA-256** for key separation | OWASP-aligned; tune upward after benchmarking on low-end phones |
| Biometrics/passkeys | **WebAuthn** with the **PRF extension**; `@simplewebauthn/server` is not used because the Rust server uses `webauthn-rs` | PRF is the only way biometrics can gate decryption cryptographically |
| Randomness | `crypto.getRandomValues` only | Never `Math.random` |

The only crypto-adjacent npm dependency is the OPAQUE client. Everything else uses the browser's built-in WebCrypto.

## 4. Threat model (summary)

| Attacker | Capability | Required outcome |
| --- | --- | --- |
| Database thief | Full copy of Postgres | Sees only ciphertext and OPAQUE records; cannot brute-force (see the Secret Key in section 5) |
| Server compromiser | Root on API, reads all secrets and memory | Cannot decrypt vaults; **can** serve malicious JS (see section 9) |
| Network attacker | MITM on a user's connection | Blocked by TLS 1.3, HSTS preload, and OPAQUE |
| Credential stuffer | Bulk login attempts | Rate limits, backoff, mandatory second factor |
| XSS attacker | Runs script in the page | Strict CSP and Trusted Types make injection very hard; non-extractable keys mean raw keys cannot be exported |
| Malicious dependency | Compromised npm or crates package | Minimal dependencies, pinned versions, delayed upgrades, CI audits |
| Stolen unlocked device | Physical access | Auto-lock; reveal needs fresh biometric/passkey |
| Malware on user's device | Keylogger or screen capture | **Out of scope** (stated openly in our docs) |
| Nation-state coercion of us | Legal demand for user data | We hold nothing readable |
| Insider (you or a future hire) | Production access | Same as server compromiser; plus access controls and audit logs |

## 5. Cryptographic design

### 5.1 Secrets a user holds

- **Master password:** chosen by the user. Minimum 12 characters, with a strength meter (zxcvbn) that blocks weak choices and a check against breached passwords via the Have I Been Pwned k-anonymity range API.
- **Secret Key:** 128 random bits generated in the browser at signup, formatted like `A3-XXXXXX-XXXXXX-XXXXX`. It is shown once in a downloadable **Emergency Kit** (client-side generated PDF) and stored on the device encrypted under a non-extractable device key. Required to sign in on any new device.

Because the Secret Key has 128 bits of entropy and never touches the server, an attacker who steals the database **and** the server's OPAQUE key still faces a 128-bit search no matter how weak the master password is.

### 5.2 Key hierarchy

1. `pw_input = HKDF(master_password || Secret Key)`. This is the input to OPAQUE registration and login.
2. OPAQUE produces an **export key** that only the client can derive.
3. `KEK = HKDF(export_key, secret_key, "vault-kek-v1")`. Never leaves the browser.
4. **Vault Metadata Key (K\_m)** and **Vault Secret Key (K\_s)** are random 256-bit keys generated at signup. They are stored on the server only **wrapped** (AES-256-GCM) under the KEK.
5. Each item has its own random 256-bit **item key**. The item's metadata (title, URL, username, notes) is encrypted with an item key wrapped by K\_m. The item's secret (password, TOTP seed, recovery codes) uses an item key wrapped by K\_s.
6. A second wrapped copy of K\_s exists under each registered passkey's **PRF-derived key** (section 6).

Why two vault keys: the vault list can be browsed and searched with K\_m, while K\_s is held in memory only for seconds, at the moment of reveal.

### 5.3 Item encryption rules

- A fresh random 96-bit nonce for every encryption; a fresh item key per item (this removes any GCM nonce-reuse concern).
- **Authenticated associated data (AAD)** binds every ciphertext to `user_id || item_id || key_version || schema_version`, so the server cannot swap, replay, or roll back items undetected.
- **Metadata is encrypted too.** The server sees only opaque IDs, timestamps, and padded ciphertext size (padded to 256-byte buckets). Search is client-side.
- Versioned envelope format on every blob, so algorithms can be migrated.

### 5.4 Master password change and rotation

- Changing the master password re-registers OPAQUE and re-wraps K\_m and K\_s. Item data is untouched.
- "Rotate vault keys" (after suspected compromise) re-encrypts all items client-side in a resumable background job.

### 5.5 Recovery

- **There is no server-side recovery.** If a user loses the master password **and** has no signed-in device, the data is gone. The signup flow forces the user to confirm they saved the Emergency Kit before continuing.
- A user who forgot only the master password but is still signed in on a device can set a new one from that device.

## 6. Biometrics and passkeys

- Users register one or more passkeys (platform: Face ID, Touch ID, Windows Hello, Android biometrics; or roaming: YubiKey) with `userVerification: "required"` and the PRF extension enabled.
- On registration, the authenticator returns PRF output. The browser derives a wrapping key and stores a copy of K\_s wrapped under it. The PRF output never leaves the browser.
- **Reveal flow:** the user taps Reveal; the browser triggers a WebAuthn assertion with PRF; the biometric/PIN check releases the PRF output; K\_s is unwrapped; the secret is decrypted, displayed, and K\_s is wiped from memory after at most 30 seconds.
- **Fallback when PRF is unsupported:** re-enter the master password (the Secret Key is already on the device). The UI says plainly that biometric gating is unavailable on this device and why.
- **Second factor at login:** WebAuthn (passkey or security key) is the default and strongly preferred. TOTP is allowed as a fallback. 2FA is **mandatory** for all accounts. Ten single-use recovery codes are issued, shown once, and stored hashed.
- Passkey management: list, rename, and revoke; a user must always keep at least one second factor.
- Where the platform allows, enforce a challenge freshness window of 60 seconds, and verify `origin`, `rpId`, sign counter, and challenge on the server.

## 7. Authentication and sessions

- Signup and login use OPAQUE. The server returns **indistinguishable fake responses** for unknown emails, to prevent user enumeration.
- After OPAQUE and the second factor succeed, the server issues:
  - a short-lived access token (10 minutes) in a `__Host-` prefixed cookie with `HttpOnly; Secure; SameSite=Strict; Path=/`;
  - a rotating refresh token (7 days max, 24 hours idle) with **reuse detection**: if a refresh token is replayed, the whole session family is revoked.
- Mutating requests require a custom CSRF header, plus strict CORS to the app origin only.
- Sessions are bound to a device record. Users can see all devices and revoke any remotely.
- New-device sign-in sends an email alert. Email is used only for alerts and verification, never for recovery of the vault.
- Email verification is required before any vault data is stored.
- Login throttling: per-IP and per-account sliding windows, exponential backoff, temporary lockout after 10 failures, and Cloudflare edge rate limits. No third-party CAPTCHA scripts, since that would violate the no-third-party-scripts rule.

## 8. Client-side security requirements

- Keys live in memory only, as **non-extractable `CryptoKey` objects** wherever the algorithm allows. No keys in `localStorage`, `sessionStorage`, cookies, or the URL.
- The only persisted material on a device is the Secret Key, wrapped under a non-extractable device key in IndexedDB.
- **Auto-lock:** after 5 minutes idle (user-configurable down to 1 minute, never off), on logout, and on tab close. Locking zeroes buffers and drops key references.
- Revealed passwords auto-hide after 15 seconds.
- Copy to clipboard auto-clears after 30 seconds (best effort in browsers); a notice explains the limitation.
- Password fields use `autocomplete="off"` or the correct `new-password`/`current-password` values, and the app disables browser-side caching of vault pages (`Cache-Control: no-store`).
- Built-in password generator using `crypto.getRandomValues` with rejection sampling to avoid modulo bias.
- Breach monitoring of stored passwords using HIBP k-anonymity (only a 5-character hash prefix leaves the browser).
- Export is an **encrypted** file by default; plaintext export requires fresh biometric/master password and shows a warning.
- No autofill in v1.

## 9. The web-delivery risk and how we contain it

In any web app, the server supplies the code that does the encryption. A compromised host or build pipeline could ship malicious JavaScript. We acknowledge this openly and reduce it with layers:

1. **Strict CSP:** `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://api.<domain>; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'`. No `unsafe-inline`, no `unsafe-eval`, no inline scripts, ever.
2. **Trusted Types** enforced; no `dangerouslySetInnerHTML`, and an ESLint rule bans it.
3. **Subresource Integrity** on every script and stylesheet; fonts and assets self-hosted.
4. **Other headers:** HSTS (2 years, `includeSubDomains`, preload), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` locking down unused features, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`.
5. **Deployment pipeline security:** protected `main` branch, signed commits, deploys only from CI after all checks pass, hardware security keys on GitHub, Render, Cloudflare, and the domain registrar, and no long-lived deploy tokens.
6. **Reproducible builds:** the build hash of every release is published on a public transparency page and in the git tag, so researchers can compare what's served against the source.
7. **Domain security:** registrar lock, DNSSEC, CAA records limited to your CA, and the domain on the HSTS preload list.
8. **Roadmap:** v2 ships a browser extension and native mobile apps, which do not trust our server for code delivery.

## 10. Server and infrastructure requirements

### Application

- Rust, `#![forbid(unsafe_code)]` in our own crates; clippy with deny-warnings.
- Parameterized queries only (SQLx); strict request size limits; strict JSON schema validation (reject unknown fields).
- Constant-time comparison for all secret comparisons; uniform error messages.
- OPAQUE server setup secret and cookie/token signing keys held as Render secrets, never in the repo, with a documented rotation procedure. Tokens are stored server-side only as hashes.
- Logs never contain request bodies, emails in plaintext, tokens, or ciphertext. Identifiers are hashed in logs.

### Container and runtime

- Multi-stage Docker build to a **distroless** image, running as non-root with a read-only filesystem.
- The image is built in CI, scanned (Trivy), and signed.

### Database

- Render managed Postgres with encryption at rest, **IP allowlist limited to the API service over Render's private network**, no public access.
- Point-in-time recovery enabled; backup restore drill every quarter.
- Row-level ownership checks in every query (`WHERE user_id = $session_user`); tests prove cross-user access is impossible.
- Least-privilege DB role: the app cannot alter schema; migrations run with a separate role.

### Edge and network

- Cloudflare WAF with managed rules, bot fight mode, rate-limiting rules for `/auth/*`, TLS 1.3 only, and "Full (strict)" origin mode.
- Separate origins: `app.<domain>` (static frontend) and `api.<domain>` (API).

### Operations

- Separate Render environments for staging and production, with separate databases, secrets, and domains.
- Audit log (append-only, shipped to an external log service) of: logins, failed logins, new devices, passkey changes, password changes, exports, deletions, and admin actions. Users see their own security log.
- Alerts on anomaly spikes, error rates, and failed-login bursts.
- Uptime monitoring and a public status page.

## 11. Supply-chain policy

- **Dependency budget:** every new dependency needs a written justification. Prefer the platform (WebCrypto, `fetch`) over packages.
- Exact version pinning; lockfiles committed; `npm ci --ignore-scripts` in CI; `cargo deny` and `cargo audit` in CI; `cargo vet` for crates we depend on directly.
- A **14-day cooling period** before adopting any newly released package version (matches common attack windows), except for confirmed security fixes.
- Automated dependency PRs through Renovate, reviewed by hand; OSV-Scanner and GitHub dependency review on every PR; secret scanning and push protection enabled.
- No postinstall scripts allowed; no packages from unverified publishers for crypto-adjacent functionality.
- SBOM generated for every release.

## 12. Data model (server)

All ciphertext columns are `bytea` with versioned envelopes.

- **users:** `id`, `email_hash`, `email_enc` (for alerts), `opaque_record`, `wrapped_km`, `wrapped_ks_master`, `kdf_params`, `key_version`, `created_at`
- **devices:** `id`, `user_id`, `name_enc`, `created_at`, `last_seen_at`, `revoked_at`
- **sessions:** `id`, `device_id`, `refresh_hash`, `family_id`, `expires_at`, `revoked_at`
- **passkeys:** `id`, `user_id`, `credential_id`, `public_key`, `sign_count`, `wrapped_ks_prf`, `name_enc`, `created_at`
- **totp:** `user_id`, `secret_enc` (encrypted with a server key), `verified_at`
- **recovery\_codes:** `user_id`, `code_hash`, `used_at`
- **items:** `id`, `user_id`, `meta_blob`, `secret_blob`, `wrapped_item_key_m`, `wrapped_item_key_s`, `version`, `padded_size`, `created_at`, `updated_at`, `deleted_at`
- **audit\_events:** `id`, `user_id`, `type`, `ip_hash`, `device_id`, `created_at`

## 13. Core features and acceptance criteria

### F1. Signup

- User enters email and master password; sees the strength result and the breach check.
- Secret Key is generated and the Emergency Kit is downloaded; the user must confirm saving it (typing the last 4 characters of the key) to proceed.
- **Done when:** the server DB contains no value that can decrypt anything, verified by a test that attempts decryption using only server-side data.

### F2. Login and new-device flow

- Email + master password + Secret Key (new device only) + second factor.
- **Done when:** login to an unknown email is indistinguishable from a known one in response and timing.

### F3. Vault items

- Create, read, update, delete, and search (client-side) for logins, secure notes, and TOTP seeds.
- Soft delete with a 30-day trash.
- **Done when:** a DB inspection shows no plaintext titles, URLs, or usernames.

### F4. Reveal with biometrics/passkey

- **Done when:** with PRF-capable hardware, an automated test proves that a compromised UI that skips the prompt cannot decrypt a secret (K\_s is unavailable without the PRF output).

### F5. Security center

- Device list with revoke, passkey management, session log, breach and reused/weak password report (client-side only).

### F6. Account lifecycle

- Change master password, rotate vault keys, export (encrypted by default), delete account (hard-delete within 24 hours; backups purged within 35 days).

## 14. Security testing and assurance

- Crypto unit tests against known test vectors; property-based tests for envelope encode/decode; fuzzing of all parsers.
- Automated E2E tests (Playwright) for signup, login, reveal, lock, and revocation.
- SAST (Semgrep, clippy), dependency scanning, container scanning, and ZAP DAST in CI on every merge.
- A **written crypto design document** (derived from this PRD) published before launch.
- **Independent third-party audit** of cryptography and web app before public launch; publish the report.
- **Responsible disclosure** page, `security.txt`, and a bug bounty after launch.
- **Private beta first** (capped users), with no marketing claims beyond what has been audited.
- Annual re-audit and a yearly restore and incident drill.

## 15. Incident response

- Written runbook with severity levels, key-rotation procedures, and token mass-revocation.
- User notification within 72 hours of a confirmed breach, with plain-language impact (what was and was not exposed).
- Kill switch to force-logout all sessions and to freeze deployments.

## 16. Privacy and legal

- Collected data: email, encrypted blobs, device and session metadata, hashed IPs. No analytics, no tracking.
- Publish a privacy policy and terms; honest security claims only (no "unhackable").
- Ghana's Data Protection Act, 2012 (Act 843) likely applies; confirm registration requirements with the Data Protection Commission and a local lawyer. Design for GDPR-level rights (export, deletion) from day one.
- Choose the Render region to match the majority of your users, keeping in mind data-residency obligations.

## 17. Build milestones

| Phase | Scope | Exit gate |
| --- | --- | --- |
| 0 | Threat model, crypto design doc, repo setup, CI security gates, domain and Cloudflare hardening | Doc reviewed by an outside cryptographer if possible |
| 1 | OPAQUE signup/login, Secret Key, key wrapping, sessions, 2FA | Server-side decryption-impossibility tests pass |
| 2 | Encrypted item CRUD, client-side search, auto-lock, clipboard handling | DB inspection shows only ciphertext |
| 3 | WebAuthn + PRF reveal gating, passkey management | PRF bypass test passes |
| 4 | Security center, audit logs, export, key rotation, account deletion | Restore drill completed |
| 5 | Hardening, penetration testing, third-party audit, remediation | Audit report with no open high/critical findings |
| 6 | Private beta, then public launch, bug bounty | Beta feedback and monitoring clean for 30 days |
| 7 (v2) | Browser extension, mobile apps, autofill | Separate PRD |

## 18. Success metrics

- Zero plaintext secrets or metadata ever present in server storage or logs (continuously tested).
- Zero high/critical findings open at launch.
- Median unlock time under 1.5 seconds on a mid-range phone.
- Support tickets about lost access are handled by education (the Emergency Kit), never by weakening the model.

## 19. Known risks and honest limitations

1. **Web code delivery:** mitigated in section 9, fully solved only by the extension and native apps in v2.
2. **Solo operator:** you are a single point of failure. Mitigate with hardware keys, documented runbooks, an offsite encrypted backup of your own credentials, and a trusted person holding break-glass access in escrow.
3. **Render has fewer security primitives than AWS** (no managed KMS or HSM). We compensate by making the server hold nothing decryptable, so the value of its secrets is low. If you outgrow Render, migrate infrastructure without changing the crypto.
4. **Lost Secret Key and master password equals permanent data loss.** This is the price of true zero-knowledge, and the product must say so clearly.
5. **PRF support is not universal yet**, so some devices use the master-password fallback.

## 20. Decisions that are now closed

- Zero-knowledge, OPAQUE, Secret Key mandatory, 2FA mandatory
- Rust + Axum + Postgres on Render, with Cloudflare in front
- AES-256-GCM via WebCrypto, Argon2id, HKDF, per-item keys, AAD binding, encrypted metadata
- WebAuthn PRF for cryptographic biometric gating, master-password fallback
- Strict CSP, Trusted Types, SRI, no third-party scripts, reproducible builds
- Minimal dependencies, 14-day cooling period, CI scanning
- External audit before public launch; private beta first
