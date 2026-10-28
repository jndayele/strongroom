# Strongroom Threat Model (v1.0 Draft)

*Derived directly from [`/docs/PRD.md`](../docs/PRD.md) (Sections 1, 2, 4, 8, 9, 10, 11, and 19). Nothing in this document introduces assumptions or mechanisms outside the locked PRD.*

## 1. Security Promise and Scope

**Core promise:** *If we are hacked, subpoenaed, or acquired, your passwords stay unreadable.*

All encryption and decryption happen in the user's browser. The backend server stores only ciphertext and OPAQUE registration records, and never holds keys or secrets capable of decrypting, resetting, or recovering user vault data. Revealing any stored secret requires fresh proof of user presence through biometrics or a passkey enforced cryptographically via the WebAuthn PRF extension (with a master-password re-entry fallback where PRF is unsupported).

### 1.1 Security Goals (PRD Section 2)

1. **Zero-knowledge server:** The server never holds anything that can decrypt user data.
2. **Offline brute-force resistance after full server + DB compromise:** A database leak combined with a server-secret leak still cannot be brute-forced, even against weak master passwords, due to the client-only 128-bit random Secret Key.
3. **Cryptographic biometric/passkey gating:** Revealing secrets is gated by WebAuthn PRF output (or master-password re-entry fallback on unsupported hardware), not merely a UI toggle.
4. **Minimal attack surface:** Minimal dependency count, pinned versions, 14-day cooling period, and native browser WebCrypto for bulk encryption.
5. **Auditability:** Transparent, publishable security design that can be independently audited prior to public launch.

### 1.2 Explicit Non-Goals for v1 (PRD Section 2)

- Shared vaults, teams, or family plans
- Browser autofill and browser extension (planned for v2)
- File attachments
- SSO or social login (never: breaks the user-held key model)
- Server-side password recovery (never)
- Third-party analytics, ads, or trackers (never)

---

## 2. Trust Boundaries and Assets

### 2.1 Protected Assets

| Asset | Sensitivity | Where Held | Protection |
| --- | --- | --- | --- |
| Master Password | Critical | User memory; transiently in browser RAM during unlock/re-auth | Never sent to server; combined with Secret Key via HKDF into OPAQUE input |
| Secret Key (128-bit random) | Critical | User's Emergency Kit PDF; wrapped in browser IndexedDB under non-extractable device key | Never sent to server; provides 128 bits of entropy independent of password strength |
| OPAQUE Export Key & KEK | Critical | Browser RAM only | Derived client-side via OPAQUE + HKDF; never transmitted |
| Vault Metadata Key (`K_m`) | Critical | Browser RAM while unlocked (non-extractable `CryptoKey`); stored on server wrapped (AES-256-GCM) under KEK | Zeroed/dropped on auto-lock, logout, or tab close |
| Vault Secret Key (`K_s`) | Critical | Browser RAM for at most 30 seconds during secret reveal; stored wrapped under KEK and under each passkey's PRF-derived key | Unwrapped only upon fresh WebAuthn PRF assertion (or master-password fallback); wiped within 30 seconds |
| Per-Item Keys | High | Browser RAM during item read/write; stored wrapped under `K_m` (metadata) and `K_s` (secrets) | Unique random 256-bit key per item with fresh 96-bit GCM nonces |
| Vault Item Metadata & Secrets | High | Encrypted in PostgreSQL (`bytea` blobs padded to 256-byte buckets) | AES-256-GCM with AAD bound to `user_id \|\| item_id \|\| key_version \|\| schema_version` |
| Server OPAQUE Setup Secret & Token Signing Keys | Medium-High | Render environment secrets | Never committed to repository; documented rotation procedure; cannot decrypt user vaults |

### 2.2 Trust Boundaries

1. **User Device / Browser Execution Context:** Trusted to execute the client application, invoke WebCrypto and WebAuthn APIs, and display plaintext secrets during reveal windows.
2. **Cloudflare Edge (`app.<domain>`, `api.<domain>`):** Terminates public connections with TLS 1.3 only, enforces WAF managed rules, bot fight mode, DDoS protection, and `/auth/*` rate limits.
3. **Render Static Frontend (`app.<domain>`):** Serves static frontend bundle with strict CSP, Trusted Types, Subresource Integrity (SRI), and security headers.
4. **Render API Service (`api.<domain>`):** Runs a `#![forbid(unsafe_code)]` Rust/Axum binary in a distroless, non-root, read-only container. Treated as **untrusted for confidentiality of user secrets**.
5. **Render Managed PostgreSQL:** Private network access limited to the API service IP allowlist; encrypted at rest; stores only ciphertext, OPAQUE records, and hashed identifiers/tokens.

---

## 3. Adversary Profiles and Required Outcomes (PRD Section 4)

| Attacker | Capability | Required Outcome & Mitigations |
| --- | --- | --- |
| **Database thief** | Obtains a full copy of the PostgreSQL database (backups or SQL dump). | Sees only padded ciphertext blobs (`bytea`), OPAQUE records, and hashed tokens/IPs. Cannot brute-force user vaults because the 128-bit client-side Secret Key never touches the server (Section 5.1). |
| **Server compromiser** | Gains root/execution access on the API container and reads all server secrets and memory. | Cannot decrypt existing vaults because KEK, `K_m`, `K_s`, and Secret Keys never leave the browser. **Can** attempt to serve malicious JS if frontend delivery is also compromised; contained via Section 9 controls (strict CSP, SRI, reproducible builds, protected deploy pipeline). |
| **Network attacker** | Active MITM on a user's network connection. | Blocked by TLS 1.3 only, HSTS (2 years, `includeSubDomains`, `preload`), and OPAQUE (password never transits the wire). |
| **Credential stuffer** | Automated bulk login attempts using leaked credentials from other sites. | Blocked by Cloudflare edge rate limits, per-IP and per-account sliding windows, exponential backoff, temporary lockout after 10 failures, mandatory 2FA (WebAuthn or TOTP), and Secret Key requirement on new devices. |
| **XSS attacker** | Attempts to inject and execute arbitrary JavaScript in the web client. | Contained by strict CSP (`default-src 'none'; script-src 'self'; require-trusted-types-for 'script'`), Trusted Types enforcement, ESLint bans on `dangerouslySetInnerHTML`/`innerHTML`/`eval`, non-extractable `CryptoKey` objects, and keeping `K_s` wrapped until reveal. |
| **Malicious dependency** | Compromises an upstream npm package or Rust crate. | Contained by strict dependency budget, only one crypto-adjacent npm dependency (`@serenity-kit/opaque`), native WebCrypto for bulk crypto, exact version pinning, committed lockfiles, 14-day cooling period, `npm ci --ignore-scripts`, `cargo deny`, `cargo audit`, `cargo vet`, and OSV-Scanner in CI. |
| **Stolen unlocked device** | Physical access to a user's unattended unlocked device. | Mitigated by auto-lock after 5 minutes idle (configurable down to 1 minute, never off), lock on tab close/logout, 15-second auto-hide on revealed passwords, 30-second clipboard auto-clear, and requiring a fresh biometric/passkey check for every secret reveal. |
| **Malware on user's device** | Local keylogger, memory scraper, or screen capture on the endpoint OS. | **Explicitly out of scope** (documented openly to users per PRD Section 4). |
| **Nation-state / legal coercion** | Subpoena or legal demand served to the operator for user vault contents. | Operator holds nothing readable; only encrypted blobs, hashed metadata, and encrypted alert emails exist on the server. |
| **Insider (founder or future hire)** | Full administrative access to production infrastructure. | Same technical ceiling as the server compromiser (cannot decrypt vaults), reinforced by hardware security keys on all critical accounts, protected `main` branch, signed commits, CI-only deployments, and append-only audit logs. |

---

## 4. Web-Delivery Risk and Layered Containment (PRD Section 9)

Because a web application serves its encryption code on demand, a compromised hosting provider or build pipeline could attempt to serve modified JavaScript. Strongroom acknowledges this limitation openly and applies eight layers of containment:

1. **Strict Content-Security-Policy:** `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://api.<domain>; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'`. No `unsafe-inline` or `unsafe-eval`.
2. **Trusted Types & DOM Sink Bans:** Trusted Types enforced in CSP; `dangerouslySetInnerHTML`, `innerHTML`, and `eval` banned via ESLint.
3. **Subresource Integrity (SRI) & Self-Hosting:** SRI hashes on every script and stylesheet; all assets and fonts self-hosted (zero third-party scripts or fonts).
4. **Hardened HTTP Headers:** HSTS (`max-age=63072000; includeSubDomains; preload`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and `Cache-Control: no-store`.
5. **Deployment Pipeline Security:** Protected `main` branch, signed commits, deployments triggered only from CI after all security gates pass, hardware security keys (FIDO2) on GitHub, Render, Cloudflare, and the domain registrar, and no long-lived deploy tokens.
6. **Reproducible Builds:** Release build hashes published in git tags and on a public transparency page so independent researchers can verify served assets against source.
7. **Domain Hardening:** Registrar lock, DNSSEC, CAA records restricted to the chosen CA, and HSTS preload registration.
8. **v2 Roadmap:** Browser extension and native mobile applications that package code independently of server delivery.

---

## 5. Known Risks and Honest Limitations (PRD Section 19)

1. **Web code delivery:** Mitigated by Section 9 controls in v1; eliminated only by packaged browser extension / native apps in v2.
2. **Solo operator risk:** Single point of operational failure; mitigated via hardware FIDO2 keys, documented runbooks, offsite encrypted credential backup, and break-glass escrow with a trusted person.
3. **Render platform primitives:** Render lacks AWS-style managed HSM/KMS; compensated by ensuring server secrets never protect decryptable user vault data.
4. **Permanent data loss if both credentials and devices are lost:** Losing the Master Password and the Emergency Kit (Secret Key) with no signed-in device results in permanent, unrecoverable data loss by design.
5. **Incomplete WebAuthn PRF hardware support:** Devices/browsers without PRF support fall back to master-password re-entry at reveal time with an explicit UI notice.
