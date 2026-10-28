# Strongroom Incident Response Runbook (v1.0 Draft)

*Derived directly from [`/docs/PRD.md`](../docs/PRD.md) (Sections 7, 10, 14, 15, and 19). Nothing in this runbook invents procedures or capabilities outside the PRD.*

## 1. Purpose and Guiding Principles

Strongroom is designed so that a server or database compromise never exposes plaintext user vault secrets or metadata. However, security incidents can still threaten active sessions, code delivery integrity, service availability, or account metadata (hashed IPs, encrypted alert emails, audit events).

This runbook defines:
- Incident severity levels
- Immediate containment controls ("Kill Switch")
- Key and secret rotation procedures
- Mass session and token revocation
- 72-hour user and regulatory notification requirements
- Solo-operator continuity and annual drill cadence

---

## 2. Severity Levels (PRD Section 15)

| Severity | Definition | Examples | Target Response |
| --- | --- | --- | --- |
| **SEV-1 (Critical)** | Confirmed or suspected compromise of production infrastructure, build/deploy pipeline, frontend bundle integrity, database, or server secrets; or any flaw in client cryptography/PRF gating. | Unauthorized commit/deploy; tampered JS bundle detected against reproducible build hash; database dump exfiltrated; Render secret exposure; critical finding in `opaque-ke` / `@serenity-kit/opaque`. | Immediate containment (< 15 minutes); freeze deployments; assess kill-switch activation; user notification within 72 hours if breach confirmed. |
| **SEV-2 (High)** | Active attack or vulnerability affecting authentication, session management, rate limiting, or access controls without confirmed data exfiltration or code tampering. | Credential stuffing spike bypassing edge rules; refresh-token reuse anomaly surge; high-severity CVE in direct runtime dependency (`axum`, `tokio`, `react`). | Triage within 1 hour; deploy mitigation or WAF rule; rotate affected secrets if needed. |
| **SEV-3 (Medium)** | Non-exploited security control degradation, CI scanner failure, or staging-only security issue. | Audit log shipping interruption; failed backup restore test; moderate dependency advisory in build-only tooling. | Remediate before next release; verify in staging. |

---

## 3. Kill Switch Controls (PRD Section 15)

Strongroom maintains two immediate emergency kill switches:

1. **Deployment Freeze:**
   - Disable automatic/CI deployments on Render for both the static site (`app.<domain>`) and API service (`api.<domain>`).
   - Lock the `main` branch on GitHub to prevent merges until forensics and verification are complete.
   - If frontend code-delivery tampering is suspected, use Cloudflare to place `app.<domain>` into maintenance/block mode immediately so browsers do not fetch untrusted assets.
2. **Global Session Force-Logout (Mass Token Revocation):**
   - Revoke all active rows in the `sessions` table (`UPDATE sessions SET revoked_at = NOW() WHERE revoked_at IS NULL`) **and** rotate the server access-token/cookie signing secret in Render.
   - Because access tokens have a maximum lifetime of **10 minutes** (`__Host-` cookie) and refresh tokens are checked against `sessions.refresh_hash` on every rotation, rotating the signing key plus revoking `sessions` terminates all active sessions immediately across all devices.

---

## 4. Secret and Key Rotation Procedures (PRD Sections 5.4, 7, 10, 15)

### 4.1 Server Cookie / Access-Token Signing Key Rotation
1. Generate a fresh cryptographic signing secret out-of-band using OS CSPRNG.
2. Update the secret in Render environment variables for the API service.
3. Restart the API service container.
4. All previously issued 10-minute access cookies are immediately invalidated.

### 4.2 Refresh Token Mass Revocation
1. Connect to Render PostgreSQL using the administrative/migration role over the private network.
2. Mark all active session families revoked (`revoked_at = NOW()`).
3. Record an `audit_events` entry documenting the administrative mass revocation.
4. All clients are forced to complete full OPAQUE login + 2FA on their next request.

### 4.3 Server TOTP Encryption Key & Alert Email Key Rotation
1. Provision the new server encryption key alongside the previous key version in Render secrets.
2. Run a migration job to re-encrypt `totp.secret_enc` and `users.email_enc` under the new key.
3. Remove the retired server key from Render secrets and verify via test that old key material is purged.

### 4.4 OPAQUE Server Setup Secret Rotation
1. If the server's OPAQUE setup secret is suspected of exposure:
   - Note that user vaults remain protected by the 128-bit client-side Secret Key and cannot be brute-forced offline (PRD Section 5.1).
   - Provision a new OPAQUE server setup secret version and require users to re-register their OPAQUE record on next authenticated password change / key rotation flow.

### 4.5 User-Initiated Vault Key Rotation (PRD Section 5.4)
- If a user suspects compromise of their own account or device, direct them to use **"Rotate vault keys"** in the Security Center, which generates fresh `K_m` and `K_s` keys and re-encrypts all vault items client-side in a resumable background job, and to revoke untrusted devices and passkeys.

---

## 5. Incident Response Phases

### Phase 1: Detection & Triage
- Monitor alerts on anomaly spikes, elevated 4xx/5xx error rates, failed-login bursts, and refresh-token reuse detections (PRD Sections 7, 10).
- Verify whether the alert indicates:
  - Credential stuffing / brute-force attempt
  - Refresh token replay (which automatically revokes the session family)
  - Infrastructure, dependency, or build-pipeline compromise

### Phase 2: Containment
- Execute the **Kill Switch** (Section 3) if production integrity or secret confidentiality is in doubt.
- Isolate affected services and preserve append-only external audit logs (`audit_events` and external log sink) and container image digests for forensic inspection.

### Phase 3: Eradication & Verification
- Compare the served frontend bundle hash against the published reproducible build hash in git tags (PRD Section 9.6).
- Rebuild container images and static assets from a clean, signed git commit through CI after all scanners (`gitleaks`, `osv-scanner`, `cargo audit`, `cargo deny`, `clippy`, `eslint`, `tsc`) pass.
- Rotate all potentially affected infrastructure credentials (GitHub, Render, Cloudflare, PostgreSQL roles) using hardware FIDO2 keys.

### Phase 4: User & Regulatory Notification (Within 72 Hours — PRD Sections 15, 16)
- Within **72 hours** of confirming a breach, notify affected users via email and a public security advisory.
- Notification must state in plain, honest language:
  - **What was exposed:** e.g., encrypted blobs (`bytea`), hashed IPs, session timestamps, or encrypted email records.
  - **What was NOT exposed:** master passwords, Secret Keys, `K_m`, `K_s`, and plaintext vault items/metadata (explaining how the zero-knowledge architecture and 128-bit Secret Key protect their data).
  - **Required user actions:** e.g., verify Emergency Kit possession, sign back in, review Security Center device/passkey list, or rotate vault keys if client code integrity was affected.
- Comply with applicable data-protection notification obligations, including Ghana's Data Protection Act, 2012 (Act 843) and GDPR-level breach reporting standards (PRD Section 16).

---

## 6. Continuity, Backups, and Drills (PRD Sections 10, 14, 19)

1. **Quarterly Backup Restore Drill (PRD Section 10):**
   - Every quarter, restore a Render PostgreSQL point-in-time backup into an isolated staging environment and verify schema integrity, ciphertext envelope readability, and zero production cross-talk.
2. **Annual Incident & Restore Drill (PRD Section 14):**
   - Once per year, simulate a SEV-1 incident end-to-end: trigger the session kill switch, rotate server secrets, verify reproducible build hashes, and test break-glass procedures.
3. **Solo-Operator Break-Glass Escrow (PRD Section 19.2):**
   - Maintain hardware FIDO2 security keys (primary + backup stored offsite), an offline encrypted backup of operator credentials, and a documented break-glass escrow package held by a designated trusted person.
