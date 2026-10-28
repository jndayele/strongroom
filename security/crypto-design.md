# Strongroom Cryptographic Design (v1.0 Draft)

*Derived directly from [`/docs/PRD.md`](../docs/PRD.md) (Sections 3, 5, 6, 7, 8, 12, 13, and 14). No custom cryptography is invented; all primitives and flows follow the locked PRD.*

## 1. Cryptographic Primitives and Libraries (PRD Section 3)

| Function | Algorithm / Standard | Implementation | Rationale |
| --- | --- | --- | --- |
| Password-Authenticated Key Exchange | **OPAQUE** (RFC 9807) | `@serenity-kit/opaque` (client WASM) & `opaque-ke` (Rust server) | Password never leaves the browser; immune to offline pre-computation attacks; shared underlying `opaque-ke` core prevents cross-implementation protocol bugs |
| Password Hardening (inside OPAQUE) | **Argon2id** | Configured inside OPAQUE (`m >= 64 MiB`, `t >= 3`, `p = 1` minimum floor) | OWASP-aligned memory-hard KDF; tuned upward after benchmarking on low-end phones |
| Key Derivation & Separation | **HKDF-SHA-256** | Browser native **WebCrypto API** | Domain-separated key derivation without external JS crypto libraries |
| Symmetric Authenticated Encryption & Key Wrapping | **AES-256-GCM** | Browser native **WebCrypto API** | Hardware-accelerated, zero npm dependency surface, supports non-extractable `CryptoKey` objects |
| Biometric / Passkey Key Gating | **WebAuthn + PRF extension** | Browser `navigator.credentials` + `webauthn-rs` (server verification) | Cryptographically binds secret decryption (`K_s`) to an authenticator user-verification check |
| Cryptographic Randomness | CSPRNG | Browser `crypto.getRandomValues` (client) / OS CSPRNG (server) | `Math.random` is strictly forbidden |

---

## 2. User-Held Secrets (PRD Section 5.1)

1. **Master Password:**
   - Chosen by the user at signup; minimum **12 characters**.
   - Validated client-side using a `zxcvbn` strength meter (blocking weak passwords) and checked against breached passwords via the Have I Been Pwned (HIBP) k-anonymity range API (only a 5-character SHA-1 hash prefix leaves the browser).
2. **Secret Key:**
   - **128 random bits** generated in the browser via `crypto.getRandomValues` at signup, formatted as `A3-XXXXXX-XXXXXX-XXXXX`.
   - Displayed once in a client-side generated downloadable **Emergency Kit** PDF. Signup requires the user to confirm saving the Emergency Kit (by typing the last 4 characters of the Secret Key) before proceeding.
   - Persisted on a signed-in device in IndexedDB **only wrapped under a non-extractable WebCrypto device key**.
   - Required to sign in on any new device.
   - **Security property:** Because the 128-bit Secret Key never touches the server, an adversary who steals both the PostgreSQL database and the server's OPAQUE setup key still faces a $2^{128}$ search space regardless of master password strength.

---

## 3. Key Hierarchy and Wrapping Architecture (PRD Section 5.2)

```
Master Password + Secret Key (128-bit)
        │
        ▼  HKDF-SHA-256
    pw_input  ──────────► OPAQUE Registration / Login (Argon2id: >=64 MiB, t>=3, p=1)
                                │
                                ▼
                        OPAQUE export_key (client-only)
                                │
                                ▼  HKDF-SHA-256(export_key, secret_key, "vault-kek-v1")
                               KEK (never leaves browser)
                              ╱   ╲
         AES-256-GCM wrap   ╱       ╲   AES-256-GCM wrap
                          ▼           ▼
              Vault Metadata Key     Vault Secret Key (K_s, 256-bit) ◄── Also wrapped under each
                 (K_m, 256-bit)               │                          passkey's PRF-derived key
                      │                       │
         AES-256-GCM  │                       │  AES-256-GCM
            wrap      ▼                       ▼     wrap
              Item Metadata Key       Item Secret Key
                 (256-bit/item)        (256-bit/item)
                      │                       │
                      ▼                       ▼
              Encrypted Metadata      Encrypted Secret
              (title, URL, user,      (password, TOTP seed,
                    notes)               recovery codes)
```

### Step-by-Step Derivation & Storage Rules

1. **OPAQUE Input (`pw_input`):**
   - `pw_input = HKDF(master_password || Secret Key)`
   - Used as the client input to OPAQUE registration and login.
2. **OPAQUE Export Key:**
   - Produced by the OPAQUE protocol exclusively on the client; the server never learns `export_key`.
3. **Key Encryption Key (`KEK`):**
   - `KEK = HKDF-SHA-256(ikm = export_key, salt = secret_key, info = "vault-kek-v1")`
   - Lives only in browser memory and never leaves the browser.
4. **Vault Keys (`K_m` and `K_s`):**
   - **Vault Metadata Key (`K_m`):** 256-bit random key generated at signup. Stored on the server only wrapped (`AES-256-GCM`) under `KEK` (`wrapped_km`). Held in memory as a non-extractable `CryptoKey` while the vault is unlocked so the user can browse and search item metadata client-side.
   - **Vault Secret Key (`K_s`):** 256-bit random key generated at signup. Stored on the server wrapped (`AES-256-GCM`) under `KEK` (`wrapped_ks_master`), and additionally wrapped under each registered passkey's PRF-derived wrapping key (`wrapped_ks_prf`). Held in memory **only for seconds** (at most 30 seconds) at the moment a secret is revealed.
5. **Per-Item Keys:**
   - Every vault item generates fresh random 256-bit item keys for its metadata and secret payloads:
     - `wrapped_item_key_m`: item metadata key wrapped with `K_m`.
     - `wrapped_item_key_s`: item secret key wrapped with `K_s`.

---

## 4. Item Encryption, AAD Binding, and Padding (PRD Section 5.3)

- **Cipher & Nonce:** `AES-256-GCM` with a fresh random **96-bit nonce** from `crypto.getRandomValues` for every encryption operation, paired with a fresh random 256-bit per-item key (eliminating nonce-reuse risk).
- **Authenticated Associated Data (AAD):** Every item ciphertext and wrapped key binds AAD to:
  `user_id || item_id || key_version || schema_version`
  This prevents the server or an attacker with database write access from swapping ciphertext between users or items, replaying old versions, or rolling back schema/key versions undetected.
- **Encrypted Metadata & Size Padding:** Item titles, URLs, usernames, notes, device names, and passkey names are all encrypted client-side. Ciphertext blobs (`meta_blob`, `secret_blob`) are padded to **256-byte buckets** (`padded_size`) so ciphertext length does not leak exact password or metadata lengths. All vault search happens client-side.
- **Versioned Envelope Format:** Every encrypted blob stored in PostgreSQL (`bytea`) uses an explicit versioned binary envelope header so cryptographic algorithms or parameters can be migrated cleanly in future versions.

---

## 5. Biometric / Passkey Gating with WebAuthn PRF (PRD Section 6)

1. **Passkey Registration:**
   - Users register one or more platform (Windows Hello, Touch ID, Face ID, Android biometrics) or roaming (YubiKey) authenticators with `userVerification: "required"` and the WebAuthn **PRF extension** enabled.
   - From the authenticator's PRF output, the browser derives a wrapping key via WebCrypto and wraps `K_s` (`wrapped_ks_prf`). The raw PRF output never leaves the browser.
2. **Secret Reveal Flow:**
   - When the user clicks **Reveal** on an item secret, the browser requests a WebAuthn assertion with the PRF extension.
   - Local biometric/PIN verification releases the PRF output to the browser.
   - The browser derives the PRF wrapping key, unwraps `K_s`, unwraps the item's secret key (`wrapped_item_key_s`), decrypts `secret_blob` (verifying AAD), displays the secret for at most **15 seconds**, and wipes `K_s` from memory within at most **30 seconds**.
3. **Fallback When PRF Is Unsupported:**
   - On devices/browsers lacking WebAuthn PRF support, revealing a secret requires re-entering the Master Password (combined with the device's stored Secret Key) to re-derive `KEK` and unwrap `wrapped_ks_master`.
   - The UI explicitly informs the user that hardware biometric gating is unavailable on the current device and why.
4. **Server-Side WebAuthn Verification:**
   - Challenge freshness window of **60 seconds**; strict server verification of `origin`, `rpId`, signature counter (`sign_count`), and challenge via `webauthn-rs`.

---

## 6. Key Rotation, Password Change, and Recovery (PRD Sections 5.4, 5.5)

- **Master Password Change:** Re-runs OPAQUE registration and re-wraps `K_m` and `K_s` (`wrapped_km`, `wrapped_ks_master`) under the new `KEK`. Existing item ciphertexts (`meta_blob`, `secret_blob`) do not need to be re-encrypted.
- **Full Vault Key Rotation ("Rotate vault keys"):** After suspected compromise, generates new `K_m` and `K_s` (incrementing `key_version`), re-wraps them, and re-encrypts all item keys/items client-side in a resumable background job.
- **Recovery Model:**
  - **Zero server-side recovery:** If a user loses both their Master Password and Emergency Kit (Secret Key) and has no signed-in device, the vault cannot be decrypted by anyone.
  - **Signed-in device recovery:** A user who forgets only their Master Password while still authenticated on an existing device can set a new Master Password from that device.

---

## 7. Client Memory Hygiene and Session Binding (PRD Sections 7, 8)

- **Non-Extractable Keys:** All keys live in browser RAM only, represented as non-extractable `CryptoKey` objects wherever WebCrypto permits. Keys are never written to `localStorage`, `sessionStorage`, cookies, or URL parameters.
- **Auto-Lock:** Triggers after **5 minutes** of inactivity (user-configurable down to 1 minute, never disabled), on explicit logout, and on tab close. Locking zeroes mutable buffers and drops all in-memory key references.
- **Clipboard Hygiene:** Copied secrets are cleared from the clipboard after **30 seconds** (best-effort in browsers, with a clear UI notice).
- **Password Generator:** Uses `crypto.getRandomValues` with rejection sampling to eliminate modulo bias.
- **Authentication & Anti-Enumeration:** OPAQUE login responses for unknown email addresses return indistinguishable fake responses and uniform timing to prevent account enumeration.

---

## 8. Cryptographic Verification Requirements (PRD Sections 13, 14)

1. **Known-Answer & Property Tests:** Unit tests against official RFC/NIST test vectors and property-based round-trip/tampering tests for versioned envelope encoding/decoding and AAD mismatches.
2. **Server Decryption-Impossibility Test (F1 Exit Gate):** Automated test proving that an attacker holding the complete database record and server secrets cannot decrypt `wrapped_km`, `wrapped_ks_master`, `meta_blob`, or `secret_blob`.
3. **PRF Bypass Test (F4 Exit Gate):** Automated test proving that a modified UI skipping the WebAuthn prompt cannot decrypt `secret_blob` because `K_s` is absent from memory without PRF output.
