# Strongroom Cryptographic Design (v1.0 Draft)

*Derived directly from [`/docs/PRD.md`](../docs/PRD.md) (Sections 3, 5, 6, 7, 8, 12, 13, and 14). No custom cryptography is invented; all primitives and flows follow the locked PRD.*

## 1. Cryptographic Primitives and Libraries (PRD Section 3)

| Function | Algorithm / Standard | Implementation | Rationale |
| --- | --- | --- | --- |
| Password-Authenticated Key Exchange | **OPAQUE** (RFC 9807) | `@serenity-kit/opaque` (client WASM) & `opaque-ke` (Rust server) | Password never leaves the browser; immune to offline pre-computation attacks; shared underlying `opaque-ke` core prevents cross-implementation protocol bugs |
| Password Hardening (inside OPAQUE) | **Argon2id** | Configured inside OPAQUE (`m >= 64 MiB`, `t >= 3`, `p = 1` minimum floor) | OWASP-aligned memory-hard KDF; tuned upward after benchmarking on low-end phones |
| Key Derivation & Separation | **HKDF-SHA-256** | Browser native **WebCrypto API** | Domain-separated key derivation without external JS crypto libraries |
| Symmetric Authenticated Encryption & Key Wrapping | **AES-256-GCM** | Browser native **WebCrypto API** | Hardware-accelerated AEAD (CTR + GHASH), zero npm dependency surface, supports non-extractable `CryptoKey` objects |
| Biometric / Passkey Key Gating | **WebAuthn + PRF extension** | Browser `navigator.credentials` + `webauthn-rs` (server verification) | Cryptographically binds secret decryption (`K_s`) to an authenticator user-verification check |
| Cryptographic Randomness | CSPRNG | Browser `crypto.getRandomValues` (client) / OS CSPRNG (server) | `Math.random` is strictly forbidden |

---

## 2. User-Held Secrets and Secret Key Format (PRD Section 5.1)

1. **Master Password:**
   - Chosen by the user at signup; minimum **12 characters**.
   - **Planned:** Client-side validation using a `zxcvbn` strength meter (blocking weak passwords) and breach checking via the Have I Been Pwned (HIBP) k-anonymity range API (only a 5-character SHA-1 hash prefix leaves the browser).
2. **Secret Key:**
   - **128 random bits (16 bytes)** generated in the browser via `crypto.getRandomValues` at signup.
   - **Planned:** Displayed once in a client-side generated downloadable **Emergency Kit** PDF; signup requires the user to confirm saving the Emergency Kit (by typing the last 4 characters of the Secret Key) before proceeding.
   - **Planned:** Persisted on a signed-in device in IndexedDB **only wrapped under a non-extractable WebCrypto device key**.
   - Required to sign in on any new device.
   - **HKDF input rule:** Only the **16 decoded raw bytes** returned by `parseSecretKey()` (never the formatted display string) are fed into HKDF key derivation (`derivePasswordInput` and `deriveKek`).
   - **Security property:** Because the 128-bit Secret Key never touches the server, an adversary who steals both the PostgreSQL database and the server's OPAQUE setup key still faces a $2^{128}$ search space regardless of master password strength.

### 2.1 Secret Key Exact Bit and Character Layout

- **Display format:** `A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX`
  - Version prefix: `A3`
  - Payload: **27 uppercase RFC 4648 Base32 characters** (`A–Z`, `2–7`, 5 bits per character), grouped **`6-6-5-5-5`** (`6 + 6 + 5 + 5 + 5 = 27` characters).
  - Total encoded payload bits: $27 \times 5 = 135\text{ bits}$.

```text
Bit Offset   Width      Content
-----------  ---------  --------------------------------------------------------
0 .. 127     128 bits   Raw Secret Key (16 CSPRNG bytes, MSB-first)
128 .. 134     7 bits   CRC-7 checksum over the 128-bit key (polynomial G(x) = x^7 + x^3 + 1, 7-bit feedback tap mask 0x09 / full polynomial 0x89, pre-seeded with 0x5A)
```

- **Checksum properties:** Because each Base32 character spans 5 consecutive bits and $G(x) = x^7 + x^3 + 1$ (7-bit tap mask `0x09`, full polynomial `0x89`, initial seed `0x5A`) is primitive and irreducible of degree 7 over $\text{GF}(2)$, any single-character substitution error ($27\text{ positions} \times 31\text{ alternatives} = 837\text{ mutations}$) produces a 5-bit burst error $E(x) = x^k B(x)$ with $\deg(B) \le 4 < 7$ that is never divisible by $G(x)$ (100% single-character typo detection), and 100% of two-character transpositions at any distance are detected because $G(x)$ has primitive period $2^7 - 1 = 127$ and $\gcd(5, 127) = 1$.
- **Parser normalization:** `parseSecretKey` rejects any input longer than 128 characters before running any regex, requires the contiguous `A3` version prefix before stripping separators, strips hyphens and whitespace from the payload, normalizes lowercase input to uppercase, enforces the exact 27-character Base32 payload length, verifies the CRC-7 checksum, and returns the 16-byte `Uint8Array`.

---

## 3. Key Hierarchy and Wrapping Architecture (PRD Section 5.2)

```
Master Password (NFKC UTF-8) + Secret Key (16 raw bytes = 128 bits)
        │
        ▼  HKDF-SHA-256(ikm = UTF8(NFKC(master_password)), salt = secret_key_raw_16B, info = "strongroom-pw-input-v1", 32B)
    pw_input  ──────────► OPAQUE Registration / Login (Argon2id: >=64 MiB, t>=3, p=1) [Planned]
                                │
                                ▼
                        OPAQUE export_key (client-only)
                                │
                                ▼  HKDF-SHA-256(export_key, secret_key_raw_16B, "vault-kek-v1")
                               KEK (non-extractable CryptoKey, usages: ['wrapKey', 'unwrapKey'])
                              ╱   ╲
         AES-256-GCM wrap   ╱       ╲   AES-256-GCM wrap
     (purpose: vault-key-km)▼         ▼ (purpose: vault-key-ks-master)
              Vault Metadata Key     Vault Secret Key (K_s, 256-bit) ◄── Also wrapped under each
                 (K_m, 256-bit,      (usages: ['wrapKey', 'unwrapKey'])  passkey's PRF-derived key
      usages: ['wrapKey', 'unwrapKey'])       │                          (purpose: vault-key-ks-prf)
                      │                       │
         AES-256-GCM  │                       │  AES-256-GCM
            wrap      ▼                       ▼     wrap
              Item Metadata Key       Item Secret Key
                 (256-bit/item,          (256-bit/item,
       usages: ['encrypt', 'decrypt']) usages: ['encrypt', 'decrypt'])
                      │                       │
                      ▼                       ▼
              Encrypted Metadata      Encrypted Secret
              (title, URL, user,      (password, TOTP seed,
                    notes)               recovery codes)
```

### Step-by-Step Derivation & Storage Rules

1. **OPAQUE Input (`pw_input`):**
   - `pw_input = HKDF-SHA-256(ikm = NFKC-normalized UTF-8 master password, salt = the 16 raw Secret Key bytes, info = "strongroom-pw-input-v1", 32 bytes)` (implemented via `derivePasswordInput`).
   - Used as the client input to OPAQUE registration and login (**Planned:** `@serenity-kit/opaque` integration).
2. **OPAQUE Export Key:**
   - Produced by the OPAQUE protocol exclusively on the client (**Planned**); the server never learns `export_key`.
3. **Key Encryption Key (`KEK`):**
   - `KEK = HKDF-SHA-256(ikm = export_key, salt = secret_key_raw_16B, info = "vault-kek-v1")` (implemented via `deriveKek`).
   - Derived directly into a non-extractable `AES-GCM` 256-bit `CryptoKey` with usages strictly `['wrapKey', 'unwrapKey']`; lives only in browser memory and never leaves the browser.
4. **Vault Keys (`K_m` and `K_s`):**
   - **Vault Metadata Key (`K_m`):** 256-bit random key generated at signup with usages `['wrapKey', 'unwrapKey']`. Stored on the server only wrapped (`AES-256-GCM`, `purpose = "vault-key-km"`) under `KEK` (`wrapped_km`). Held in memory as a non-extractable `CryptoKey` while the vault is unlocked so the user can browse and search item metadata client-side.
   - **Vault Secret Key (`K_s`):** 256-bit random key generated at signup with usages `['wrapKey', 'unwrapKey']`. Stored on the server wrapped (`AES-256-GCM`, `purpose = "vault-key-ks-master"`) under `KEK` (`wrapped_ks_master`), and additionally wrapped under each registered passkey's PRF-derived wrapping key (`wrapped_ks_prf`, `purpose = "vault-key-ks-prf"` binding `credential_id`). Held in memory **only for seconds** (at most 30 seconds) at the moment a secret is revealed.
5. **Per-Item Keys:**
   - Every vault item generates fresh random 256-bit item keys for its metadata and secret payloads with usages strictly `['encrypt', 'decrypt']`:
     - `wrapped_item_key_m`: item metadata key wrapped with `K_m` (`purpose = "item-key-m"`).
     - `wrapped_item_key_s`: item secret key wrapped with `K_s` (`purpose = "item-key-s"`).
6. **Strict Usage Separation & Nonce-Reuse Bounds:**
   - Wrapping keys (`KEK`, `K_m`, `K_s`, and PRF wrapping keys) receive **only** `['wrapKey', 'unwrapKey']` usages; leaf data keys (item keys) receive **only** `['encrypt', 'decrypt']` usages. Any attempt to mix the two usage groups throws `CryptoArgumentError`. This prevents calling `subtle.decrypt` with a wrapping key to extract raw wrapped key bytes.
   - Item data (`meta_blob`, `secret_blob`) uses a fresh per-item key and random 96-bit nonce per encryption. Wrapping keys (`KEK`, `K_m`, `K_s`, PRF wrapping keys) use random 96-bit nonces (`crypto.getRandomValues`) and encrypt very few messages per user, remaining far below the NIST SP 800-38D birthday-bound limit of $2^{32}$ invocations per key.

---

## 4. Exact Binary Layouts: Envelope, Padding, and AAD (PRD Section 5.3)

### 4.1 Versioned Binary Envelope Layout

Every encrypted blob (`meta_blob`, `secret_blob`) and wrapped key (`wrapped_km`, `wrapped_ks_master`, `wrapped_ks_prf`, `wrapped_item_key_m`, `wrapped_item_key_s`) uses the following binary envelope:

```text
Byte Offset   Length       Field
------------  -----------  -----------------------------------------------------
0             1 byte       version (0x01 for v1 AES-256-GCM envelope)
1 .. 12       12 bytes     nonce (96-bit fresh CSPRNG IV from crypto.getRandomValues)
13 .. 13+N-1  N bytes      AES-256-GCM ciphertext body
13+N .. 28+N  16 bytes     AES-256-GCM 128-bit authentication tag (appended by WebCrypto)
```

- **Fixed envelope overhead:** $1 + 12 + 16 = 29\text{ bytes}$.
- **Wrapped 256-bit key envelope size:** $1 + 12 + 32 + 16 = 61\text{ bytes}$.
- **Encrypted item blob envelope size:** Exact multiple of $256\text{ bytes}$ ($256k\text{ bytes}$, where $N = 256k - 29$).

### 4.2 256-Byte Bucket Padding Layout (Pad-then-AEAD-Encrypt)

Before AES-256-GCM AEAD encryption, item plaintexts (`metadata` and `secret`, up to a maximum plaintext size of **1 MiB = 1,048,576 bytes**) are padded so that the final versioned envelope is an exact multiple of **256 bytes** (`PADDING_BUCKET_BYTES = 256`):

```text
Byte Offset     Length                Field
--------------  --------------------  ------------------------------------------
0 .. 3          4 bytes (uint32 BE)   plaintext_len (L, 0 <= L <= 1,048,576)
4 .. 4+L-1      L bytes               plaintext payload
4+L .. 4+L+P-1  P bytes               0x00 zero padding (0 <= P <= 255)
```

- **Bucket sizing formula:** With envelope overhead $O = 29\text{ bytes}$ (or $O = 0$ for standalone padding), bucket count is $k = \max\left(1, \left\lceil \frac{4 + L + O}{256} \right\rceil\right)$, total padded plaintext length is $4 + L + P = 256k - O$, and padding length is $P = (256k - O) - (4 + L) \in [0, 255]$.
- **AEAD integrity & unpadding validation:** Padding is inside the plaintext passed to AES-256-GCM, so both the 4-byte length header and all $P$ zero-padding bytes are authenticated by the 128-bit GCM tag. **Padding is validated only after AES-256-GCM authentication succeeds.** During unpadding, `unpadFromBucket` verifies that the buffer does not exceed the 1 MiB padded ceiling, `plaintext_len <= 1,048,576`, `plaintext_len <= padded.byteLength - 4`, `P < 256` (minimal bucket count), and all $P$ padding bytes equal `0x00`, throwing the uniform `DecryptionError` on any violation.

### 4.3 Canonical Length-Prefixed AAD Layout

Every encryption, decryption, key-wrapping, key-unwrapping, and key-rewrapping call requires structured `AadParams`; raw `Uint8Array` AAD inputs are rejected by the type system and at runtime. Only `encodeAad` produces AAD bytes, using big-endian `uint32` length prefixes on variable-length fields (`1 .. 256` bytes, checked before encoding) followed by fixed-width `uint32` version and revision numbers:

```text
Byte Offset  Length               Field
-----------  -------------------  ----------------------------------------------
0 .. 3       4 bytes (uint32 BE)  purpose_len (byte length of ASCII purpose label)
4 .. 4+P-1   P bytes              purpose ("item-meta" | "item-secret" | "item-key-m" | "item-key-s" | "vault-key-km" | "vault-key-ks-master" | "vault-key-ks-prf")
...          4 bytes (uint32 BE)  user_id_len (byte length of user_id, 1 .. 256)
...          U bytes              user_id (UTF-8 or raw identifier bytes)
...          4 bytes (uint32 BE)  target_id_len (byte length of item_id / key_id / credential_id, 1 .. 256)
...          I bytes              target_id (item_id for item-*, key_id for vault-key-km/ks-master, passkey credential_id for vault-key-ks-prf)
...          4 bytes (uint32 BE)  key_version (1 .. 0xFFFFFFFF)
...          4 bytes (uint32 BE)  schema_version (1 .. 0xFFFFFFFF)
...          4 bytes (uint32 BE)  revision (1 .. 0xFFFFFFFF for item purposes; 0 .. 0xFFFFFFFF for vault-key-* purposes)
```

- **Domain separation:** Binding `purpose` prevents swapping `meta_blob` with `secret_blob`, swapping `wrapped_item_key_m` with `wrapped_item_key_s`, swapping `wrapped_km` (`vault-key-km`) with `wrapped_ks_master` (`vault-key-ks-master`), or substituting a master-wrapped `K_s` for a passkey PRF-wrapped `K_s` (`vault-key-ks-prf` bound to `credential_id`).
- **Per-item revision binding & whole-item rollback limitation:** Including `revision` in item AADs guarantees that an older revision's ciphertext or wrapped item key fails to decrypt when verified against a newer revision's AAD. However, **the vault does not yet detect server rollback of whole items** (e.g., a compromised server serving both a stale item blob and its matching older `revision` number, or omitting newly created/deleted items altogether), because there is no signed vault-wide state root or manifest in Phase 1.

---

## 5. Biometric / Passkey Gating with WebAuthn PRF (PRD Section 6 — *Planned*)

1. **Passkey Registration (*Planned*):**
   - Users register one or more platform (Windows Hello, Touch ID, Face ID, Android biometrics) or roaming (YubiKey) authenticators with `userVerification: "required"` and the WebAuthn **PRF extension** enabled.
   - **PRF Wrapping-Key Derivation Specification (*Planned — not yet implemented*):**
     - `K_prf = HKDF-SHA-256(ikm = prf_output_32B, salt = credential_id_bytes, info = "strongroom-prf-kek-v1", length = 32 bytes / 256 bits)`
     - Derived directly into a non-extractable `AES-GCM` 256-bit `CryptoKey` with usages `['wrapKey', 'unwrapKey']`.
     - Wraps `K_s` via `rewrapKey` using `purpose = "vault-key-ks-prf"` and `credentialId = credential_id` in the AAD (`wrapped_ks_prf`). The raw PRF output never leaves the browser.
2. **Secret Reveal Flow (*Planned*):**
   - When the user clicks **Reveal** on an item secret, the browser requests a WebAuthn assertion with the PRF extension.
   - Local biometric/PIN verification releases the PRF output to the browser.
   - The browser derives the PRF wrapping key (`K_prf`), unwraps `K_s` (`purpose = "vault-key-ks-prf"`), unwraps the item's secret key (`wrapped_item_key_s`), decrypts `secret_blob` (verifying AAD), displays the secret for at most **15 seconds**, and releases `K_s` from memory within at most **30 seconds**.
3. **Fallback When PRF Is Unsupported (*Planned*):**
   - On devices/browsers lacking WebAuthn PRF support, revealing a secret requires re-entering the Master Password (combined with the device's stored Secret Key) to re-derive `KEK` and unwrap `wrapped_ks_master` (`purpose = "vault-key-ks-master"`).
   - The UI explicitly informs the user that hardware biometric gating is unavailable on the current device and why.
4. **Server-Side WebAuthn Verification (*Planned*):**
   - Challenge freshness window of **60 seconds**; strict server verification of `origin`, `rpId`, signature counter (`sign_count`), and challenge via `webauthn-rs`.

---

## 6. Key Rotation, Password Change, and Recovery (PRD Sections 5.4, 5.5)

- **Master Password Change (`rewrapKey`):** After fresh authentication, re-runs OPAQUE registration (*Planned*) and re-wraps `K_m` (`vault-key-km`) and `K_s` (`vault-key-ks-master`) under the new `KEK` via `rewrapKey(oldWrappingKey, oldEnvelope, oldAad, newWrappingKey, newAad)` without exposing raw key bytes to JavaScript or keeping extractable `CryptoKey` objects outside the function. Existing item ciphertexts (`meta_blob`, `secret_blob`) do not need to be re-encrypted.
- **Full Vault Key Rotation ("Rotate vault keys", *Planned*):** After suspected compromise, generates new `K_m` and `K_s` (incrementing `key_version`), wraps them, and re-encrypts all item keys/items client-side in a resumable background job.
- **Recovery Model (*Planned*):**
  - **Zero server-side recovery:** If a user loses both their Master Password and Emergency Kit (Secret Key) and has no signed-in device, the vault cannot be decrypted by anyone.
  - **Signed-in device recovery:** A user who forgets only their Master Password while still authenticated on an existing device can set a new Master Password from that device.

---

## 7. Client Memory Hygiene and Session Binding (PRD Sections 7, 8)

- **Non-Extractable Keys Cannot Be Wiped, Only Released (and Can Still Be Used by In-Page Scripts):** Long-lived keys (`KEK`, `K_m`, `K_s`, and unwrapped item keys) live as non-extractable WebCrypto `CryptoKey` objects (`extractable = false`). Only short-lived, function-local keys inside `wrapKey` and `rewrapKey` are imported/unwrapped with `extractable = true`, and they are never returned or stored and are released in `finally`. Because WebCrypto isolates non-extractable key material outside the JavaScript heap, **non-extractable `CryptoKey` objects cannot be explicitly zeroed/wiped by JavaScript code—they can only be released** by dropping all object references. **Important limitation:** a script running in the page (XSS) can still **use** any unlocked `CryptoKey` currently held in memory to perform WebCrypto operations; `extractable = false` only prevents exporting the raw key bytes.
- **Best-Effort Buffer Zeroing:** Transient `Uint8Array` and `ArrayBuffer` instances holding raw key seeds during initial wrapping, padded plaintexts, decoded envelope slices, or AAD buffers are explicitly zeroed via `wipeBuffer` / `wipeBuffers` in `finally` blocks on both success and error paths (including partial failures in `decryptItem` via `Promise.allSettled`).
- **Auto-Lock (*Planned*):** Triggers after **5 minutes** of inactivity (user-configurable down to 1 minute, never disabled), on explicit logout, and on tab close. Locking zeroes mutable buffers and drops all in-memory `CryptoKey` references.
- **Clipboard Hygiene (*Planned*):** Copied secrets are cleared from the clipboard after **30 seconds** (best-effort in browsers, with a clear UI notice).
- **Password Generator (*Planned*):** Uses `crypto.getRandomValues` with rejection sampling to eliminate modulo bias.
- **Authentication & Anti-Enumeration (*Planned*):** OPAQUE login responses for unknown email addresses return indistinguishable fake responses and uniform timing to prevent account enumeration.

---

## 8. Cryptographic Verification Requirements (PRD Sections 13, 14)

1. **Known-Answer & Property Tests:** Unit tests against official RFC 5869 (HKDF-SHA-256) and IEEE 802.1AE / McGrew & Viega GCM specification known-answer test vectors, cross-implementation verification against `node:crypto`, and tampering/property tests for versioned envelope encoding/decoding and AAD mismatches (**Planned:** full NIST CAVP test suite & fuzzing).
2. **Server Decryption-Impossibility Test (F1 Exit Gate — *Planned*):** Automated test proving that an attacker holding the complete database record and server secrets cannot decrypt `wrapped_km`, `wrapped_ks_master`, `meta_blob`, or `secret_blob`.
3. **PRF Bypass Test (F4 Exit Gate — *Planned*):** Automated test proving that a modified UI skipping the WebAuthn prompt cannot decrypt `secret_blob` because `K_s` is absent from memory without PRF output.
