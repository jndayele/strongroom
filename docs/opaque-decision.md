# OPAQUE Research and Decision Document (Phase 1, Step 3A)

*Status: Draft for review. No application code or dependencies have been added.*

---

## 1. Versions

### Client package (`@serenity-kit/opaque`)
- **Exact version to use:** `@serenity-kit/opaque` **`1.1.0`** (pinned as `"1.1.0"`, no `^` or `~`).
- **Release history & 14-day cooling check:**
  - `1.1.0` was published on **2026-02-01T14:40:35.117Z** (over 9 months old as of 2026-11-10, well past the 14-day cooling requirement in [PRD §11](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L185)).
  - Previous release `1.0.0` was published on **2025-11-01T18:50:14.533Z**.
  - Source: [npm registry metadata for `@serenity-kit/opaque`](https://registry.npmjs.org/@serenity-kit/opaque) and [GitHub tag `@serenity-kit/opaque@1.1.0`](https://github.com/serenity-kit/opaque/tree/@serenity-kit/opaque@1.1.0).

### Underlying `opaque-ke` version compiled into `@serenity-kit/opaque@1.1.0`
- **Declared in `Cargo.toml`:** `opaque-ke = { version = "4.0.0", features = ["argon2"] }` ([`serenity-kit/opaque` `Cargo.toml` at tag `@serenity-kit/opaque@1.1.0`](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/Cargo.toml#L18)).
- **Exact version compiled into the published WASM binary:** **`opaque-ke` `4.0.1`** (along with `voprf` `0.5.0`, `argon2` `0.5.3`, and `curve25519-dalek` `4.1.3`), verified by inspecting the embedded Rust source paths inside the compiled WASM payload in `@serenity-kit/opaque@1.1.0` (`esm/index.js`), which contain `opaque-ke-4.0.1/src/opaque.rs`, `opaque-ke-4.0.1/src/messages.rs`, and `opaque-ke-4.0.1/src/keypair.rs`.
- **Difference between `4.0.0` and `4.0.1`:** `4.0.1` (released **2025-11-03T17:43:24Z**) contains zero protocol or code changes from `4.0.0` (released **2025-10-24T01:57:50Z**)—only a `docs.rs` build fix in `Cargo.toml` ([`facebook/opaque-ke` PR #409](https://github.com/facebook/opaque-ke/pull/409), [compare `v4.0.0...v4.0.1`](https://github.com/facebook/opaque-ke/compare/v4.0.0...v4.0.1)).

### Rust server crate (`opaque-ke`)
- **Exact version to use on the server:** `opaque-ke` **`=4.0.1`** (published **2025-11-03**, over 12 months old; matches the exact crate version compiled into `@serenity-kit/opaque@1.1.0`).
- Note: Newer pre-releases `4.1.0-pre.0` through `4.1.0-pre.2` exist on [crates.io](https://crates.io/crates/opaque-ke/versions) for experimental ML-KEM support, but `4.0.1` is the latest stable release and matches the client WASM byte-for-byte.

---

## 2. Cipher Suite

### Client cipher suite in `@serenity-kit/opaque@1.1.0`
In [`serenity-kit/opaque` `src/lib.rs` (lines 86–93)](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L86-L93), when compiled without the `p256` feature (the default `@serenity-kit/opaque` package), the cipher suite is:
- **OPRF cipher suite (`OprfCs`):** `opaque_ke::Ristretto255` (implementing `voprf::CipherSuite` with Group = `Ristretto255` and Hash = `sha2::Sha512`, i.e., `OPRF(ristretto255, SHA-512)` per [RFC 9497 §4.1](https://www.rfc-editor.org/rfc/rfc9497.html#section-4.1) and [RFC 9807 §10.1](https://www.rfc-editor.org/rfc/rfc9807.html#section-10.1)).
- **Key Exchange (`KeyExchange`):** `opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>` (3DH over `ristretto255` using `SHA-512` for HKDF and HMAC transcript MACs).
- **Main Hash:** `sha2::Sha512` (512-bit / 64-byte output).
- **Key Stretching Function (`Ksf`):** Argon2id (`argon2::Argon2<'static>`, V0x13, hashing with a 16-byte all-zero salt `&[0; 16]` as specified in [RFC 9807 §4.1](https://www.rfc-editor.org/rfc/rfc9807.html#section-4.1) and [`opaque-ke` `src/ksf.rs`](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/ksf.rs#L35-L46)).
- **Wire encoding:** All byte arrays crossing the JS/WASM boundary are encoded with URL-safe Base64 without padding (`base64::engine::general_purpose::URL_SAFE_NO_PAD`, [`serenity-kit/opaque` `src/lib.rs` line 102](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L102)).

### Exact `CipherSuite` definition for the Rust server
Note that in OPAQUE ([RFC 9807 §3.3](https://www.rfc-editor.org/rfc/rfc9807.html#section-3.3) and [`opaque-ke` `src/opaque.rs`](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/opaque.rs)), the KSF (`CipherSuite::Ksf`) is **only invoked by the client** during `ClientRegistration::finish` and `ClientLogin::finish`. The server never runs the KSF during `ServerRegistration` or `ServerLogin`. However, to keep the `CipherSuite` definition identical across client, server, and server-side integration tests (where `ClientRegistration` / `ClientLogin` are used in Rust tests), we define:

```rust
use opaque_ke::CipherSuite;

pub struct VaultCipherSuite;

impl CipherSuite for VaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;
}
```
*(Source: [`opaque-ke` `v4.0.1` `src/lib.rs` lines 1240–1246](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/lib.rs#L1240-L1246) and [`serenity-kit/opaque` `src/lib.rs` lines 88–93](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L88-L93).)*

---

## 3. Argon2id Parameters

### What `@serenity-kit/opaque@1.1.0` uses
In [`serenity-kit/opaque` `src/lib.rs` (lines 124–165, 224–241)](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L124-L165) and its [`index.d.ts` (line 88)](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/build/index.d.ts), the client accepts an optional `keyStretching?: KeyStretchingFunctionConfig` parameter in both `client.finishRegistration` and `client.finishLogin`, with three modes:

1. **`"memory-constrained"` (the default when `keyStretching` is omitted):**
   - **Memory (`m_cost`):** `2^16` KiB = `65,536` KiB (**64 MiB**)
   - **Iterations (`t_cost`):** `3`
   - **Parallelism (`p_cost`):** `4`
   - Based on [RFC 9106 §4 (Second Recommended Option)](https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.2).
2. **`"rfc-recommended"` (and deprecated alias `"rfc-draft-recommended"`):**
   - **Memory (`m_cost`):** `2^21 - 1` KiB = `2,097,151` KiB (~2 GiB; set to `2^21 - 1` because `2^21` overflowed/crashed in browser WASM).
   - **Iterations (`t_cost`):** `1`
   - **Parallelism (`p_cost`):** `4`
   - Based on [RFC 9807 §10.2.1](https://www.rfc-editor.org/rfc/rfc9807.html#name-configurations) / [RFC 9106 §4 (First Recommended Option)](https://www.rfc-editor.org/rfc/rfc9106.html#section-4-6.1). Takes ~13 seconds on an M1 MacBook Pro.
3. **Custom (`{ "argon2id-custom": { memory, iterations, parallelism } }`):**
   - **Configurable?** **Yes.** `@serenity-kit/opaque@1.1.0` passes `memory` (in KiB), `iterations`, and `parallelism` directly to `argon2::ParamsBuilder` (`Version::V0x13`, `Algorithm::Argon2id`) ([`src/lib.rs` lines 124–164](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L124-L164), [README lines 272–289](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/README.md#custom)).

### Comparison against the PRD floor
- **PRD floor ([PRD §3 line 41](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L41)):** Memory **64 MiB** (`65,536` KiB), **3 iterations**, **parallelism 1** as the minimum floor.
- **Plain answer: YES, we meet the PRD floor.**
  - Even the package's default (`"memory-constrained"`: 64 MiB, 3 iterations, parallelism 4) meets the 64 MiB and 3-iteration floor, and we can also pass the exact PRD floor (`memory: 65536, iterations: 3, parallelism: 1`) or higher parameters explicitly via:
    ```ts
    keyStretching: {
      "argon2id-custom": {
        memory: 65536,      // 64 MiB in KiB
        iterations: 3,
        parallelism: 1,
      },
    }
    ```
  - Because `users.kdf_params` is stored in the database ([PRD §12 line 194](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L194)), we should always pass explicit `"argon2id-custom"` parameters rather than relying on library defaults, so future library default changes never break existing accounts.

---

## 4. Spec Status, Audits, Advisories, and Maintenance

### RFC 9807 compliance
- **Implements final RFC 9807:** **Yes.** Both `opaque-ke` `4.0.1` and `@serenity-kit/opaque` `1.1.0` implement the final published **RFC 9807** (*The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol*, published July 2025 by the IRTF CFRG stream: [rfc-editor.org/rfc/rfc9807.html](https://www.rfc-editor.org/rfc/rfc9807.html)).
- In `opaque-ke` `v4.0.0` / `v4.0.1`, test vectors were explicitly verified against the final RFC 9807 specification ([`facebook/opaque-ke` PR #386](https://github.com/facebook/opaque-ke/pull/386)). Earlier `3.x` versions implemented `draft-irtf-cfrg-opaque-18` (`voprf` `0.5.0` implements final **RFC 9497**).

### Audits
1. **`opaque-ke` (NCC Group Cryptography Assessment, June 2021):**
   - Sponsored by WhatsApp/Meta and conducted by NCC Group on `v0.5.0` ([Public Report PDF](https://github.com/facebook/opaque-ke/blob/v4.0.1/report.pdf), referenced in [`facebook/opaque-ke` README](https://github.com/facebook/opaque-ke/blob/v4.0.1/README.md#security-audits)).
   - Findings in `v0.5.0` (including client enumeration warning and reflected-value checks) were resolved by `v1.2.0` and `v2.0.0`.
2. **`@serenity-kit/opaque` (7ASecurity Whitebox Review & Pentest, 2023):**
   - Funded by the Open Technology Fund (OTF) Red Team Lab, conducted by 7ASecurity ([Public Pentest Report PDF](https://7asecurity.com/reports/pentest-report-opaque.pdf), cited in [`serenity-kit/opaque` README line 12](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/README.md#benefits)).

### Advisories and known issues
- **RustSec / OSV advisories:** Querying the [OSV.dev API](https://osv.dev/) (`crates.io/opaque-ke` and `npm/@serenity-kit/opaque`) returns **0 security advisories** for both packages.
- **Resolved bug in `@serenity-kit/opaque` `1.1.0`:** Version `1.1.0` fixed a WASM boundary memory leak when invalid parameter types were passed across `tsify` (fixing [`madonoharu/tsify#65`](https://github.com/madonoharu/tsify/issues/65) by deserializing inside Rust rather than throwing across Rust stack frames; see [`serenity-kit/opaque` `src/lib.rs` lines 170–181](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L170-L181)).

### Release dates and maintenance status
- **`opaque-ke`:** Maintained by Meta Platforms (Kevin Lewi, François Garillot, and contributors at [github.com/facebook/opaque-ke](https://github.com/facebook/opaque-ke)). Latest stable `4.0.1` released **2025-11-03**; latest pre-release `4.1.0-pre.2` released **2026-03-27**. Actively maintained.
- **`@serenity-kit/opaque`:** Maintained by Serenity Kit (Nik Graf, Stefan Oestreicher at [github.com/serenity-kit/opaque](https://github.com/serenity-kit/opaque)). `1.0.0` (updating to `opaque-ke` `4.0` / RFC 9807) released **2025-11-01**; `1.1.0` released **2026-02-01**. Published with npm provenance attestation (`"provenance": true`). Actively maintained.

---

## 5. Export Key

### Client API for the `exportKey`
In `@serenity-kit/opaque@1.1.0` ([`index.d.ts` lines 26–31, 41–45](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/build/index.d.ts) and [`src/lib.rs` lines 487–493, 585–590](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/src/lib.rs#L487-L493)):
1. **At registration:** `opaque.client.finishRegistration(params)` returns `FinishRegistrationResult`:
   ```ts
   const { registrationRecord, exportKey, serverStaticPublicKey } =
     opaque.client.finishRegistration({
       clientRegistrationState,
       registrationResponse,
       password,
       identifiers,
       keyStretching,
     });
   ```
2. **At login:** `opaque.client.finishLogin(params)` returns `FinishLoginResult | undefined` (returns `undefined` if authentication / envelope opening fails):
   ```ts
   const loginResult = opaque.client.finishLogin({
     clientLoginState,
     loginResponse,
     password,
     identifiers,
     keyStretching,
   });
   // loginResult.exportKey is a 64-byte (512-bit) secret encoded as an 86-char URL_SAFE_NO_PAD base64 string
   ```

### Confirmation: Only the client can derive `exportKey`
- **Mathematical and implementation proof ([RFC 9807 §4.1.2](https://www.rfc-editor.org/rfc/rfc9807.html#section-4.1.2) and [`opaque-ke` `src/opaque.rs` lines 349–376](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/opaque.rs#L349-L376), [`src/envelope.rs` lines 250–266](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/envelope.rs#L250-L266)):**
  1. The client blinds `password` with a random scalar `blind` and sends only `blinded_element` to the server.
  2. The server evaluates the OPRF using its per-credential `oprf_key` and returns `evaluation_element`. Because of the random `blind` factor, the server cannot compute `oprf_output`.
  3. Only the client unblinds `evaluation_element` to obtain `oprf_output`, runs Argon2id (`Ksf::hash`) to compute `stretched_oprf_output`, and extracts `randomized_pwd = HKDF-Extract(0, oprf_output || stretched_oprf_output)`.
  4. The client derives `export_key = HKDF-Expand(randomized_pwd, envelope_nonce || "ExportKey", 64)` ([`src/envelope.rs` line 258](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/envelope.rs#L258)).
  5. Neither `randomized_pwd` nor `export_key` is ever placed into `RegistrationUpload` (`opaque_record`) or `CredentialFinalization` (`finishLoginRequest`). The server structs `ServerRegistrationStartResult`, `ServerRegistration`, `ServerLoginStartResult`, and `ServerLoginFinishResult` do not contain `export_key` (they only produce `session_key` upon login finish).
  6. Even an attacker with both the database (`RegistrationUpload`) and the server's `ServerSetup` secret cannot compute `export_key` without guessing the client's `pw_input = HKDF(master_password || Secret Key)` (which has 128 bits of random entropy from the Secret Key plus the master password, stretched through Argon2id).

---

## 6. Supply Chain

### `@serenity-kit/opaque@1.1.0` (Frontend npm package)
- **Full dependency tree:** **Zero runtime dependencies** (`dependencies` is omitted/empty in [`package.json`](https://registry.npmjs.org/@serenity-kit/opaque/1.1.0)). Adding `@serenity-kit/opaque@1.1.0` adds **1 package (0 transitive dependencies)** to `node_modules`.
- **Install scripts:** **None.** There are no `preinstall`, `install`, or `postinstall` scripts in `package.json` (the `scripts` field is completely absent from the published tarball's `package.json`). It is 100% compatible with `npm ci --ignore-scripts` ([PRD §11 line 184](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L184)).
- **Tarball contents:** Only 7 files (`package.json`, `README.md`, `LICENSE`, `index.d.ts`, `esm/index.js`, `cjs/index.js`, `bin/index.js`) with the WASM binary inlined as Base64 inside `esm/index.js` and `cjs/index.js`.

### `opaque-ke` `=4.0.1` (Backend Rust crate)

#### Important feature-flag finding (`std` feature bloat)
In [`opaque-ke` `v4.0.1` `Cargo.toml` (lines 38, 60–61)](https://github.com/facebook/opaque-ke/blob/v4.0.1/Cargo.toml#L38), the `std` feature only does `std = ["dep:getrandom"]` for `cfg(target_arch = "wasm32")` with `getrandom/js`. Because Cargo's v2 feature resolver unifies features across all target triples in `Cargo.lock`, enabling `features = ["std"]` on `opaque-ke` pulls `js-sys`, `wasm-bindgen`, `wasm-bindgen-macro`, `wasm-bindgen-macro-support`, `wasm-bindgen-shared`, `bumpalo`, and `rustversion` into `Cargo.lock` even on Linux/Windows servers!
Furthermore, the server does **not** run Argon2id during registration or login (only the client runs the KSF), unless we enable `argon2` for Rust-side client integration tests.
Even with `features = ["ristretto255", "argon2"]` (and `default-features = false`, omitting `serde` and `std`), we also need `rand = { version = "=0.8.8", default-features = false, features = ["getrandom"] }` so we can pass `rand::rngs::OsRng` to `opaque-ke` (which uses `rand 0.8`), and `sha2 = "=0.10.9"` (already in `Cargo.lock` via `sqlx-core`).

#### Exact `Cargo.lock` diff for adding `opaque-ke = { version = "=4.0.1", default-features = false, features = ["ristretto255", "argon2"] }` + `rand = { version = "=0.8.8", default-features = false, features = ["getrandom"] }` + `sha2 = { version = "=0.10.9", default-features = false }`
Tested against our current [`Cargo.lock`](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/Cargo.lock):
- **1 crate downgraded in place:** `generic-array` `0.14.9` -> `0.14.7` (because `opaque-ke` pins `generic-array = "=0.14.7"`).
- **4 crates where a newer major version is already in `Cargo.lock` (so Cargo adds the `0.8` / `0.12` version alongside the existing one):**
  1. `hkdf` `0.12.4` — RFC 5869 HKDF used by `opaque-ke` *(already have `hkdf` `0.13.0` via `sqlx-postgres`)*.
  2. `hmac` `0.12.1` — RFC 2104 HMAC used by `opaque-ke` *(already have `hmac` `0.13.0` via `sqlx-postgres`)*.
  3. `rand` `0.8.8` — RNG traits and `OsRng` required by `opaque-ke` `4.0.1` *(already have `rand` `0.10.3` via `sqlx-postgres`)*.
  4. `rand_core` `0.6.4` — Core RNG traits for `rand 0.8` / `curve25519-dalek` *(already have `rand_core` `0.10.1` via `sqlx-postgres`)*.
- **Crates required by `opaque-ke` that are ALREADY in `Cargo.lock` at the exact same version (0 new entries):**
  - `sha2` `0.10.9`, `digest` `0.10.7`, `block-buffer` `0.10.4`, `crypto-common` `0.1.6`, `typenum` `1.20.1`, `subtle` `2.6.1`, `zeroize` `1.9.1`, `displaydoc` `0.2.7`, `cpufeatures` `0.2.17`, `cfg-if` `1.0.5`, `getrandom` `0.2.17`, `base64` `0.22.1`.
- **21 genuinely NEW crates added to `Cargo.lock`** (25 new package entries total including the 4 duplicate-major-version crates above; or **17 new crates** if `argon2` is only enabled on the client / dev-dependencies):
  1. `opaque-ke` `4.0.1` — Core RFC 9807 OPAQUE protocol implementation.
  2. `voprf` `0.5.0` — RFC 9497 Oblivious Pseudo-Random Function (OPRF) implementation used by `opaque-ke`.
  3. `curve25519-dalek` `4.1.3` — Ristretto255 group arithmetic for OPRF and TripleDH key exchange.
  4. `curve25519-dalek-derive` `0.1.1` — Internal proc-macro for target-feature specialization in `curve25519-dalek`.
  5. `fiat-crypto` `0.2.9` — Formally verified field arithmetic primitives used by `curve25519-dalek`.
  6. `rustc_version` `0.4.1` — Build-script helper for `curve25519-dalek` to detect compiler version.
  7. `semver` `1.0.28` — Semantic version parser used by `rustc_version`.
  8. `derive-where` `1.7.0` — Proc-macro used by `opaque-ke` and `voprf` to derive traits (`Clone`, `ZeroizeOnDrop`) on generic cipher suite types.
  9. `zeroize_derive` `1.5.0` — Proc-macro for `#[derive(Zeroize, ZeroizeOnDrop)]` required by `opaque-ke` to wipe secrets from memory.
  10. `elliptic-curve` `0.13.8` — RustCrypto elliptic curve traits and hash-to-curve primitives required by `voprf` and `opaque-ke`.
  11. `group` `0.13.0` — RustCrypto prime-order group traits used by `elliptic-curve`.
  12. `ff` `0.13.1` — RustCrypto finite field traits used by `elliptic-curve` and `group`.
  13. `crypto-bigint` `0.5.5` — Constant-time big integer arithmetic required by `elliptic-curve`.
  14. `sec1` `0.7.3` — SEC1 elliptic-curve point encoding required by `elliptic-curve`.
  15. `der` `0.7.10` — ASN.1 DER parser required by `sec1`.
  16. `const-oid` `0.9.6` — Object Identifier constants required by `der`.
  17. `base16ct` `0.2.0` — Constant-time hex encoding required by `elliptic-curve` and `sec1`.
  18. `argon2` `0.5.3` — RFC 9106 Argon2id key stretching function for `VaultCipherSuite` *(only needed if `argon2` feature is enabled on the server)*.
  19. `blake2` `0.10.6` — BLAKE2b hash function used internally by `argon2`.
  20. `password-hash` `0.5.0` — RustCrypto password hashing trait definitions used by `argon2`.
  21. `base64ct` `1.8.3` — Constant-time Base64 implementation required by `password-hash`.

---

## 7. Server Design Decisions

### 7a. Indistinguishable fake responses for unknown emails
- **What `opaque-ke` `4.0.1` does internally:**
  - When `ServerLogin::start` is called with `password_file: None` ([`opaque-ke` `src/opaque.rs` lines 659–664](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/opaque.rs#L659-L664) and [`src/messages.rs` lines 1699–1711](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/messages.rs#L1699-L1711)), `opaque-ke` **always** constructs a dummy `ServerRegistration` (`ServerRegistration::dummy(rng, server_setup)`) and selects between the dummy record and the real `password_file` using constant-time `subtle::CtOption`.
  - Specifically, `ServerSetup` pre-generates a static `dummy_pk` on setup creation (`ServerSetup::new`). On every `ServerLogin::start` call, `opaque-ke`:
    1. Generates a random `masking_key` for the dummy record and selects in constant time between the dummy record (`Envelope::dummy()`, random `masking_key`, `server_setup.dummy_pk`) and the real `password_file`.
    2. Computes `mask_response` (HKDF-Expand + XOR) over the chosen record.
    3. Derives the deterministic per-user `oprf_key` from `server_setup.oprf_seed` and `credential_identifier` via HKDF (`STR_OPRF_KEY` / `"OPAQUE-DeriveKeyPair"`), and evaluates `voprf::OprfServer::blind_evaluate`. Because `oprf_key` is derived deterministically from `oprf_seed` and `credential_identifier`, **repeating logins for the same nonexistent email returns the exact same OPRF output**, defeating multi-attempt OPRF probing ([RFC 9807 §10.4](https://www.rfc-editor.org/rfc/rfc9807.html#section-10.4)).
    4. Runs `TripleDh::generate_ke2_input` (performing the exact same Ristretto255 scalar multiplications) and returns a `CredentialResponse` of the exact same byte length (`32 + 32 + 128 + 128 = 320` bytes raw, `427` chars in URL-safe Base64) and a valid `ServerLogin` state (`128` bytes raw).
- **What OUR server code must do so timing and response size match:**
  1. **Always normalize the email and compute `email_hash` and `credential_identifier` first** before touching the database.
  2. **Execute the single `SELECT id, opaque_record, kdf_params FROM users WHERE email_hash = $1` query.**
  3. **If no user row exists (or if the user has not completed signup):**
     - Pass `None` as `password_file` to `ServerLogin::start`, using the **exact same `credential_identifier` derivation** (see 7c).
     - Return the **exact same JSON response structure** from `/auth/login/start` (including `login_id`, `login_response`, and a deterministic dummy `kdf_params` object matching our default floor `{ memory: 65536, iterations: 3, parallelism: 1 }` so the response payload size and schema are identical!).
     - **Persist the dummy `ServerLogin` state in our in-progress login store** (flagged internally with `user_id: None`) so that if an attacker calls `/auth/login/finish` with the returned `login_id`, our server still deserializes `ServerLogin` and executes `ServerLogin::finish` (which verifies the HMAC in constant time and fails) before returning the uniform `401 Unauthorized` error.
  4. **During signup (`/auth/signup/start`):** If an email is already registered, do **not** return `409 Conflict`. Run `ServerRegistration::start` with the deterministic `credential_identifier` and return a valid `RegistrationResponse` (or handle completion via the mandatory email verification step per [PRD §7 line 118](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L118)), so `/auth/signup/start` cannot be used as an email enumeration oracle either.

### 7b. Storing in-progress login state between `login/start` and `login/finish`
- **Options:**
  - **Option A (In-memory store with TTL and size cap):** A `tokio::sync::Mutex` or `RwLock` wrapping a bounded structure (e.g., a `HashMap<[u8; 32], PendingLogin>` plus a `VecDeque` eviction queue) in process memory, with a 60-second TTL and a hard cap (e.g., 10,000 entries, ~2 MB max RAM; evicting expired entries first, or rejecting / dropping oldest under DoS).
  - **Option B (PostgreSQL table `pending_logins`):** Storing `ServerLogin` bytes (`128` bytes, encrypted or raw) in Postgres with `expires_at`.
- **Recommendation:** **Option A (In-memory store with 60-second expiry and hard size cap) for Phase 1, behind a clean internal helper trait/module.**
- **Reasoning & multi-instance implications:**
  - **Security:** `ServerLogin` (`ke2_state`) holds the session key and expected client MAC (`km3`) in memory and implements `ZeroizeOnDrop` ([`opaque-ke` `src/opaque.rs` line 151](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/opaque.rs#L151)). Keeping it in RAM guarantees it is zeroized immediately upon consumption or expiry and never written to disk or WAL logs.
  - **Performance & DoS resistance:** `login/start` is an unauthenticated endpoint. Avoiding a database `INSERT` on every `login/start` (including unauthenticated flood attempts for unknown emails) protects the Render Postgres connection pool from exhaustion.
  - **Single-use enforcement:** On `login/finish`, the entry is atomically `remove()`d from the map before calling `ServerLogin::finish`, preventing replay of `CredentialFinalization`.
  - **What it means for running >1 server instance later:** In-memory state is local to one API instance. Since v1 runs as a single Docker web service on Render ([PRD §3](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L37)), in-memory works with zero external state. If we scale to multiple API instances later without sticky sessions, `login/start` could hit instance A and `login/finish` could hit instance B. By isolating the state store in a small module (`PendingLoginStore`), we can swap the backing store to Postgres (encrypting `ServerLogin` bytes with an ephemeral/server key) or Redis when horizontal scaling is needed, without touching the route handlers.

### 7c. What to use as the OPAQUE `credential_identifier`
- **User suggestion:** Keyed HMAC of the normalized email using a server secret.
- **Recommendation:** **Confirmed — use `HMAC-SHA-256(SERVER_CREDENTIAL_ID_SECRET, canonical_email)`** (where `canonical_email` is trimmed and ASCII/Unicode-lowercased per standard email normalization).
- **Reasoning:**
  - In `opaque-ke`, `credential_identifier: &[u8]` is fed into `HKDF-Expand(oprf_seed, [credential_identifier, "OprfKey"])` to derive the per-account OPRF scalar ([`src/opaque.rs` lines 201–209, 907–916](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/opaque.rs#L201-L209)).
  - **Why it MUST be deterministic from the email (not a random DB `user_id` UUID):**
    1. During `ServerRegistration::start` (`/auth/signup/start`), the user row may not be committed yet, and during `ServerLogin::start` (`/auth/login/start`) for an **unknown email**, no `user_id` UUID exists in the database! Yet `ServerLogin::start` requires a deterministic `credential_identifier` so that repeated logins for the same unknown email produce the same deterministic OPRF output.
    2. Using `HMAC-SHA-256(key, normalized_email)` works identically for both existing and nonexistent emails, never requires generating a fake UUID, and ensures the plaintext email is never passed into protocol state or logs ([PRD §10 line 155](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L155)).
  - **Key separation note:** Use domain-separated HKDF or separate keys for `email_hash` (stored in `users.email_hash` for DB lookups) vs `credential_identifier` (passed to OPAQUE), e.g., deriving both from a master pepper or holding `OPAQUE_SERVER_SETUP` separately, so a leak of the `users` table does not expose raw inputs to any other subsystem.

### 7d. Generating, storing, and rotating the OPAQUE `ServerSetup` secret
- **What `ServerSetup` contains:**
  - For `Ristretto255` + `Sha512`, `ServerSetup::serialize()` produces **128 bytes** (`64`-byte `OprfSeed<Sha512>` + `32`-byte `PrivateKey<Ristretto255>` + `32`-byte `dummy_pk` `PublicKey<Ristretto255>`, per [`src/opaque.rs` lines 174–178, 212–225](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/opaque.rs#L174-L178)). Encoded as URL-safe Base64 (no pad), it is a **171-character string** ([`@serenity-kit/opaque` README line 40](https://github.com/serenity-kit/opaque/blob/ca1cb22f03b9e456159ce367e2975124f87f5ad8/README.md#L40)).
- **Generation:**
  - Provide a dedicated Rust CLI subcommand or binary in our workspace (or test utility) that calls `ServerSetup::<VaultCipherSuite>::new(&mut OsRng)` and prints the Base64-encoded 128-byte setup string to stdout (compatible with `npx @serenity-kit/opaque@1.1.0 create-server-setup`).
  - Never generate `ServerSetup` on the fly at server startup in production—if the server restarts with a new `ServerSetup`, all existing `opaque_record` rows become invalid. At startup, the API must read `OPAQUE_SERVER_SETUP` from the environment, decode the 128 bytes, call `ServerSetup::<VaultCipherSuite>::deserialize(&bytes)`, and fail fast (refuse to start) if missing or malformed.
- **Storage:**
  - Stored **exclusively** as a Render Environment Secret (`OPAQUE_SERVER_SETUP`, Separate secrets for staging and production per [PRD §10 line 176](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L176)).
  - In local development, stored in `.env` (which is gitignored), with a placeholder comment in `.env.example` (Rule 8).
  - Wrapped in a non-logging struct in Rust (never `#[derive(Debug)]` printing secret bytes).
- **Rotation procedure ([PRD §10 line 154](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L154)):**
  - Because `ServerSetup` contains `oprf_seed` (which determines the client's `oprf_output` and therefore `randomized_pwd` and `export_key`) and `server_s_sk` (whose public key `server_s_pk` is sealed inside the client's `Envelope`), **rotating `ServerSetup` invalidates all existing `opaque_record` blobs**.
  - **How to support zero-downtime / graceful rotation:**
    1. Include a `server_setup_version: smallint` column on `users` (or use `key_version`, [PRD §12 line 194](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L194)) indicating which `ServerSetup` version (`v1`, `v2`) the user's `opaque_record` was registered against.
    2. The server holds `OPAQUE_SERVER_SETUP_CURRENT` (e.g. `v2`) and optionally `OPAQUE_SERVER_SETUP_PREVIOUS` (e.g. `v1`).
    3. All new signups and password changes use `CURRENT`.
    4. When a user on `PREVIOUS` logs in:
       - `login/start` uses `PREVIOUS` so the client can complete login and recover their `export_key` and unwrap `K_m` / `K_s`.
       - The login response indicates `re_registration_required: true`. The client immediately runs a silent OPAQUE registration against `CURRENT` (using the in-memory `pw_input`), derives the new `export_key` and `KEK`, re-wraps `K_m` and `K_s` (just like [PRD §5.4 Master password change](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L91)), and uploads the new `opaque_record`, `wrapped_km`, and `wrapped_ks_master` without touching any vault items.

---

## 8. Top 5 Integration Risks and How We Will Test for Each

| # | Subtle Failure Mode | Why It Happens | How We Will Test for It |
| --- | --- | --- | --- |
| **1** | **Argon2id (`kdf_params`) drift between signup and login** | In OPAQUE, the server does not execute the KSF—the client runs Argon2id in both `finishRegistration` and `finishLogin`. If a client signs up with custom `kdf_params` (or we raise the default floor in a future release) and later logs in on a new device using different Argon2id parameters, `Envelope::open` will fail with a generic `InvalidLoginError` (`finishLogin` returns `undefined`), permanently locking the user out despite entering the right password and Secret Key. | **Integration & E2E test:** Register a user with non-default `kdf_params` (e.g., `memory: 65536, iterations: 4, parallelism: 1`), persist `kdf_params` on the `users` row, return `kdf_params` in `/auth/login/start`, and verify in a test that the client reads `kdf_params` from `/auth/login/start` (after validating against the minimum security floor!) to succeed, while wrong `kdf_params` fails. |
| **2** | **KDF downgrade attack via malicious/compromised server response** | Because the client uses `kdf_params` returned by `/auth/login/start`, a compromised server could return `{ memory: 8, iterations: 1, parallelism: 1 }` during login or password change, tricking the client into running a weak KSF or crashing WASM with huge memory (`2^21` KiB). | **Client unit test:** Write strict client-side bounds validation on `kdf_params` before passing to `finishLogin`: reject any `memory < 65536` (64 MiB), `memory > 524288` (512 MiB WASM safety ceiling), `iterations < 3`, `iterations > 10`, or `parallelism < 1` / `> 4`. Assert in unit tests that out-of-range server `kdf_params` throw an explicit error before calling WASM. |
| **3** | **Email canonicalization mismatch between client and server** | If a user registers as `Alice@Example.com ` and logs in as `alice@example.com`: (a) if the server's `credential_identifier` HMAC or `email_hash` does not normalize identically on signup and login, the server derives a different `oprf_key` and login fails; (b) if we pass `identifiers: { client }` with un-normalized email strings, `Envelope::open` AAD verification fails. | **Unit & integration test:** Centralize email normalization (trim + Unicode NFC + lowercase) on both client and server, and write table-driven tests verifying that registering with `"  Alice.Smith@Example.COM\n"` and logging in with `"alice.smith@example.com"` succeeds and derives the exact same `exportKey`. |
| **4** | **Timing or payload-size side channel on `/auth/login/start` for unknown emails** | Even though `opaque-ke` runs a constant-time dummy OPRF + 3DH when `password_file` is `None`, our handler could leak account existence if: (a) `kdf_params` is `null` for unknown users and an object for known users, (b) deserializing a stored `ServerRegistration` is skipped or errors early, or (c) `login/finish` returns immediately (`404`) for a dummy login instead of running `ServerLogin::finish`. | **Automated security test ([PRD §13 F2](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L214)):** Write an integration test that calls `/auth/login/start` and `/auth/login/finish` for both a registered email and an unregistered email, asserting: (1) identical HTTP status codes, JSON keys, and exact `login_response` string lengths (`427` chars), (2) dummy `ServerLogin` state is stored and evaluated on `/auth/login/finish`, and (3) statistical timing distributions overlap within noise margins. |
| **5** | **Server static public key (`serverStaticPublicKey`) impersonation or mismatch** | As noted in [`opaque-ke` `src/lib.rs` lines 619–624](https://github.com/facebook/opaque-ke/blob/v4.0.1/src/lib.rs#L619-L624), if an attacker steals a user's `opaque_record` (`RegistrationUpload`) from the database, they could impersonate the server during login unless the client verifies `serverStaticPublicKey` against the expected pinned server public key (`VITE_OPAQUE_SERVER_PUBLIC_KEY`). | **Client unit & E2E test:** Configure the expected `serverStaticPublicKey` in frontend config, verify it in both `finishRegistration` and `finishLogin` before deriving `KEK` or sending `finishLoginRequest`, and write a test where a rogue `ServerSetup` produces a valid `RegistrationResponse` / `loginResponse` and assert that the client aborts immediately on `serverStaticPublicKey` mismatch. |

---

## 9. Recommended Implementation Plan

Once you review and approve this document and the dependency list in Section 6, we will proceed one small step at a time:

1. **Step 3B (Dependencies & Server Setup):**
   - With your approval, add `opaque-ke = "=4.0.1"`, `rand = "=0.8.8"`, and `sha2 = "=0.10.9"` ( plus `hmac = "=0.12.1"` and `base64 = "=0.22.1"`, which are already in `Cargo.lock`) to `apps/api/Cargo.toml`, and `@serenity-kit/opaque` `"1.1.0"` to the frontend `package.json`.
   - Define `VaultCipherSuite` on the server, add `OPAQUE_SERVER_SETUP` and `OPAQUE_CREDENTIAL_ID_SECRET` to `.env.example`, and write a small Rust helper/test to generate and validate a `ServerSetup`.
2. **Step 3C (Server OPAQUE Crypto Module & Unit Tests):**
   - Implement a pure, self-contained `auth::opaque` module in `apps/api` wrapping `ServerRegistration::start`, `ServerRegistration::finish`, `ServerLogin::start` (handling both `Some(record)` and `None`), `ServerLogin::finish`, email normalization + HMAC `credential_identifier`, and the bounded in-memory `PendingLoginStore` with 60s expiry.
   - Write Rust unit tests covering full registration, valid login, wrong password, unknown email (indistinguishability check), and expired/replayed login state.
3. **Step 3D (Database Migration & HTTP Endpoints):**
   - Add the SQLx migration for `users` (`id`, `email_hash`, `email_enc`, `opaque_record`, `wrapped_km`, `wrapped_ks_master`, `kdf_params`, `key_version`, `created_at` per [PRD §12](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L194)).
   - Wire up the Axum endpoints (`/auth/signup/start`, `/auth/signup/finish`, `/auth/login/start`, `/auth/login/finish`) with strict request size limits, unknown-field rejection (`#[serde(deny_unknown_fields)]`), and uniform error responses.
4. **Step 3E (Client OPAQUE & Key Hierarchy Module):**
   - Implement the TypeScript client wrapper around `@serenity-kit/opaque@1.1.0` and WebCrypto (`HKDF-SHA-256` for `pw_input = HKDF(master_password || Secret Key)` and `KEK = HKDF(export_key, secret_key, "vault-kek-v1")`, plus `serverStaticPublicKey` verification and `kdf_params` floor validation).
   - Run cross-layer tests verifying that a browser client registration/login round-trips cleanly against the Rust server and that server-side data alone cannot decrypt `wrapped_km` or `wrapped_ks_master` ([PRD §13 F1](file:///c:/Users/Jonathan%20Ndayele/Desktop/strongroom/docs/PRD.md#L209)).

---

## 10. Rules for step 3D

a) `kdf_params` are one constant server-wide value for every user (memory 65536 KiB, iterations 3, parallelism 1), returned identically for known and unknown emails. If it ever changes, the fake response for unknown emails must mimic the real distribution, or this becomes an enumeration leak.

b) `signup/finish` for an email that already exists must NEVER overwrite or modify the existing record, must return the same success-shaped response, and must take the same code path (use `INSERT ... ON CONFLICT DO NOTHING`; the unique constraint on `email_hash` decides races).

c) The `users` table already exists from migration 0001; any change is a new migration 0003.

d) `login/finish` must not release wrapped keys or sessions; that is gated by 2FA in later steps.

e) **Email verification prerequisite (design debt from Step 3C):** Currently `signup/finish` inserts into `users` before the email is verified, which would allow pre-registration squatting on an unverified email (making the real owner's subsequent signup a silent no-op). The email-verification step MUST fix this by holding unverified signups in a separate pending table with an expiry and creating the `users` row only after the email verification link is confirmed.
