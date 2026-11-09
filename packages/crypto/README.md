# @strongroom/crypto

Browser-side cryptographic primitives for the Strongroom zero-knowledge password vault (`docs/PRD.md` Sections 5.1–5.3 and 8).

## Security Invariants

- **Zero runtime dependencies:** Uses only the platform's native WebCrypto API (`globalThis.crypto.subtle` and `globalThis.crypto.getRandomValues`). `Math.random` is strictly forbidden.
- **Non-extractable keys:** In-memory `CryptoKey` objects are created and unwrapped with `extractable: false`. Whenever raw key bytes are transiently needed (e.g., wrapping a freshly generated key), the raw byte buffer is zeroed via `zeroize()` in a `finally` block.
- **Domain-separated HKDF:** `kdf.ts` enforces compile-time and runtime checks that only constant domain-separation labels (`KDF_LABELS`) can be passed to `hkdfDeriveAesGcmKey` and `hkdfDeriveBytes`.
- **Canonical AAD & 256-byte bucket padding:** `aad.ts` binds every ciphertext to `(userId, itemId, keyVersion, schemaVersion)` with 4-byte big-endian length prefixes to prevent framing collisions. `envelope.ts` pads plaintexts into 256-byte buckets and wraps ciphertexts in a versioned binary header (`[version][algorithmId][12B nonce][ciphertext+tag]`).
- **Full 128-bit Secret Key:** `secretKey.ts` encodes all 128 bits of randomness into 26 Crockford Base32 characters plus the `A3` version prefix and a Luhn mod 32 check character (`A3-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXX`).
