# @strongroom/crypto

Placeholder package for browser-side cryptography.

No cryptographic logic is implemented in Phase 0, Step 1. In future phases, this package will strictly use the browser's native WebCrypto API (`AES-256-GCM`, `HKDF-SHA-256`, `crypto.getRandomValues`) and `@serenity-kit/opaque` (WASM) as specified in `docs/PRD.md`.
