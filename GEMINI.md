You are helping me build a zero-knowledge password vault. The full spec is in docs/PRD.md. Read it completely before doing anything, and treat it as the source of truth. If anything I ask conflicts with the PRD, stop and tell me.

About me: this is my FIRST time writing Rust. So:
- Keep code simple and boring. Prefer clear code over clever code. No macros, no advanced generics, no unnecessary lifetimes or trait tricks.
- After each task, explain in plain language what you wrote and any Rust concept I need to know (ownership, Result, async), in a few lines.
- Do one small step at a time. Do not build ahead of what I ask.

Hard security rules (never break these):
1. The server must never receive or hold anything that can decrypt user data. All encryption happens in the browser.
2. Never write your own cryptography. Use only: browser WebCrypto, `opaque-ke` (Rust) and `@serenity-kit/opaque` (client), `webauthn-rs`. Never use Math.random; use crypto.getRandomValues.
3. Every new dependency (npm or crate) needs a one-line written justification from you, and my approval before you add it. Prefer built-in platform features. Pin exact versions, with no ^ or ~.
4. Rust: `#![forbid(unsafe_code)]` in our own crates, clippy with warnings denied, no `unwrap()` or `expect()` outside tests. Use proper error handling.
5. SQL: only parameterized SQLx queries. Every query touching user data filters by the session's user_id.
6. Never log request bodies, emails, tokens, or ciphertext.
7. Frontend: TypeScript strict mode, no dangerouslySetInnerHTML, no inline scripts, no third-party scripts, no keys in localStorage/sessionStorage/cookies.
8. Never commit secrets. Use .env files (gitignored) and provide .env.example.

Working style: after finishing a task, run the build, lint and tests yourself and show me the results. If something fails, fix it before reporting. Never claim something works without running it.