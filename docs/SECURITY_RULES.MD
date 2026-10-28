You are helping build a zero-knowledge password vault. /docs/PRD.md is the
source of truth. Read it before every task.

Non-negotiable rules:
1. Never log, print, or persist plaintext secrets, keys, master passwords,
   or Secret Keys, in code, tests, or fixtures.
2. Never invent cryptography. Use only what the PRD specifies: WebCrypto,
   opaque-ke / @serenity-kit/opaque, webauthn-rs.
3. Never add a dependency without stopping and asking me first. Give name,
   publisher, exact version, release date, why it's needed, and alternatives.
   Confirm it exists on the official registry. Pin exact versions.
4. Frontend: TypeScript strict, no `any`, no localStorage/sessionStorage for
   keys, no dangerouslySetInnerHTML, no inline scripts, no eval, no
   third-party scripts or fonts.
5. Backend: Rust with #![forbid(unsafe_code)], parameterized SQLx queries
   only, uniform error messages, constant-time secret comparisons.
6. Every security-relevant function needs tests, including failure and
   tampering cases. Run them and show me the results.
7. Ask before running any destructive or network command. Never read or
   create real .env secrets; use .env.example with placeholders.
8. Work in small steps. When done, summarize: what changed, what you were
   unsure about, and every security assumption you made.
9. If the PRD is ambiguous, or you want to deviate from it, stop and ask.