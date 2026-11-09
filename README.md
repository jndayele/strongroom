# Strongroom (Password Vault)

Zero-knowledge web password vault. All encryption occurs in the user's browser; the server stores only ciphertext and cannot decrypt user data.

## Repository Structure

- `apps/api`: Rust + Axum backend service
- `apps/web`: React + Vite + TypeScript (strict) frontend application
- `packages/crypto`: Client-side cryptography package (placeholder for Phase 0)
- `docs`: Product Requirements Document (`PRD.md`), threat model, crypto design, and operational runbook
- `infra`: Multi-stage distroless API `Dockerfile` and local PostgreSQL `docker-compose.yml`
- `.github/workflows`: CI pipeline with formatting, linting, tests, supply-chain audits, and secret scanning

## Local Development

1. Copy `.env.example` to `.env` for local environment variables.
2. Backend checks:
   ```sh
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```
3. Frontend checks (`apps/web`):
   ```sh
   npm ci --ignore-scripts
   npm run typecheck
   npm run lint
   npm test
   ```
