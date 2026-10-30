# Strongroom

Zero-knowledge web password vault (`Phase 0: Project Skeleton`).

- **Product Requirements Document:** [`/docs/PRD.md`](./docs/PRD.md)
- **Engineering Security Rules:** [`/docs/SECURITY_RULES.MD`](./docs/SECURITY_RULES.MD)
- **Threat Model:** [`/security/threat-model.md`](./security/threat-model.md)
- **Cryptographic Design:** [`/security/crypto-design.md`](./security/crypto-design.md)
- **Incident Response Runbook:** [`/security/incident-response.md`](./security/incident-response.md)

---

## Repository Layout

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml                  # Strict CI pipeline (lint, typecheck, secret/vuln scans, tests, Docker)
├── backend/                        # Rust + Axum API service (#![forbid(unsafe_code)])
│   ├── migrations/                 # SQLx database migrations (Phase 1+)
│   ├── src/
│   │   ├── auth/                   # Authentication boundary placeholder
│   │   ├── db/                     # Database boundary placeholder
│   │   ├── middleware/             # Request body size limit & canonical security headers
│   │   ├── routes/                 # HTTP endpoints (GET /health)
│   │   ├── lib.rs                  # Router construction & #![forbid(unsafe_code)]
│   │   └── main.rs                 # Binary entrypoint
│   ├── tests/
│   │   ├── headers_sync.rs         # CI/local test verifying render.yaml & backend headers match security-headers.json
│   │   └── health.rs               # Integration, per-route body limit & security header tests
│   ├── Cargo.toml                  # Exact-pinned Rust dependencies & strict clippy lints
│   └── Dockerfile                  # Multi-stage build -> gcr.io/distroless/cc-debian12:nonroot (pinned by digest)
├── client/                         # React + TypeScript (strict, no `any`) + Vite frontend
│   ├── public/                     # Self-hosted static assets only
│   │   └── .well-known/
│   │       └── security.txt        # RFC 9116 security disclosure file pointing at SECURITY.md
│   ├── src/
│   │   ├── auth/                   # Client auth boundary placeholder
│   │   ├── components/             # React components (LandingPage)
│   │   ├── crypto/                 # Client WebCrypto/OPAQUE boundary placeholder
│   │   ├── lib/                    # Shared utilities placeholder
│   │   ├── vault/                  # Vault state boundary placeholder
│   │   ├── App.tsx                 # Root component
│   │   └── main.tsx                # Application bootstrap
│   ├── eslint.config.js            # Bans dangerouslySetInnerHTML, innerHTML, eval, Math.random, `any`
│   ├── index.html                  # Self-hosted entry HTML (no inline scripts or third-party assets)
│   ├── package.json                # Exact-pinned npm dependencies
│   ├── tsconfig.json               # Strict TypeScript compiler configuration
│   └── vite.config.ts              # Vite bundler configuration
├── docs/
│   ├── decisions/                  # Architecture & security decision records
│   ├── PRD.md                      # Locked v1.0 Product Requirements Document
│   └── SECURITY_RULES.MD           # Non-negotiable security rules
├── security/
│   ├── audits/                     # Third-party security audit reports
│   ├── checklists/
│   │   └── pre-release-checklist.md
│   ├── configs/
│   │   ├── deny.toml               # cargo-deny license, ban, and advisory policy
│   │   └── gitleaks.toml           # Secret scanning configuration
│   ├── headers/
│   │   ├── README.md               # Documentation for canonical HTTP security headers
│   │   └── security-headers.json   # Single source of truth for CSP & HTTP security headers
│   ├── crypto-design.md            # Cryptographic design specification
│   ├── incident-response.md        # Incident response & key rotation runbook
│   └── threat-model.md             # Adversary model & trust boundaries
├── .env.example                    # Environment variable template (placeholders only)
├── .gitignore                      # Excludes .env, keys, node_modules, target, dist
├── render.yaml                     # Render static site + Docker web service blueprint
└── SECURITY.md                     # Responsible disclosure policy
```

---

## Running Everything Locally

### 1. Frontend (`client/`)

```bash
cd client
npm ci --ignore-scripts
npx tsc --noEmit
npm run lint
npm run build
npm run dev
```

The frontend dev server listens on `http://localhost:5173`.

### 2. Backend (`backend/`)

```bash
cd backend
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run
```

The API server listens on `http://127.0.0.1:3000` (or `HOST`/`PORT` from the environment) and exposes `GET /health`.

### 3. Backend Container (`Docker`)

Build the distroless image and run it with a read-only root filesystem and dropped Linux capabilities:

```bash
docker build -t strongroom-backend:local ./backend
docker run --rm -p 3000:3000 --read-only --cap-drop=ALL --security-opt=no-new-privileges:true strongroom-backend:local
```

Verify `GET /health` and all security headers:

```bash
curl -i http://localhost:3000/health
```
