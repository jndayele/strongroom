# Security Headers — Single Source of Truth

This directory defines the canonical HTTP security headers required by [`/docs/PRD.md`](../../docs/PRD.md) (Sections 8 and 9).

- **Canonical Machine-Readable Definition:** [`security-headers.json`](./security-headers.json)
- **Static Frontend (`client/`):** Mirrored in [`/render.yaml`](../../render.yaml) under the `strongroom-client` static site `headers` block.
- **API Backend (`backend/`):** Enforced on every HTTP response by [`/backend/src/middleware/mod.rs`](../../backend/src/middleware/mod.rs) and verified by automated integration tests in [`/backend/tests/health.rs`](../../backend/tests/health.rs).

## Canonical Header Values (PRD Sections 8 & 9)

| Header | Value | PRD Reference |
| --- | --- | --- |
| `Content-Security-Policy` (Client) | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://api.<domain>; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'` | Section 9.1, 9.2 |
| `Content-Security-Policy` (API) | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | Section 9.1 |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Section 9.4 (2 years, `includeSubDomains`, `preload`) |
| `X-Content-Type-Options` | `nosniff` | Section 9.4 |
| `Referrer-Policy` | `no-referrer` | Section 9.4 |
| `Permissions-Policy` | `accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()` | Section 9.4 |
| `Cross-Origin-Opener-Policy` | `same-origin` | Section 9.4 |
| `Cross-Origin-Resource-Policy` | `same-origin` | Section 9.4 |
| `Cache-Control` | `no-store` | Section 8 |
| `X-Frame-Options` | `DENY` | Section 9.1 (defense-in-depth with `frame-ancestors 'none'`) |

> **Important:** Before deploying to production, replace `https://api.strongroom.example` in `render.yaml` and `security-headers.json` with your production API origin (`https://api.<your-domain>`). Never add `'unsafe-inline'` or `'unsafe-eval'`.
