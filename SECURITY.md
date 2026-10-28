# Security Policy & Responsible Disclosure

Strongroom is a zero-knowledge password vault. We welcome independent security research and treat every vulnerability report with the highest priority.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for suspected security vulnerabilities.**

Please report security issues privately using the following contact details:

- **Security Email:** `security@[REPLACE-WITH-YOUR-DOMAIN]` *(placeholder — configure before beta/launch)*
- **PGP Key Fingerprint:** `[REPLACE-WITH-PGP-FINGERPRINT]` *(placeholder — publish at `/.well-known/security.txt` before launch)*
- **Security Advisory Channel:** GitHub Private Vulnerability Reporting on this repository

### What to Include

1. A clear description of the issue and the affected component (`client/`, `backend/`, headers, or deployment configuration).
2. Minimal, reproducible steps or proof-of-concept code.
3. Assessment of the security impact with reference to our [Threat Model](./security/threat-model.md) and [Cryptographic Design](./security/crypto-design.md).

## Response Targets

- **Initial acknowledgment:** within 24 hours
- **Triage and severity assessment:** within 72 hours
- **Coordinated disclosure:** after a fix is released and verified

## Scope & Safe Harbor

Good-faith security research conducted against your own test accounts and in compliance with this policy is authorized. Please do not perform denial-of-service testing, social engineering, or attempt to access accounts belonging to other users.
