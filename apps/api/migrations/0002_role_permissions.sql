-- Migration: 0002_role_permissions.sql
--
-- What:
--   Configures table-level permissions for the `vault_app` runtime database role.
--
-- Why:
--   Enforces the principle of least privilege (PRD Section 10):
--   - `vault_migrator` owns all schema objects and is the only role allowed to run DDL
--     (`CREATE`, `ALTER`, `DROP`).
--   - `vault_app` is granted only `SELECT`, `INSERT`, `UPDATE`, `DELETE` on operational
--     tables (`users`, `devices`, `sessions`, `passkeys`, `totp`, `recovery_codes`, `items`).
--   - `audit_events` is strictly append-only for `vault_app`: only `SELECT` and `INSERT`
--     are granted (`UPDATE` and `DELETE` are revoked/omitted so an attacker compromising
--     the API runtime cannot erase or alter security audit history).
--   - `_sqlx_migrations` receives no grants for `vault_app`.

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM vault_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    users,
    devices,
    sessions,
    passkeys,
    totp,
    recovery_codes,
    items
TO vault_app;

GRANT SELECT, INSERT ON TABLE
    audit_events
TO vault_app;
