#!/bin/sh
# Initializes the two PostgreSQL roles required by Strongroom on first container start:
#   1. vault_migrator: owns the public schema and runs schema migrations (DDL).
#   2. vault_app: least-privilege runtime role used by the API (DML only; no DDL).
#
# Both passwords must be supplied via environment variables.

set -eu

if [ -z "${VAULT_MIGRATOR_PASSWORD:-}" ]; then
    echo "ERROR: VAULT_MIGRATOR_PASSWORD must be set" >&2
    exit 1
fi

if [ -z "${VAULT_APP_PASSWORD:-}" ]; then
    echo "ERROR: VAULT_APP_PASSWORD must be set" >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    -v db_name="$POSTGRES_DB" \
    -v migrator_password="$VAULT_MIGRATOR_PASSWORD" \
    -v app_password="$VAULT_APP_PASSWORD" <<'EOSQL'
-- 1. Schema migration role: owns schema objects and runs SQLx migrations.
CREATE ROLE vault_migrator WITH
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    PASSWORD :'migrator_password';

-- 2. Application runtime role: strictly limited to table DML granted by migrations.
CREATE ROLE vault_app WITH
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    PASSWORD :'app_password';

-- 3. Remove default PUBLIC privileges so vault_app cannot inherit CREATE on public.
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

GRANT CONNECT ON DATABASE :"db_name" TO vault_migrator;
GRANT CONNECT ON DATABASE :"db_name" TO vault_app;

-- 4. Transfer ownership of public schema to vault_migrator.
ALTER SCHEMA public OWNER TO vault_migrator;
GRANT USAGE, CREATE ON SCHEMA public TO vault_migrator;

-- 5. Allow vault_app to resolve objects in public without allowing CREATE.
GRANT USAGE ON SCHEMA public TO vault_app;
EOSQL
