CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sub2api_portal') THEN
        CREATE ROLE sub2api_portal NOLOGIN;
    END IF;
END;
$$;

DROP SCHEMA IF EXISTS portal CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;

CREATE SCHEMA portal;
GRANT USAGE ON SCHEMA portal TO sub2api_portal;

CREATE TABLE api_keys (
    id BIGSERIAL PRIMARY KEY,
    key TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    deleted_at TIMESTAMPTZ
);

CREATE TABLE portal.customers (
    id BIGSERIAL PRIMARY KEY,
    public_customer_id VARCHAR(32) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'closed'))
);

CREATE TABLE portal.devices (
    id BIGSERIAL PRIMARY KEY,
    customer_id BIGINT NOT NULL REFERENCES portal.customers(id) ON DELETE CASCADE,
    device_hash CHAR(64) NOT NULL,
    installer_version VARCHAR(80),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (customer_id, device_hash)
);

CREATE TABLE portal.audit_events (
    id BIGSERIAL PRIMARY KEY,
    customer_id BIGINT REFERENCES portal.customers(id) ON DELETE SET NULL,
    event_type VARCHAR(64) NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE portal.installer_releases (
    build_id VARCHAR(80) PRIMARY KEY,
    version VARCHAR(80) NOT NULL,
    file_name VARCHAR(180) NOT NULL,
    file_size BIGINT NOT NULL CHECK (file_size > 0),
    sha256 CHAR(64) NOT NULL,
    download_url TEXT NOT NULL,
    package_source TEXT NOT NULL,
    signature_status VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'candidate'
        CHECK (status IN ('candidate', 'released', 'retired')),
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE portal.installer_bootstraps (
    id BIGSERIAL PRIMARY KEY,
    customer_id BIGINT NOT NULL REFERENCES portal.customers(id) ON DELETE CASCADE,
    api_key_id BIGINT NOT NULL REFERENCES api_keys(id) ON DELETE RESTRICT,
    bootstrap_hash CHAR(64) NOT NULL UNIQUE,
    bootstrap_secret_cipher BYTEA NOT NULL,
    management_token_cipher BYTEA NOT NULL,
    installer_build VARCHAR(80) NOT NULL
        REFERENCES portal.installer_releases(build_id) ON DELETE RESTRICT,
    status VARCHAR(20) NOT NULL DEFAULT 'ready'
        CHECK (status IN ('ready', 'claimed', 'revoked', 'expired')),
    device_hash CHAR(64),
    claim_count INTEGER NOT NULL DEFAULT 0 CHECK (claim_count >= 0),
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_portal_installer_bootstrap_status
    ON portal.installer_bootstraps(status, expires_at);
