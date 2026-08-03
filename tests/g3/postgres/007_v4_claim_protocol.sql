CREATE TABLE IF NOT EXISTS portal.installer_claim_operations (
    id BIGSERIAL PRIMARY KEY,
    bootstrap_id BIGINT NOT NULL
        REFERENCES portal.installer_bootstraps(id) ON DELETE CASCADE,
    idempotency_key CHAR(64) NOT NULL,
    device_hash CHAR(64) NOT NULL,
    installer_build VARCHAR(80) NOT NULL,
    first_operation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bootstrap_id, idempotency_key)
);

REVOKE ALL ON TABLE portal.installer_claim_operations FROM PUBLIC;
REVOKE ALL ON SEQUENCE portal.installer_claim_operations_id_seq FROM PUBLIC;

CREATE OR REPLACE FUNCTION portal.claim_installer_bootstrap_v4(
    p_bootstrap_hash TEXT,
    p_device_hash TEXT,
    p_bootstrap_encryption_key TEXT,
    p_idempotency_key TEXT,
    p_operation_id UUID,
    p_installer_build TEXT,
    p_app_health_verified BOOLEAN
)
RETURNS TABLE (
    customer_id BIGINT,
    public_customer_id VARCHAR,
    api_key TEXT,
    management_token TEXT,
    installer_build VARCHAR,
    download_url TEXT,
    file_sha256 TEXT,
    already_claimed BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = portal, public, pg_temp
AS $$
DECLARE
    selected_bootstrap portal.installer_bootstraps%ROWTYPE;
    prior_claim BOOLEAN;
    operation_inserted BOOLEAN := FALSE;
    operation_device_hash CHAR(64);
    operation_installer_build VARCHAR(80);
    operation_first_id UUID;
BEGIN
    IF p_app_health_verified IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'PORTAL_APP_HEALTH_REQUIRED';
    END IF;
    IF p_idempotency_key !~ '^[0-9a-f]{64}$'
       OR p_device_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'PORTAL_IDEMPOTENCY_CONFLICT';
    END IF;

    SELECT bootstrap.* INTO selected_bootstrap
    FROM portal.installer_bootstraps AS bootstrap
    WHERE bootstrap.bootstrap_hash = p_bootstrap_hash
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PORTAL_BOOTSTRAP_NOT_FOUND';
    END IF;
    IF selected_bootstrap.installer_build <> p_installer_build THEN
        RAISE EXCEPTION 'PORTAL_INSTALLER_BUILD_MISMATCH';
    END IF;
    PERFORM 1
    FROM portal.customers AS customer
    WHERE customer.id = selected_bootstrap.customer_id
      AND customer.status = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'PORTAL_CUSTOMER_UNAVAILABLE';
    END IF;
    PERFORM 1
    FROM api_keys AS key_record
    WHERE key_record.id = selected_bootstrap.api_key_id
      AND key_record.status = 'active'
      AND key_record.deleted_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'PORTAL_CREDENTIAL_UNAVAILABLE';
    END IF;
    PERFORM 1
    FROM portal.installer_releases AS release
    WHERE release.build_id = selected_bootstrap.installer_build
      AND release.status = 'released';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'PORTAL_RELEASE_UNAVAILABLE';
    END IF;
    IF selected_bootstrap.status = 'claimed' THEN
        IF selected_bootstrap.device_hash <> p_device_hash THEN
            RAISE EXCEPTION 'PORTAL_BOOTSTRAP_DEVICE_MISMATCH';
        END IF;
        prior_claim := TRUE;
    ELSIF selected_bootstrap.status = 'ready' THEN
        IF selected_bootstrap.expires_at <= NOW() THEN
            UPDATE portal.installer_bootstraps
            SET status = 'expired'
            WHERE id = selected_bootstrap.id;
            RAISE EXCEPTION 'PORTAL_BOOTSTRAP_EXPIRED';
        END IF;
        prior_claim := FALSE;
    ELSE
        RAISE EXCEPTION 'PORTAL_BOOTSTRAP_UNAVAILABLE';
    END IF;

    INSERT INTO portal.installer_claim_operations (
        bootstrap_id,
        idempotency_key,
        device_hash,
        installer_build,
        first_operation_id
    ) VALUES (
        selected_bootstrap.id,
        p_idempotency_key,
        p_device_hash,
        p_installer_build,
        p_operation_id
    )
    ON CONFLICT (bootstrap_id, idempotency_key) DO NOTHING
    RETURNING TRUE INTO operation_inserted;

    IF operation_inserted IS DISTINCT FROM TRUE THEN
        UPDATE portal.installer_claim_operations
        SET last_seen_at = NOW()
        WHERE bootstrap_id = selected_bootstrap.id
          AND idempotency_key = p_idempotency_key;
    END IF;

    SELECT
        operation.device_hash,
        operation.installer_build,
        operation.first_operation_id
    INTO operation_device_hash, operation_installer_build, operation_first_id
    FROM portal.installer_claim_operations AS operation
    WHERE operation.bootstrap_id = selected_bootstrap.id
      AND operation.idempotency_key = p_idempotency_key;

    IF operation_device_hash <> p_device_hash
       OR operation_installer_build <> p_installer_build
       OR operation_first_id <> p_operation_id THEN
        RAISE EXCEPTION 'PORTAL_IDEMPOTENCY_CONFLICT';
    END IF;

    UPDATE portal.installer_bootstraps
    SET status = 'claimed',
        device_hash = COALESCE(device_hash, p_device_hash),
        claim_count = claim_count + CASE WHEN prior_claim THEN 0 ELSE 1 END,
        claimed_at = COALESCE(claimed_at, NOW())
    WHERE id = selected_bootstrap.id;

    INSERT INTO portal.devices (
        customer_id, device_hash, installer_version, status
    ) VALUES (
        selected_bootstrap.customer_id,
        p_device_hash,
        selected_bootstrap.installer_build,
        'active'
    )
    ON CONFLICT ON CONSTRAINT devices_customer_id_device_hash_key DO UPDATE SET
        installer_version = EXCLUDED.installer_version,
        last_seen_at = NOW(),
        status = 'active',
        revoked_at = NULL;

    IF operation_inserted THEN
        INSERT INTO portal.audit_events (customer_id, event_type, event_data)
        VALUES (
            selected_bootstrap.customer_id,
            'installer_bootstrap_v4_claimed',
            jsonb_build_object(
                'bootstrap_id', selected_bootstrap.id,
                'device_hash', p_device_hash,
                'installer_build', p_installer_build,
                'idempotency_key', p_idempotency_key,
                'operation_id', p_operation_id,
                'prior_claim', prior_claim
            )
        );
    END IF;

    RETURN QUERY
    SELECT
        customer.id,
        customer.public_customer_id::VARCHAR,
        key_record.key::TEXT,
        pgp_sym_decrypt(
            selected_bootstrap.management_token_cipher,
            p_bootstrap_encryption_key
        ),
        release.build_id::VARCHAR,
        release.download_url::TEXT,
        release.sha256::TEXT,
        prior_claim
    FROM portal.customers AS customer
    JOIN api_keys AS key_record ON key_record.id = selected_bootstrap.api_key_id
    JOIN portal.installer_releases AS release
      ON release.build_id = selected_bootstrap.installer_build
    WHERE customer.id = selected_bootstrap.customer_id;
END;
$$;

REVOKE ALL ON FUNCTION portal.claim_installer_bootstrap_v4(
    TEXT, TEXT, TEXT, TEXT, UUID, TEXT, BOOLEAN
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION portal.claim_installer_bootstrap_v4(
    TEXT, TEXT, TEXT, TEXT, UUID, TEXT, BOOLEAN
) TO sub2api_portal;
