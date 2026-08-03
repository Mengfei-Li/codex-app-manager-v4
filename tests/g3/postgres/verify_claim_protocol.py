from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

import psycopg
from psycopg.rows import dict_row


HERE = Path(__file__).resolve().parent
SETUP_SQL = HERE / "000_test_schema.sql"
MIGRATION_SQL = HERE / "007_v4_claim_protocol.sql"
BOOTSTRAP_HASH = "a" * 64
DEVICE_ONE = "b" * 64
DEVICE_TWO = "c" * 64
IDEMPOTENCY_ONE = "d" * 64
IDEMPOTENCY_TWO = "e" * 64
OPERATION_ONE = uuid.UUID("11111111-1111-4111-8111-111111111111")
OPERATION_TWO = uuid.UUID("22222222-2222-4222-8222-222222222222")
BUILD = "v4-g3-fixture"
ENCRYPTION_KEY = "fixture-only-encryption-key"


def canonical_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")


def connect(dsn: str, *, row_dict: bool = False) -> psycopg.Connection[Any]:
    factory = dict_row if row_dict else None
    return psycopg.connect(dsn, autocommit=True, row_factory=factory)


def reset_database(dsn: str) -> None:
    with connect(dsn) as connection:
        connection.execute(canonical_text(SETUP_SQL))
        connection.execute(canonical_text(MIGRATION_SQL))


def seed(
    dsn: str,
    *,
    bootstrap_status: str = "ready",
    customer_status: str = "active",
    key_status: str = "active",
    key_deleted: bool = False,
    release_status: str = "released",
    expired: bool = False,
) -> None:
    with connect(dsn) as connection:
        connection.execute(
            "INSERT INTO api_keys (id, key, status, deleted_at) "
            "VALUES (1, 'sk-fixture-only', %s, CASE WHEN %s THEN NOW() ELSE NULL END)",
            (key_status, key_deleted),
        )
        connection.execute(
            "INSERT INTO portal.customers (id, public_customer_id, status) "
            "VALUES (1, 'CUST-V4-FIXTURE', %s)",
            (customer_status,),
        )
        connection.execute(
            "INSERT INTO portal.installer_releases "
            "(build_id, version, file_name, file_size, sha256, download_url, "
            "package_source, signature_status, status, released_at) "
            "VALUES (%s, '4.0.0', 'manager.exe', 1024, %s, "
            "'https://download.invalid/manager.exe', 'fixture', 'verified', %s, NOW())",
            (BUILD, "f" * 64, release_status),
        )
        connection.execute(
            "INSERT INTO portal.installer_bootstraps "
            "(id, customer_id, api_key_id, bootstrap_hash, bootstrap_secret_cipher, "
            "management_token_cipher, installer_build, status, expires_at) "
            "VALUES (1, 1, 1, %s, pgp_sym_encrypt('boot-fixture', %s), "
            "pgp_sym_encrypt('mgmt-fixture', %s), %s, %s, "
            "CASE WHEN %s THEN NOW() - INTERVAL '1 minute' ELSE NOW() + INTERVAL '1 hour' END)",
            (
                BOOTSTRAP_HASH,
                ENCRYPTION_KEY,
                ENCRYPTION_KEY,
                BUILD,
                bootstrap_status,
                expired,
            ),
        )


def claim(
    dsn: str,
    *,
    device_hash: str = DEVICE_ONE,
    idempotency_key: str = IDEMPOTENCY_ONE,
    operation_id: uuid.UUID = OPERATION_ONE,
    installer_build: str = BUILD,
    app_health: bool = True,
    as_portal_role: bool = False,
) -> dict[str, Any]:
    with connect(dsn, row_dict=True) as connection:
        if as_portal_role:
            connection.execute("SET ROLE sub2api_portal")
        row = connection.execute(
            "SELECT * FROM portal.claim_installer_bootstrap_v4("
            "%s, %s, %s, %s, %s, %s, %s)",
            (
                BOOTSTRAP_HASH,
                device_hash,
                ENCRYPTION_KEY,
                idempotency_key,
                operation_id,
                installer_build,
                app_health,
            ),
        ).fetchone()
        assert row is not None
        return dict(row)


def snapshot(dsn: str) -> dict[str, Any]:
    with connect(dsn, row_dict=True) as connection:
        bootstrap = connection.execute(
            "SELECT status, device_hash, claim_count, claimed_at IS NOT NULL AS claimed "
            "FROM portal.installer_bootstraps WHERE id = 1"
        ).fetchone()
        counts = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM portal.installer_claim_operations) AS operations, "
            "(SELECT COUNT(*) FROM portal.devices) AS devices, "
            "(SELECT COUNT(*) FROM portal.audit_events) AS audits"
        ).fetchone()
        return {"bootstrap": dict(bootstrap or {}), "counts": dict(counts or {})}


def expect_error(code: str, action: Callable[[], Any]) -> None:
    try:
        action()
    except psycopg.Error as error:
        assert code in str(error), (code, type(error).__name__)
        return
    raise AssertionError(f"expected database error {code}")


def assert_no_mutation_failure(
    dsn: str,
    code: str,
    **claim_arguments: Any,
) -> None:
    before = snapshot(dsn)
    expect_error(code, lambda: claim(dsn, **claim_arguments))
    assert snapshot(dsn) == before


def test_precommit_and_eligibility_failures(dsn: str) -> None:
    reset_database(dsn)
    seed(dsn)
    assert_no_mutation_failure(dsn, "PORTAL_APP_HEALTH_REQUIRED", app_health=False)
    assert_no_mutation_failure(
        dsn,
        "PORTAL_INSTALLER_BUILD_MISMATCH",
        installer_build="stale-build",
    )

    scenarios = (
        ({"customer_status": "suspended"}, "PORTAL_CUSTOMER_UNAVAILABLE"),
        ({"key_status": "revoked"}, "PORTAL_CREDENTIAL_UNAVAILABLE"),
        ({"key_deleted": True}, "PORTAL_CREDENTIAL_UNAVAILABLE"),
        ({"release_status": "retired"}, "PORTAL_RELEASE_UNAVAILABLE"),
        ({"bootstrap_status": "revoked"}, "PORTAL_BOOTSTRAP_UNAVAILABLE"),
        ({"expired": True}, "PORTAL_BOOTSTRAP_EXPIRED"),
    )
    for seed_arguments, code in scenarios:
        reset_database(dsn)
        seed(dsn, **seed_arguments)
        assert_no_mutation_failure(dsn, code)


def test_idempotency_device_and_role_boundaries(dsn: str) -> None:
    reset_database(dsn)
    seed(dsn)
    first = claim(dsn, as_portal_role=True)
    replay = claim(dsn, as_portal_role=True)
    assert first["already_claimed"] is False
    assert replay["already_claimed"] is True
    assert first["api_key"] == "sk-fixture-only"
    assert first["management_token"] == "mgmt-fixture"
    state = snapshot(dsn)
    assert state["bootstrap"] == {
        "status": "claimed",
        "device_hash": DEVICE_ONE,
        "claim_count": 1,
        "claimed": True,
    }
    assert state["counts"] == {"operations": 1, "devices": 1, "audits": 1}

    assert_no_mutation_failure(
        dsn,
        "PORTAL_IDEMPOTENCY_CONFLICT",
        operation_id=OPERATION_TWO,
    )
    resumed = claim(
        dsn,
        idempotency_key=IDEMPOTENCY_TWO,
        operation_id=OPERATION_TWO,
    )
    assert resumed["already_claimed"] is True
    state = snapshot(dsn)
    assert state["bootstrap"]["claim_count"] == 1
    assert state["counts"] == {"operations": 2, "devices": 1, "audits": 2}
    assert_no_mutation_failure(
        dsn,
        "PORTAL_BOOTSTRAP_DEVICE_MISMATCH",
        device_hash=DEVICE_TWO,
        idempotency_key="1" * 64,
        operation_id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
    )

    with connect(dsn) as connection:
        connection.execute("SET ROLE sub2api_portal")
        expect_error(
            "permission denied",
            lambda: connection.execute("SELECT * FROM portal.installer_bootstraps").fetchall(),
        )


def concurrent_claim(
    dsn: str,
    barrier: threading.Barrier,
    **arguments: Any,
) -> tuple[str, Any]:
    barrier.wait(timeout=10)
    try:
        return "ok", claim(dsn, **arguments)["already_claimed"]
    except psycopg.Error as error:
        return "error", str(error)


def test_concurrent_claims(dsn: str) -> None:
    reset_database(dsn)
    seed(dsn)
    barrier = threading.Barrier(2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(concurrent_claim, dsn, barrier) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert sorted(results) == [("ok", False), ("ok", True)]
    assert snapshot(dsn)["counts"] == {"operations": 1, "devices": 1, "audits": 1}

    reset_database(dsn)
    seed(dsn)
    barrier = threading.Barrier(2)
    calls = (
        {},
        {
            "device_hash": DEVICE_TWO,
            "idempotency_key": IDMP_CROSS_DEVICE,
            "operation_id": uuid.UUID("44444444-4444-4444-8444-444444444444"),
        },
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(concurrent_claim, dsn, barrier, **arguments)
            for arguments in calls
        ]
        results = [future.result(timeout=20) for future in futures]
    assert sum(result[0] == "ok" for result in results) == 1
    assert sum("PORTAL_BOOTSTRAP_DEVICE_MISMATCH" in str(result[1]) for result in results) == 1
    state = snapshot(dsn)
    assert state["bootstrap"]["claim_count"] == 1
    assert state["counts"] == {"operations": 1, "devices": 1, "audits": 1}


IDMP_CROSS_DEVICE = "2" * 64


def verify_source_copy(source: Path | None) -> str:
    snapshot_text = canonical_text(MIGRATION_SQL)
    if source is not None:
        assert canonical_text(source) == snapshot_text, "portal migration snapshot drifted"
    return hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--source", type=Path)
    arguments = parser.parse_args()
    if not arguments.dsn:
        raise SystemExit("DATABASE_URL or --dsn is required")

    migration_sha256 = verify_source_copy(arguments.source)
    test_precommit_and_eligibility_failures(arguments.dsn)
    test_idempotency_device_and_role_boundaries(arguments.dsn)
    test_concurrent_claims(arguments.dsn)
    print(
        json.dumps(
            {
                "status": "passed",
                "migration_sha256": migration_sha256,
                "state_matrix": 12,
                "concurrency_scenarios": 2,
                "secrets_emitted": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
