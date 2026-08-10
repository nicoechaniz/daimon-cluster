"""Adversarial acceptance tests for the production resource-fence backend."""

from __future__ import annotations

import json
import multiprocessing
import os
import sqlite3
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clusterctl.embodiments import Registry
from clusterctl.fences import (
    Ed25519Signer,
    FakeSigner,
    FenceConflict,
    FenceError,
    InvalidSignature,
    ResourceFenceStore,
)
from clusterctl.production_fences import (
    _public_fingerprint,
    create_holder_authorization,
)

BODY = "cluster:being:compaii"
EMBODIMENT = "embodiment:11111111-1111-4111-8111-111111111111"
INCARNATION = "incarnation:22222222-2222-4222-8222-222222222222"
RESOURCE = "volume:compaii-state"
OWNER_KEY_ID = "cluster-fence-2026-08"
HOLDER_KEY_ID = "embodiment-key-2026-08"


def _key(path: Path, key_id: str) -> Ed25519Signer:
    private = Ed25519PrivateKey.generate()
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return Ed25519Signer(path, key_id)


@pytest.fixture()
def keys(tmp_path):
    return (
        _key(tmp_path / "owner.pem", OWNER_KEY_ID),
        _key(tmp_path / "holder.pem", HOLDER_KEY_ID),
    )


def _store(tmp_path: Path, owner: Ed25519Signer, **kwargs) -> ResourceFenceStore:
    return ResourceFenceStore.production(
        tmp_path / "state", signer=owner, key_id=owner.key_id, **kwargs
    )


def _authorization(
    holder: Ed25519Signer,
    *,
    operation: str,
    position: dict,
    resource_ref: str = RESOURCE,
    body_ref: str = BODY,
    embodiment_id: str = EMBODIMENT,
    incarnation_id: str = INCARNATION,
    issued_ms: int = 1_800_000_000_000,
) -> dict:
    return create_holder_authorization(
        holder,
        operation=operation,
        body_ref=body_ref,
        embodiment_id=embodiment_id,
        incarnation_id=incarnation_id,
        resource_ref=resource_ref,
        expected_epoch=position["epoch"],
        expected_proof=position["proof"],
        issued_ms=issued_ms,
        ttl_s=60,
        nonce=f"{operation}:{resource_ref}:{position['epoch']}",
    )


def _acquire(
    store: ResourceFenceStore,
    holder: Ed25519Signer,
    *,
    resource_ref: str = RESOURCE,
    observed_at_ms: int = 1_800_000_000_001,
    ttl_s: int = 120,
) -> dict:
    position = store.position(resource_ref)
    authorization = _authorization(
        holder,
        operation="acquire",
        position=position,
        resource_ref=resource_ref,
        issued_ms=observed_at_ms - 1,
    )
    return store.acquire(
        resource_ref,
        holder.public_key,
        _public_fingerprint(holder.public_key),
        ttl_s=ttl_s,
        holder_embodiment_id=EMBODIMENT,
        body_ref=BODY,
        holder_incarnation_id=INCARNATION,
        holder_key_id=holder.key_id,
        expected_epoch=position["epoch"],
        expected_proof=position["proof"],
        authorization=authorization,
        observed_at_ms=observed_at_ms,
    )


def _race_worker(
    state_dir: str,
    owner_path: str,
    holder_path: str,
    resource_ref: str,
    authorization: dict,
    queue,
) -> None:
    try:
        owner = Ed25519Signer(owner_path, OWNER_KEY_ID)
        holder = Ed25519Signer(holder_path, HOLDER_KEY_ID)
        store = ResourceFenceStore.production(
            state_dir, signer=owner, key_id=OWNER_KEY_ID
        )
        store.acquire(
            resource_ref,
            holder.public_key,
            _public_fingerprint(holder.public_key),
            holder_embodiment_id=EMBODIMENT,
            body_ref=BODY,
            holder_incarnation_id=INCARNATION,
            holder_key_id=HOLDER_KEY_ID,
            expected_epoch=-1,
            expected_proof=None,
            authorization=authorization,
            observed_at_ms=1_800_000_000_001,
        )
        queue.put("won")
    except FenceConflict:
        queue.put("conflict")
    except Exception as exc:  # pragma: no cover - diagnostic for child failures
        queue.put(f"error:{type(exc).__name__}:{exc}")


def _kill_worker(
    state_dir: str,
    owner_path: str,
    holder_path: str,
    authorization: dict,
    boundary: str,
) -> None:
    owner = Ed25519Signer(owner_path, OWNER_KEY_ID)
    holder = Ed25519Signer(holder_path, HOLDER_KEY_ID)

    def kill(observed: str) -> None:
        if observed == boundary:
            os._exit(71)

    store = ResourceFenceStore.production(
        state_dir,
        signer=owner,
        key_id=OWNER_KEY_ID,
        fault_hook=kill,
    )
    store.acquire(
        RESOURCE,
        holder.public_key,
        _public_fingerprint(holder.public_key),
        holder_embodiment_id=EMBODIMENT,
        body_ref=BODY,
        holder_incarnation_id=INCARNATION,
        holder_key_id=HOLDER_KEY_ID,
        expected_epoch=-1,
        expected_proof=None,
        authorization=authorization,
        observed_at_ms=1_800_000_000_001,
    )


def _renew_release_worker(
    state_dir: str,
    owner_path: str,
    operation: str,
    authorization: dict,
    expected_epoch: int,
    expected_proof: str,
    queue,
) -> None:
    try:
        owner = Ed25519Signer(owner_path, OWNER_KEY_ID)
        store = ResourceFenceStore.production(
            state_dir, signer=owner, key_id=OWNER_KEY_ID
        )
        kwargs = {
            "expected_epoch": expected_epoch,
            "expected_proof": expected_proof,
            "authorization": authorization,
            "observed_at_ms": 1_800_000_000_010,
        }
        if operation == "renew":
            store.renew(RESOURCE, **kwargs)
        else:
            store.release(RESOURCE, **kwargs)
        queue.put(operation)
    except FenceConflict:
        queue.put("conflict")
    except Exception as exc:  # pragma: no cover - diagnostic for child failures
        queue.put(f"error:{type(exc).__name__}:{exc}")


def test_production_refuses_synthetic_and_non_owner_key(tmp_path):
    with pytest.raises(FenceError, match="Ed25519"):
        ResourceFenceStore(
            tmp_path, FakeSigner(), production=True, key_id="fake"
        )
    path = tmp_path / "open.pem"
    signer = _key(path, OWNER_KEY_ID)
    path.chmod(0o644)
    with pytest.raises(FenceError, match="owner-only"):
        Ed25519Signer(path, signer.key_id)


def test_signed_acquire_is_exact_and_matrix_verifier_compatible(tmp_path, keys):
    pytest.importorskip("daimon_matrix")
    from clusterctl.matrix_host import MatrixHostAdapter

    owner, holder = keys
    store = _store(tmp_path, owner)
    held = _acquire(store, holder)
    registry = Registry(tmp_path / "state")
    registry.register(body_ref=BODY, embodiment_id=EMBODIMENT)
    registry.start(
        EMBODIMENT,
        incarnation_id=INCARNATION,
        started_at_ms=held["created_ms"] - 1,
    )
    adapter = MatrixHostAdapter(
        tmp_path / "state",
        EMBODIMENT,
        fence_store=store,
        clock=lambda: held["created_ms"] + 1,
    )
    evidence = adapter.fence_evidence(RESOURCE)
    assert evidence is not None
    assert adapter.verify_fence(evidence, held["created_ms"] + 1)["current"] is True
    assert held["body_ref"] == BODY
    assert held["schema"] == "resource-fence/v2"
    assert held["holder_incarnation_id"] == INCARNATION
    assert held["signing_key_id"] == OWNER_KEY_ID
    assert held["signature"].startswith("ED25519:")
    assert stat.S_IMODE((tmp_path / "state" / "resource-fences.sqlite3").stat().st_mode) == 0o600
    support = store.support_status()
    assert support["production_ready"] is True
    assert support["interprocess_cas"] is True
    assert "path" not in json.dumps(support)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("body_ref", "cluster:being:other"),
        ("embodiment_id", "embodiment:other"),
        ("incarnation_id", "incarnation:other"),
        ("resource_ref", "volume:other"),
        ("holder_key_id", "wrong-key"),
        ("operation", "renew"),
        ("expected_epoch", 8),
        ("expected_proof", "cluster:fence-proof:v1:wrong"),
    ],
)
def test_wrong_authorization_binding_fails_closed(tmp_path, keys, field, replacement):
    owner, holder = keys
    store = _store(tmp_path, owner)
    position = store.position(RESOURCE)
    authorization = _authorization(holder, operation="acquire", position=position)
    authorization[field] = replacement
    authorization["signature"] = holder.sign(
        json.dumps(
            {key: value for key, value in authorization.items() if key != "signature"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    with pytest.raises(InvalidSignature, match="binding"):
        store.acquire(
            RESOURCE,
            holder.public_key,
            _public_fingerprint(holder.public_key),
            holder_embodiment_id=EMBODIMENT,
            body_ref=BODY,
            holder_incarnation_id=INCARNATION,
            holder_key_id=HOLDER_KEY_ID,
            expected_epoch=-1,
            expected_proof=None,
            authorization=authorization,
            observed_at_ms=1_800_000_000_001,
        )


def test_signature_fingerprint_future_expiry_and_revocation_fail_closed(tmp_path, keys):
    owner, holder = keys
    store = _store(tmp_path, owner)
    position = store.position(RESOURCE)
    future = _authorization(
        holder,
        operation="acquire",
        position=position,
        issued_ms=1_800_000_100_000,
    )
    with pytest.raises(InvalidSignature, match="time"):
        store.acquire(
            RESOURCE,
            holder.public_key,
            _public_fingerprint(holder.public_key),
            holder_embodiment_id=EMBODIMENT,
            body_ref=BODY,
            holder_incarnation_id=INCARNATION,
            holder_key_id=HOLDER_KEY_ID,
            expected_epoch=-1,
            expected_proof=None,
            authorization=future,
            observed_at_ms=1_800_000_000_001,
        )
    valid = _authorization(holder, operation="acquire", position=position)
    with pytest.raises(InvalidSignature, match="fingerprint"):
        store.acquire(
            RESOURCE,
            holder.public_key,
            "SHA256:wrong",
            holder_embodiment_id=EMBODIMENT,
            body_ref=BODY,
            holder_incarnation_id=INCARNATION,
            holder_key_id=HOLDER_KEY_ID,
            expected_epoch=-1,
            expected_proof=None,
            authorization=valid,
            observed_at_ms=1_800_000_000_001,
        )
    authorization = _authorization(holder, operation="acquire", position=position)
    authorization["signature"] = "ED25519:" + "A" * 88
    with pytest.raises(InvalidSignature, match="signature"):
        store.acquire(
            RESOURCE,
            holder.public_key,
            _public_fingerprint(holder.public_key),
            holder_embodiment_id=EMBODIMENT,
            body_ref=BODY,
            holder_incarnation_id=INCARNATION,
            holder_key_id=HOLDER_KEY_ID,
            expected_epoch=-1,
            expected_proof=None,
            authorization=authorization,
            observed_at_ms=1_800_000_000_001,
        )
    held = _acquire(store, holder, ttl_s=1)
    with pytest.raises(FenceError, match="precedes"):
        store.verify_current(RESOURCE, at_ms=held["created_ms"] - 1)
    assert store.verify_current(RESOURCE, at_ms=held["created_ms"] + 1_000) is None
    store.revoke_holder_key(HOLDER_KEY_ID)
    assert store.verify_current(RESOURCE, at_ms=held["created_ms"] + 1) is None
    assert store.position(RESOURCE)["epoch"] == 1


def test_renew_release_and_reacquire_keep_one_monotonic_position(tmp_path, keys):
    owner, holder = keys
    store = _store(tmp_path, owner)
    held = _acquire(store, holder)
    first_position = store.position(RESOURCE)
    renew_auth = _authorization(
        holder,
        operation="renew",
        position=first_position,
        issued_ms=held["created_ms"] + 1,
    )
    renewed = store.renew(
        RESOURCE,
        expected_epoch=first_position["epoch"],
        expected_proof=first_position["proof"],
        authorization=renew_auth,
        observed_at_ms=held["created_ms"] + 2,
    )
    assert renewed is not None and renewed["epoch"] == 1
    with pytest.raises(FenceConflict, match="stale"):
        store.renew(
            RESOURCE,
            expected_epoch=first_position["epoch"],
            expected_proof=first_position["proof"],
            authorization=renew_auth,
            observed_at_ms=held["created_ms"] + 3,
        )
    renewed_position = store.position(RESOURCE)
    release_auth = _authorization(
        holder,
        operation="release",
        position=renewed_position,
        issued_ms=held["created_ms"] + 3,
    )
    released = store.release(
        RESOURCE,
        expected_epoch=renewed_position["epoch"],
        expected_proof=renewed_position["proof"],
        authorization=release_auth,
        observed_at_ms=held["created_ms"] + 4,
    )
    assert released["state"] == "released"
    assert released["epoch"] == 2
    assert store.verify_current(RESOURCE, at_ms=held["created_ms"] + 5) is None
    with pytest.raises(FenceError, match="cannot be restored"):
        store.restore(RESOURCE, held)
    reacquired = _acquire(
        store, holder, observed_at_ms=held["created_ms"] + 10
    )
    assert reacquired["epoch"] == 3


def test_concurrent_renew_release_race_has_one_signed_winner(tmp_path, keys):
    owner, holder = keys
    state_dir = tmp_path / "state"
    store = ResourceFenceStore.production(
        state_dir, signer=owner, key_id=OWNER_KEY_ID
    )
    _acquire(store, holder)
    position = store.position(RESOURCE)
    authorizations = {
        operation: _authorization(
            holder,
            operation=operation,
            position=position,
            issued_ms=1_800_000_000_009,
        )
        for operation in ("renew", "release")
    }
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_renew_release_worker,
            args=(
                str(state_dir),
                str(tmp_path / "owner.pem"),
                operation,
                authorizations[operation],
                position["epoch"],
                position["proof"],
                queue,
            ),
        )
        for operation in ("renew", "release")
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    results = [queue.get(timeout=2) for _ in processes]
    assert results.count("conflict") == 1
    assert len({result for result in results if result != "conflict"}) == 1
    assert store.position(RESOURCE)["epoch"] == 1


def test_signer_rotation_verifies_old_records_and_revocation_fails_closed(tmp_path, keys):
    owner, holder = keys
    store = _store(tmp_path, owner)
    stale_process = _store(tmp_path, owner)
    held = _acquire(store, holder)
    replacement = _key(tmp_path / "replacement.pem", "cluster-fence-2026-09")
    store.rotate_signer(replacement)
    assert store.verify_current(RESOURCE, at_ms=held["created_ms"] + 1) == held
    other_position = stale_process.position("volume:stale-process")
    stale_authorization = _authorization(
        holder,
        operation="acquire",
        position=other_position,
        resource_ref="volume:stale-process",
    )
    with pytest.raises(FenceError, match="not active"):
        stale_process.acquire(
            "volume:stale-process",
            holder.public_key,
            _public_fingerprint(holder.public_key),
            holder_embodiment_id=EMBODIMENT,
            body_ref=BODY,
            holder_incarnation_id=INCARNATION,
            holder_key_id=HOLDER_KEY_ID,
            expected_epoch=-1,
            expected_proof=None,
            authorization=stale_authorization,
            observed_at_ms=1_800_000_000_001,
        )
    with pytest.raises(FenceError, match="inactive"):
        ResourceFenceStore.production(
            tmp_path / "state", signer=owner, key_id=OWNER_KEY_ID
        )
    store.revoke_signing_key(OWNER_KEY_ID)
    with pytest.raises(InvalidSignature, match="revoked"):
        store.verify_current(RESOURCE, at_ms=held["created_ms"] + 1)


def test_multiprocess_contenders_have_exactly_one_winner(tmp_path, keys):
    owner, holder = keys
    state_dir = tmp_path / "state"
    store = ResourceFenceStore.production(
        state_dir, signer=owner, key_id=OWNER_KEY_ID
    )
    authorization = _authorization(
        holder, operation="acquire", position=store.position(RESOURCE)
    )
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_race_worker,
            args=(
                str(state_dir),
                str(tmp_path / "owner.pem"),
                str(tmp_path / "holder.pem"),
                RESOURCE,
                authorization,
                queue,
            ),
        )
        for _ in range(8)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    results = [queue.get(timeout=2) for _ in processes]
    assert results.count("won") == 1
    assert results.count("conflict") == 7
    assert store.position(RESOURCE)["epoch"] == 0


def test_different_resources_do_not_conflict(tmp_path, keys):
    owner, holder = keys
    state_dir = tmp_path / "state"
    store = ResourceFenceStore.production(
        state_dir, signer=owner, key_id=OWNER_KEY_ID
    )
    resources = ["volume:one", "volume:two"]
    authorizations = [
        _authorization(
            holder,
            operation="acquire",
            position=store.position(resource),
            resource_ref=resource,
        )
        for resource in resources
    ]
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(
            target=_race_worker,
            args=(
                str(state_dir),
                str(tmp_path / "owner.pem"),
                str(tmp_path / "holder.pem"),
                resource,
                authorization,
                queue,
            ),
        )
        for resource, authorization in zip(resources, authorizations, strict=True)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    assert [queue.get(timeout=2) for _ in processes].count("won") == 2
    assert [store.position(resource)["epoch"] for resource in resources] == [0, 0]


@pytest.mark.parametrize(
    ("boundary", "committed"),
    [
        ("before-begin", False),
        ("after-begin", False),
        ("before-commit", False),
        ("after-commit", True),
    ],
)
def test_process_kill_at_commit_boundaries_recovers_honestly(
    tmp_path, keys, boundary, committed
):
    owner, holder = keys
    state_dir = tmp_path / boundary
    initial = ResourceFenceStore.production(
        state_dir, signer=owner, key_id=OWNER_KEY_ID
    )
    authorization = _authorization(
        holder, operation="acquire", position=initial.position(RESOURCE)
    )
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_kill_worker,
        args=(
            str(state_dir),
            str(tmp_path / "owner.pem"),
            str(tmp_path / "holder.pem"),
            authorization,
            boundary,
        ),
    )
    process.start()
    process.join(20)
    assert process.exitcode == 71
    recovered = ResourceFenceStore.production(
        state_dir, signer=owner, key_id=OWNER_KEY_ID
    )
    assert recovered.position(RESOURCE)["epoch"] == (0 if committed else -1)
    assert bool(recovered.get(RESOURCE)) is committed


def test_second_write_failure_rolls_back_position_and_high_water(tmp_path, keys):
    owner, holder = keys
    store = _store(tmp_path, owner)
    database = tmp_path / "state" / "resource-fences.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TRIGGER simulate_disk_full BEFORE INSERT ON events "
        "BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END"
    )
    connection.commit()
    connection.close()
    with pytest.raises(FenceError, match="transaction failed"):
        _acquire(store, holder)
    assert store.position(RESOURCE)["epoch"] == -1


def test_offline_migration_retires_only_expired_synthetic_fixtures(tmp_path, keys):
    owner, holder = keys
    legacy = ResourceFenceStore(tmp_path / "state")
    legacy.acquire(
        RESOURCE,
        holder.public_key,
        _public_fingerprint(holder.public_key),
        ttl_s=0,
        holder_embodiment_id=EMBODIMENT,
    )
    production = _store(tmp_path, owner)
    with pytest.raises(FenceError, match="offline"):
        production.migrate_synthetic_v1(offline=False)
    assert production.migrate_synthetic_v1(offline=True) == 1
    position = production.position(RESOURCE)
    assert position["epoch"] == 1
    assert position["current"] is False
    assert production.support_status()["migration_state"] == "retired"
