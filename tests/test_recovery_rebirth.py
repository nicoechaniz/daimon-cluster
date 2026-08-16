from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from daimon_matrix.keystore import EncryptedKeystore
from daimon_matrix.ledger import Ledger
from daimon_matrix.operator_rebirth import (
    activate_recovery_target_runtime,
    authority_from_runtime_bundle,
    authorize_recovery_from_root_custody,
    create_recovery_custody,
    create_recovery_target_preparation,
)
from daimon_matrix.runtime import load_runtime
from daimon_matrix.weave import EventSigner

from clusterctl import cli, rebirth, rebirth_host, recovery_rebirth
from clusterctl.embodiments import Registry
from clusterctl.fences import Ed25519Signer, ResourceFenceStore
from clusterctl.matrix_host import create_portable_snapshot, matrix_root
from tests.test_rebirth import _ceremony, _descriptor, _ensure_production_fences


@pytest.fixture
def short_tmp_path():
    with TemporaryDirectory(prefix="dmc-recovery-") as value:
        yield Path(value)


def _recovery_fixture(tmp_path: Path) -> dict:
    # Bootstrap timestamps its generated credentials from the live clock. Read
    # the recovery ceremony instant only after bootstrap has completed, and do
    # not place the new credential in the future relative to the restore path.
    fixture = _ceremony(tmp_path)
    now_ms = time.time_ns() // 1_000_000
    source_id = min(fixture["peers"])
    source_root = fixture["peers"][source_id]
    source_password = fixture["peer_passwords"][source_id]
    bundle = json.loads((source_root / "runtime.json").read_bytes())
    authority = authority_from_runtime_bundle(bundle)
    contents = EncryptedKeystore(source_root / "custody.json").open(
        lambda: bytearray(source_password),
        required_control_head=authority.state.head,
    )
    signing_slot = bundle["keystore"]["signing_slot"]
    member = next(
        row
        for row in authority.manifest.value["embodiments"]
        if row["embodiment_id"] == source_id
    )
    credential = authority.credentials[member["embodiment_credential_id"]]
    signer = EventSigner(
        credential["body"]["signing_key"]["key_id"], contents.secrets[signing_slot]
    )
    old_event = Ledger(
        source_root / bundle["ledger"],
        authority=authority,
        local_origin=bundle["local_origin"],
    ).append_local(
        kind="experience.observed",
        subject="before-recovery",
        payload={"summary": "survives recovery"},
        signer=signer,
        occurred_at_ms=now_ms + 1,
    )
    snapshot = tmp_path / "canonical-snapshot"
    create_portable_snapshot(source_root, snapshot)

    ceremony = tmp_path / "recovery-ceremony"
    ceremony.mkdir(mode=0o700)
    old_root_password = b"h7-offline-root-password"
    new_root_password = b"cluster-recovery-new-root-password"
    create_recovery_custody(
        ceremony / "successor-root",
        authority,
        tmp_path / "source/bootstrap/offline/root-custody.json",
        lambda: bytearray(old_root_password),
        lambda: bytearray(new_root_password),
    )
    recovery = json.loads((ceremony / "successor-root/recovery.json").read_bytes())
    target_password = b"cluster-recovery-target-password"
    preparation = create_recovery_target_preparation(
        ceremony / "preparation",
        authority,
        recovery,
        {
            "schema": "dm.operator.rebirth-target-profile/v1",
            "label": "recovered-host",
            "body_ref": "cluster:recovered-host:compaii",
            "principal_id": "compaii@recovered-host",
            "listen_host": "127.0.0.1",
            "listen_port": 21686,
            "advertised_endpoint": "http://127.0.0.1:21686/dm-peer/v1",
            "targets": [],
        },
        lambda: bytearray(target_password),
        created_at_ms=now_ms,
        expires_at_ms=now_ms + 60_000,
    )
    request = json.loads((ceremony / "preparation/request.json").read_bytes())
    activation = authorize_recovery_from_root_custody(
        request,
        authority,
        recovery,
        ceremony / "successor-root/root-custody.json",
        lambda: bytearray(new_root_password),
        issued_at_ms=now_ms,
    )
    package = ceremony / "package"
    activate_recovery_target_runtime(
        package,
        ceremony / "preparation",
        preparation,
        request,
        activation,
        bundle,
        lambda: bytearray(target_password),
    )
    return {
        "package": package,
        "snapshot": snapshot,
        "password": target_password,
        "old_event": old_event,
        "now_ms": now_ms,
    }


def _production_fence_verifier(state: Path, key_path: Path) -> None:
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    signer = Ed25519Signer(key_path, "recovery-test-cluster-owner")
    ResourceFenceStore.production(state, signer=signer, key_id=signer.key_id)


def test_recovery_restore_is_gated_idempotent_and_reproducible(short_tmp_path, capsys):
    fixture = _recovery_fixture(short_tmp_path)
    snapshot_before = {
        path.relative_to(fixture["snapshot"]).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in fixture["snapshot"].rglob("*")
        if path.is_file()
    }
    state = short_tmp_path / "cluster-state"
    state.mkdir(mode=0o700)
    direct = rebirth.install_rebirth_package(
        state,
        fixture["package"],
        {},
        idempotency_key=str(uuid.uuid4()),
    )
    with pytest.raises(rebirth_host.RebirthHostError, match="recovery_restore_missing"):
        rebirth_host.launch_rebirth_host(
            state, direct["embodiment_id"], _descriptor(fixture["password"])
        )

    with pytest.raises(
        recovery_rebirth.RecoveryRebirthError,
        match="requires_custody_free_snapshot",
    ):
        recovery_rebirth.install_recovery_rebirth(
            state,
            fixture["package"],
            fixture["snapshot"],
            lambda: bytearray(fixture["password"]),
            idempotency_key=str(uuid.uuid4()),
        )
    transfer = short_tmp_path / "custody-free-install-transfer"
    recovery_rebirth.export_recovery_snapshot(fixture["snapshot"], transfer)

    restore_key = str(uuid.uuid4())
    with pytest.raises(recovery_rebirth.RecoveryRebirthError, match="restore_rejected"):
        recovery_rebirth.install_recovery_rebirth(
            state,
            fixture["package"],
            transfer,
            lambda: bytearray(b"wrong-recovery-password"),
            idempotency_key=restore_key,
        )
    result = recovery_rebirth.install_recovery_rebirth(
        state,
        fixture["package"],
        transfer,
        lambda: bytearray(fixture["password"]),
        idempotency_key=restore_key,
    )
    replay = recovery_rebirth.install_recovery_rebirth(
        state,
        fixture["package"],
        transfer,
        lambda: (_ for _ in ()).throw(AssertionError("password reread")),
        idempotency_key=str(uuid.uuid4()),
    )
    assert replay == result
    assert snapshot_before == {
        path.relative_to(fixture["snapshot"]).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in fixture["snapshot"].rglob("*")
        if path.is_file()
    }
    assert result["state"] == "installed-restored-stopped"
    assert result["custody_free_transfer"] is True
    assert Registry(state).status(result["embodiment_id"])["status"] == "stopped"
    hosted = load_runtime(
        matrix_root(state, result["embodiment_id"]),
        "runtime.json",
        lambda: bytearray(fixture["password"]),
        clock=lambda: fixture["now_ms"] + 30,
    )
    assert hosted.service.ledger.events() == [fixture["old_event"]]

    _production_fence_verifier(state, short_tmp_path / "cluster-fence-owner.pem")
    _ensure_production_fences(state, result["embodiment_id"])
    process, started = rebirth_host.launch_rebirth_host(
        state,
        result["embodiment_id"],
        _descriptor(fixture["password"]),
        production_fence_verifier=True,
    )
    try:
        assert started["state"] == "running-ready"
        assert started["active_embodiment_ids"] == [result["embodiment_id"]]
    finally:
        process.terminate()
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0, stderr
    recovered = load_runtime(
        matrix_root(state, result["embodiment_id"]),
        "runtime.json",
        lambda: bytearray(fixture["password"]),
        clock=lambda: fixture["now_ms"] + 40,
    )
    fresh_event = recovered.service.ledger.append_local(
        kind="experience.observed",
        subject="after-recovery",
        payload={"summary": "fresh embodiment writes forward"},
        signer=recovered.service.signer,
        occurred_at_ms=fixture["now_ms"] + 40,
    )
    assert {event["event_id"] for event in recovered.service.ledger.events()} == {
        fixture["old_event"]["event_id"],
        fresh_event["event_id"],
    }

    # A fresh target rebuilt from the same package and snapshot has the exact
    # same restored canonical event set: this is the disaster-restore path,
    # never a rollback to predecessor custody or authority bytes.
    second_state = short_tmp_path / "second-cluster-state"
    assert (
        cli.run(
            [
                "--state-dir",
                str(second_state),
                "rebirth-recovery-restore",
                "--package-dir",
                str(fixture["package"]),
                "--snapshot-dir",
                str(transfer),
                "--password-fd",
                str(_descriptor(fixture["password"])),
                "--idempotency-key",
                str(uuid.uuid4()),
                "--json",
            ]
        )
        == 0
    )
    second = json.loads(capsys.readouterr().out)
    assert second["event_set_sha256"] == result["event_set_sha256"]
    second_hosted = load_runtime(
        matrix_root(second_state, second["embodiment_id"]),
        "runtime.json",
        lambda: bytearray(fixture["password"]),
        clock=lambda: fixture["now_ms"] + 30,
    )
    assert second_hosted.service.ledger.events() == [fixture["old_event"]]


def test_tampered_snapshot_refuses_before_cluster_state_mutation(short_tmp_path):
    fixture = _recovery_fixture(short_tmp_path)
    tampered = short_tmp_path / "tampered-snapshot"
    shutil.copytree(fixture["snapshot"], tampered)
    ledger = next(
        path
        for path in (tampered / "payload").iterdir()
        if path.name == "ledger.sqlite"
    )
    ledger.write_bytes(ledger.read_bytes() + b"tampered")
    state = short_tmp_path / "rejected-state"
    state.mkdir(mode=0o700)
    with pytest.raises(Exception, match="matrix_snapshot_payload_rejected"):
        recovery_rebirth.install_recovery_rebirth(
            state,
            fixture["package"],
            tampered,
            lambda: bytearray(fixture["password"]),
            idempotency_key=str(uuid.uuid4()),
        )
    assert list(state.iterdir()) == []


def test_recovery_snapshot_export_contains_only_public_bundle_and_ledger(
    short_tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = _recovery_fixture(short_tmp_path)
    transfer = short_tmp_path / "custody-free-transfer"
    assert (
        cli.run(
            [
                "--state-dir",
                str(short_tmp_path / "unused-state"),
                "rebirth-recovery-export",
                "--snapshot-dir",
                str(fixture["snapshot"]),
                "--output",
                str(transfer),
                "--json",
            ]
        )
        == 0
    )
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["custody_files_exported"] is False
    assert receipt["omitted_file_count"] > 0
    assert set(receipt["files"]) == {"ledger.sqlite", "runtime.json"}
    manifest, payload, verified = recovery_rebirth.verify_portable_snapshot(transfer)
    assert receipt["recovery_snapshot_sha256"] == recovery_rebirth._sha(manifest)
    assert {name for _path, name in verified} == {"ledger.sqlite", "runtime.json"}
    assert {path.name for path in payload.iterdir()} == {
        "ledger.sqlite",
        "runtime.json",
    }
    assert (fixture["snapshot"] / "payload/custody.json").is_file()
    assert not any("custody" in path.name for path in transfer.rglob("*"))
    restored = recovery_rebirth.install_recovery_rebirth(
        short_tmp_path / "filtered-target-state",
        fixture["package"],
        transfer,
        lambda: bytearray(fixture["password"]),
        idempotency_key=str(uuid.uuid4()),
    )
    assert restored["custody_free_transfer"] is True
    with pytest.raises(
        recovery_rebirth.RecoveryRebirthError,
        match="recovery_snapshot_destination_exists",
    ):
        recovery_rebirth.export_recovery_snapshot(fixture["snapshot"], transfer)


def test_recovery_snapshot_export_rejects_replacement_race(
    short_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _recovery_fixture(short_tmp_path)
    source_ledger = fixture["snapshot"] / "payload/ledger.sqlite"
    original_ledger = fixture["snapshot"] / "payload/ledger-original.sqlite"
    outside = short_tmp_path / "outside-export-ledger.sqlite"
    outside.write_bytes(b"must-not-cross-recovery-export")
    outside.chmod(0o600)
    transfer = short_tmp_path / "race-rejected-transfer"
    real_stage = recovery_rebirth._stage_snapshot_file
    swapped = False

    def swap_before_stage(
        source: Path,
        destination: Path,
        row: dict[str, Any],
        *,
        capture: bool = False,
    ) -> bytes | None:
        nonlocal swapped
        if source == source_ledger:
            swapped = True
            source_ledger.rename(original_ledger)
            source_ledger.symlink_to(outside)
        return real_stage(source, destination, row, capture=capture)

    monkeypatch.setattr(recovery_rebirth, "_stage_snapshot_file", swap_before_stage)
    with pytest.raises(
        recovery_rebirth.RecoveryRebirthError,
        match="recovery_rebirth_snapshot_rejected",
    ):
        recovery_rebirth.export_recovery_snapshot(fixture["snapshot"], transfer)
    assert swapped is True
    assert not transfer.exists()
    assert not list(short_tmp_path.glob(".race-rejected-transfer.recovery-*"))


def test_read_only_snapshot_parent_restores_via_target_owned_scratch(
    short_tmp_path: Path,
) -> None:
    fixture = _recovery_fixture(short_tmp_path)
    transfer = short_tmp_path / "read-only-transfer"
    transfer.mkdir(mode=0o700)
    snapshot = transfer / "canonical"
    recovery_rebirth.export_recovery_snapshot(fixture["snapshot"], snapshot)
    state_parent = short_tmp_path / "target-owned"
    state_parent.mkdir(mode=0o700)
    state = state_parent / "cluster-state"
    transfer.chmod(0o500)
    try:
        result = recovery_rebirth.install_recovery_rebirth(
            state,
            fixture["package"],
            snapshot,
            lambda: bytearray(fixture["password"]),
            idempotency_key=str(uuid.uuid4()),
        )
    finally:
        transfer.chmod(0o700)
    assert result["state"] == "installed-restored-stopped"
    assert not list(state_parent.glob(".recovery-rebirth-snapshot-*"))


def test_non_private_state_parent_uses_process_temp_before_state_creation(
    short_tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _recovery_fixture(short_tmp_path)
    transfer = short_tmp_path / "custody-free-shared-parent-transfer"
    recovery_rebirth.export_recovery_snapshot(fixture["snapshot"], transfer)
    shared_parent = short_tmp_path / "shared-parent"
    shared_parent.mkdir(mode=0o755)
    shared_parent.chmod(0o755)
    state = shared_parent / "cluster-state"
    real_mkdtemp = recovery_rebirth.tempfile.mkdtemp
    observed_staging: list[tuple[str, str | os.PathLike[str] | None]] = []

    def capture_mkdtemp(
        *, prefix: str, dir: str | os.PathLike[str] | None = None
    ) -> str:
        observed_staging.append((prefix, dir))
        return real_mkdtemp(prefix=prefix, dir=dir)

    monkeypatch.setattr(recovery_rebirth.tempfile, "mkdtemp", capture_mkdtemp)
    result = recovery_rebirth.install_recovery_rebirth(
        state,
        fixture["package"],
        transfer,
        lambda: bytearray(fixture["password"]),
        idempotency_key=str(uuid.uuid4()),
    )
    assert result["state"] == "installed-restored-stopped"
    assert [
        parent
        for prefix, parent in observed_staging
        if prefix == ".recovery-rebirth-snapshot-"
    ] == [None]
    assert not list(shared_parent.glob(".recovery-rebirth-snapshot-*"))


def test_snapshot_replacement_race_refuses_before_state_creation(
    short_tmp_path, monkeypatch
):
    fixture = _recovery_fixture(short_tmp_path)
    source_ledger = fixture["snapshot"] / "payload/ledger.sqlite"
    original_ledger = fixture["snapshot"] / "payload/ledger-original.sqlite"
    outside = short_tmp_path / "outside-ledger.sqlite"
    outside.write_bytes(b"must-not-be-read")
    outside.chmod(0o600)
    state = short_tmp_path / "race-rejected-state"
    real_stage = recovery_rebirth._stage_snapshot_file
    swapped = False

    def swap_before_stage(source, destination, row, *, capture=False):
        nonlocal swapped
        if source == source_ledger:
            swapped = True
            source_ledger.rename(original_ledger)
            source_ledger.symlink_to(outside)
        return real_stage(source, destination, row, capture=capture)

    monkeypatch.setattr(recovery_rebirth, "_stage_snapshot_file", swap_before_stage)
    with pytest.raises(
        recovery_rebirth.RecoveryRebirthError, match="snapshot_rejected"
    ):
        recovery_rebirth.install_recovery_rebirth(
            state,
            fixture["package"],
            fixture["snapshot"],
            lambda: bytearray(fixture["password"]),
            idempotency_key=str(uuid.uuid4()),
        )
    assert swapped is True
    assert not state.exists()
    assert not list(short_tmp_path.glob(".recovery-rebirth-snapshot-*"))
