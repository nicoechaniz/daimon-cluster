from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

import pytest
import yaml
from test_admission import _key
from test_park import NAME, _exec_handler, _spec_dict

from clusterctl import lifecycle, park, transfer
from clusterctl.adapters import FakeAdapter
from clusterctl.admission import (
    AdmissionAuthority,
    AdmissionServer,
    FenceMutationClient,
    serve_in_thread,
)
from clusterctl.cli import run
from clusterctl.config import Config
from clusterctl.production_fences import create_holder_enrollment


def _production_handoff(tmp_path: Path):
    def clock() -> int:
        return time.time_ns() // 1_000_000

    authority_signer = _key(tmp_path / "keys/authority.pem", "authority")
    registrar = _key(tmp_path / "keys/registrar.pem", "registrar")
    holder = _key(tmp_path / "keys/holder.pem", "holder")
    identity = {
        "being_ref": "dm:being:handoff",
        "body_ref": "cluster:body:handoff",
        "embodiment_id": "dm:embodiment:handoff",
        "incarnation_id": "dm:incarnation:handoff",
        "activation_id": "dm:activation:handoff",
        "credential_id": "dm:credential:handoff",
        "manifest_hash": "sha256:handoff",
    }
    authority = AdmissionAuthority(
        tmp_path / "authority",
        signer=authority_signer,
        holder_registrars={registrar.key_id: registrar.public_key},
        clock=clock,
    )
    server = AdmissionServer(tmp_path / "run/authority.sock", authority)
    thread = serve_in_thread(server)
    client = FenceMutationClient(
        tmp_path / "run/authority.sock",
        holder_signer=holder,
        authority_key_id=authority_signer.key_id,
        authority_public_key=authority_signer.public_key,
        being_ref=identity["being_ref"],
        body_ref=identity["body_ref"],
        embodiment_id=identity["embodiment_id"],
        incarnation_id=identity["incarnation_id"],
        activation_id=identity["activation_id"],
        credential_id=identity["credential_id"],
        manifest_hash=identity["manifest_hash"],
    )
    client.enroll(
        create_holder_enrollment(
            registrar,
            holder_key_id=holder.key_id,
            holder_pubkey=holder.public_key,
            being_ref=identity["being_ref"],
            body_ref=identity["body_ref"],
            embodiment_id=identity["embodiment_id"],
            incarnation_id=identity["incarnation_id"],
            activation_id=identity["activation_id"],
            credential_id=identity["credential_id"],
            manifest_hash=identity["manifest_hash"],
            issued_ms=clock(),
            nonce=str(uuid.uuid4()),
        )
    )
    state = tmp_path / "host"
    (state / "instances").mkdir(parents=True)
    spec = _spec_dict(
        daimon_id=identity["body_ref"],
        instance_kind="generic-instance",
        fence_holder=identity,
    )
    spec_path = state / "instances" / f"{NAME}.yaml"
    spec_path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    config_path = state / "admission-client.json"
    config_path.write_text(
        json.dumps({
            "schema": "dm.cluster.admission-client/v1",
            "endpoint": {
                "transport": "unix-local-fixture",
                "path": str(tmp_path / "run/authority.sock"),
            },
            "holder_key_path": str(tmp_path / "keys/holder.pem"),
            "holder_key_id": holder.key_id,
            "authority_key_id": authority_signer.key_id,
            "authority_public_key": authority_signer.public_key,
            "lease_ttl_s": 60,
        }),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    cfg = Config("host", "default", "", "profile", str(state))
    adapter = FakeAdapter(
        instances=[{
            "name": NAME, "state": "running", "image_version": "tribe-base/test",
            "budgets": {}, "uptime_s": 1,
        }],
        exec_handler=_exec_handler,
    )
    adapter.ensure_volume(NAME)
    client.commit(client.prepare(identity["body_ref"], operation="acquire", ttl_s=60))
    return server, thread, client, holder, identity, cfg, adapter, spec_path


class _OuterCrash(BaseException):
    pass


@pytest.mark.parametrize(
    "boundary",
    [
        "after-plan", "after-runtime-dispatch-persist", "after-runtime-observation",
        "after-logical-commit", "after-idempotency", "after-audit", "after-completed",
    ],
)
def test_production_park_outer_journal_recovers_every_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    server, thread, _client, _holder, _identity, cfg, adapter, _ = (
        _production_handoff(tmp_path)
    )
    key = "55555555-5555-4555-8555-555555555555"

    def crash(observed: str, _record: dict) -> None:
        if observed == boundary:
            raise _OuterCrash

    try:
        monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", crash)
        with pytest.raises(_OuterCrash):
            run([
                "--state-dir", cfg.state_dir, "park", "--handoff", NAME,
                "--idempotency-key", key, "--json",
            ], adapter=adapter)
        monkeypatch.setattr(lifecycle, "_MUTATION_BOUNDARY_HOOK", None)
        assert run([
            "--state-dir", cfg.state_dir, "park", "--handoff", NAME,
            "--idempotency-key", key, "--json",
        ], adapter=adapter) == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_production_park_wake_uses_enrollment_ed25519_and_exact_cas(tmp_path: Path):
    server, thread, client, holder, identity, cfg, adapter, _ = _production_handoff(
        tmp_path
    )
    try:
        parked = park.run_park(
            NAME, cfg, adapter, actor="test", signer=holder, fence_store=client
        )
        assert parked["checkpoint"]["resource_fence_receipt"]["authority_key_id"]
        woken = transfer.run_wake(
            NAME, cfg, adapter, actor="test", signer=holder, fence_store=client
        )
        assert woken["fence_epoch"] == 1
        wake_record = json.loads(Path(woken["wake_record"]).read_text())
        assert wake_record["outputs"]["prepared_fence"]["successor_epoch"] == 1
        assert client.position(identity["body_ref"])["epoch"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_production_transfer_commits_cas_before_adapter_mutation(tmp_path: Path):
    server, thread, client, holder, identity, cfg, adapter, _ = _production_handoff(
        tmp_path
    )
    try:
        park.run_park(NAME, cfg, adapter, actor="test", signer=holder, fence_store=client)
        adapter.mutation_log.clear()
        result = transfer.run_transfer(
            NAME, "daimon-y", cfg, adapter, actor="test",
            signer=holder, fence_store=client,
        )
        state = json.loads(transfer._transfer_state_path(cfg, NAME, "daimon-y").read_text())
        assert state["completed"][:3] == [
            "verify-manifest", "fence-prepared", "fence",
        ]
        assert state["outputs"]["prepared_fence"]["successor_epoch"] == 1
        assert result["fence_epoch"] == 1
        assert adapter.mutation_log[0] == ("create_instance", "daimon-y")
        assert client.position(identity["body_ref"])["epoch"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_missing_handoff_authority_has_zero_adapter_calls_and_unchanged_spec(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    (state / "instances").mkdir(parents=True)
    spec_path = state / "instances" / f"{NAME}.yaml"
    spec_path.write_text(
        yaml.safe_dump(_spec_dict(instance_kind="generic-instance"), sort_keys=False),
        encoding="utf-8",
    )
    before = spec_path.read_bytes()
    adapter = FakeAdapter(
        instances=[{"name": NAME, "state": "running", "budgets": {}}],
        exec_handler=_exec_handler,
    )
    assert run(
        ["--state-dir", str(state), "park", "--handoff", NAME], adapter=adapter
    ) == 6
    assert adapter.mutation_log == []
    assert spec_path.read_bytes() == before


@pytest.mark.parametrize("operation", ["wake", "transfer"])
@pytest.mark.parametrize("fence_record_persisted", [False, True])
def test_retry_after_exact_fence_commit_recovers_without_second_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    fence_record_persisted: bool,
) -> None:
    server, thread, client, holder, identity, cfg, adapter, _ = _production_handoff(
        tmp_path
    )
    key = "77777777-7777-4777-8777-777777777777"
    class _FenceCrash(BaseException):
        pass

    try:
        park.run_park(
            NAME, cfg, adapter, actor="test", signer=holder, fence_store=client
        )
        adapter.mutation_log.clear()
        renew_calls = 0
        original_renew = server.authority._store.renew

        def counted_renew(*args, **kwargs):
            nonlocal renew_calls
            renew_calls += 1
            return original_renew(*args, **kwargs)

        monkeypatch.setattr(server.authority._store, "renew", counted_renew)
        target = "daimon-y"
        real_runner = transfer.run_wake if operation == "wake" else transfer.run_transfer

        def crash_after_fence(step: str) -> None:
            if step == "fence":
                raise _FenceCrash

        def crashing_runner(*args, **kwargs):
            kwargs["on_step"] = crash_after_fence
            return real_runner(*args, **kwargs)

        original_commit = FenceMutationClient.commit
        commit_crashed = False

        def commit_then_crash(self, prepared):
            nonlocal commit_crashed
            receipt = original_commit(self, prepared)
            if not commit_crashed:
                commit_crashed = True
                raise _FenceCrash
            return receipt

        if fence_record_persisted:
            monkeypatch.setattr(
                transfer,
                "run_wake" if operation == "wake" else "run_transfer",
                crashing_runner,
            )
        else:
            monkeypatch.setattr(FenceMutationClient, "commit", commit_then_crash)
        command = (
            ["wake", "--handoff", NAME]
            if operation == "wake"
            else ["transfer", NAME, "--to", target]
        )
        argv = [
            "--state-dir", cfg.state_dir, *command,
            "--idempotency-key", key, "--json",
        ]
        with pytest.raises(_FenceCrash):
            run(argv, adapter=adapter)
        assert renew_calls == 1
        assert client.position(identity["body_ref"])["epoch"] == 1

        if fence_record_persisted:
            monkeypatch.setattr(
                transfer,
                "run_wake" if operation == "wake" else "run_transfer",
                real_runner,
            )
        else:
            monkeypatch.setattr(FenceMutationClient, "commit", original_commit)
        assert run(argv, adapter=adapter) == 0
        assert renew_calls == 1
        assert client.position(identity["body_ref"])["epoch"] == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("operation", ["wake", "transfer"])
def test_matrix_handoff_requires_external_authorized_successor_before_fence(
    tmp_path: Path,
    operation: str,
) -> None:
    server, thread, client, holder, identity, cfg, adapter, spec_path = (
        _production_handoff(tmp_path)
    )
    try:
        park.run_park(
            NAME, cfg, adapter, actor="test", signer=holder, fence_store=client
        )
        spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
        spec.update({
            "instance_kind": "matrix-embodiment",
            "being_ref": identity["being_ref"],
            "body_ref": identity["body_ref"],
            "embodiment_id": identity["embodiment_id"],
            "current_incarnation_id": identity["incarnation_id"],
            "activation_id": identity["activation_id"],
            "credential_id": identity["credential_id"],
            "manifest_hash": identity["manifest_hash"],
        })
        spec_path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
        before = spec_path.read_bytes()
        before_position = client.position(identity["body_ref"])
        adapter.mutation_log.clear()
        command = (
            ["wake", "--handoff", NAME]
            if operation == "wake"
            else ["transfer", NAME, "--to", "daimon-y"]
        )
        assert run(
            ["--state-dir", cfg.state_dir, *command, "--json"], adapter=adapter
        ) == 6
        with pytest.raises(
            transfer.TransferRefused, match="root/activation-authorized successor"
        ):
            if operation == "wake":
                transfer.run_wake(
                    NAME, cfg, adapter, actor="test",
                    signer=holder, fence_store=client,
                )
            else:
                transfer.run_transfer(
                    NAME, "daimon-y", cfg, adapter, actor="test",
                    signer=holder, fence_store=client,
                )
        assert client.position(identity["body_ref"]) == before_position
        assert adapter.mutation_log == []
        assert spec_path.read_bytes() == before
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_park_revalidates_revocation_under_lock_before_any_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, thread, _client, holder, _identity, cfg, adapter, spec_path = (
        _production_handoff(tmp_path)
    )
    real_lock = park._lock_or_fail

    class RevokingLock:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def __enter__(self):
            acquired = self.wrapped.__enter__()
            server.authority._store.revoke_holder_key(holder.key_id)
            return acquired

        def __exit__(self, *args):
            return self.wrapped.__exit__(*args)

    def lock_and_revoke(*args, **kwargs):
        wrapped = real_lock(*args, **kwargs)
        return wrapped if isinstance(wrapped, int) else RevokingLock(wrapped)

    try:
        monkeypatch.setattr(park, "_lock_or_fail", lock_and_revoke)
        before = spec_path.read_bytes()
        adapter.mutation_log.clear()
        assert run(
            ["--state-dir", cfg.state_dir, "park", "--handoff", NAME, "--json"],
            adapter=adapter,
        ) == 6
        assert adapter.mutation_log == []
        assert spec_path.read_bytes() == before
        assert not (Path(cfg.state_dir) / "operation-journal.sqlite3").exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
