"""H3 exact durable-volume relocation and crash recovery."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_park import NAME, _exec_handler, _Kill, _write_spec
from test_transfer import NEW, _cli, _declare_running_embodiment, _parked

from clusterctl import transfer
from clusterctl.adapters import FakeAdapter, IncusAdapter, IncusError
from clusterctl.config import Config
from clusterctl.fences import Ed25519Signer, ResourceFenceStore
from clusterctl.operation_journal import OperationJournal
from clusterctl.production_fences import (
    create_holder_authorization,
    create_holder_enrollment,
    ed25519_fingerprint,
)


def _fixture(tmp_path, adapter_type=FakeAdapter):
    state_dir = tmp_path / "state"
    cfg = Config(
        host_id="test-host",
        incus_project="default",
        managed_prefix="",
        profile="tribe-agent",
        state_dir=str(state_dir),
    )
    adapter = adapter_type(
        instances=[
            {
                "name": NAME,
                "state": "running",
                "image_version": "tribe-base/test",
                "budgets": {},
                "uptime_s": 5,
            }
        ],
        exec_handler=_exec_handler,
    )
    _write_spec(state_dir)
    _parked(state_dir, cfg, adapter)
    return state_dir, cfg, adapter


def test_real_volume_identity_moves_once_and_is_bound_to_receipt(tmp_path):
    _state_dir, cfg, adapter = _fixture(tmp_path)
    before = adapter.volume_observation(f"{NAME}-home")
    result = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    after = adapter.volume_observation(f"{NAME}-home")
    expected = [
        {
            "instance": NEW,
            "device": "home",
            "path": "/home/agent",
            "writable": True,
        }
    ]
    assert before["identity"] == after["identity"] == result["volume_identity"]
    assert before["content_sha256"] == after["content_sha256"]
    assert after["attachments"] == expected
    log = adapter.mutation_log
    assert log.index(("detach_volume", f"{NAME}-home", NAME, "home")) < log.index(
        ("attach_volume", f"{NAME}-home", NEW, "home", "/home/agent")
    ) < log.index(("start", NEW))
    receipt = json.loads(Path(result["transfer_record"]).read_text())
    assert receipt["volume_identity"] == before["identity"]
    assert receipt["volume_before"]["attachments"][0]["instance"] == NAME
    assert receipt["volume_after"]["attachments"][0]["instance"] == NEW


@pytest.mark.parametrize("boundary", transfer.TRANSFER_STEPS)
def test_every_transfer_step_crash_resumes_one_attachment(tmp_path, boundary):
    _state_dir, cfg, adapter = _fixture(tmp_path)

    def crash(step):
        if step == boundary:
            raise _Kill(step)

    with pytest.raises(_Kill):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test", on_step=crash)
    during = adapter.volume_observation(f"{NAME}-home")
    assert len(during["attachments"]) <= 1
    result = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    final = adapter.volume_observation(f"{NAME}-home")
    assert final["identity"] == result["volume_identity"]
    assert [item["instance"] for item in final["attachments"]] == [NEW]


class _LostVolumeResponse(FakeAdapter):
    lose_method = ""

    def detach_volume(self, *args, **kwargs):
        result = super().detach_volume(*args, **kwargs)
        if self.lose_method == "detach":
            self.lose_method = ""
            raise RuntimeError("lost detach response")
        return result

    def attach_volume(self, *args, **kwargs):
        result = super().attach_volume(*args, **kwargs)
        if self.lose_method == "attach" and args[1] == NEW:
            self.lose_method = ""
            raise RuntimeError("lost attach response")
        return result


class _ContainerCrash(BaseException):
    pass


class _LostContainerResponse(FakeAdapter):
    lose_method = ""

    def create_instance(self, *args, **kwargs):
        result = super().create_instance(*args, **kwargs)
        if self.lose_method in {"create", "create-crash"}:
            fault = self.lose_method
            self.lose_method = ""
            if fault == "create-crash":
                raise _ContainerCrash
            raise RuntimeError("lost create response")
        return result

    def start(self, *args, **kwargs):
        result = super().start(*args, **kwargs)
        if self.lose_method in {"start", "start-crash"} and args[0] == NEW:
            fault = self.lose_method
            self.lose_method = ""
            if fault == "start-crash":
                raise _ContainerCrash
            raise RuntimeError("lost start response")
        return result


@pytest.mark.parametrize(
    "lost", ["create", "start", "create-crash", "start-crash"]
)
def test_create_start_response_loss_converges_once(tmp_path, lost):
    if lost.startswith("start"):
        state_dir = tmp_path / "state"
        cfg = Config(
            host_id="test-host",
            incus_project="default",
            managed_prefix="",
            profile="tribe-agent",
            state_dir=str(state_dir),
        )
        adapter = _LostContainerResponse(
            instances=[
                {
                    "name": NAME,
                    "state": "running",
                    "image_version": "tribe-base/test",
                    "budgets": {},
                    "uptime_s": 5,
                }
            ],
            exec_handler=_exec_handler,
        )
        embodiment, first = _declare_running_embodiment(state_dir)
        _parked(state_dir, cfg, adapter)
    else:
        state_dir, cfg, adapter = _fixture(tmp_path, _LostContainerResponse)
    adapter.lose_method = lost
    if lost.endswith("crash"):
        with pytest.raises(_ContainerCrash):
            transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    result = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    assert result["result"] == "ok"
    assert sum(call == ("create_instance", NEW) for call in adapter.mutation_log) == 1
    assert sum(call == ("start", NEW) for call in adapter.mutation_log) == 1
    if lost.startswith("start"):
        current = transfer.embodiments.Registry(state_dir).status(
            embodiment["embodiment_id"]
        )
        assert result["incarnation_id"] is None
        assert current["current_incarnation_id"] == first["incarnation_id"]

@pytest.mark.parametrize("lost", ["detach", "attach"])
def test_detach_attach_response_loss_resumes_from_observed_truth(tmp_path, lost):
    _state_dir, cfg, adapter = _fixture(tmp_path, _LostVolumeResponse)
    adapter.lose_method = lost
    with pytest.raises(RuntimeError, match="lost .* response"):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    result = transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    final = adapter.volume_observation(f"{NAME}-home")
    assert final["identity"] == result["volume_identity"]
    assert [item["instance"] for item in final["attachments"]] == [NEW]


def test_identity_change_after_target_creation_rolls_back_or_stays_degraded(tmp_path):
    _state_dir, cfg, adapter = _fixture(tmp_path)

    def crash(step):
        if step == "target-create":
            raise _Kill(step)

    with pytest.raises(_Kill):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test", on_step=crash)
    adapter._volume_records[f"{NAME}-home"]["identity"] = "volume:replacement"
    with pytest.raises(transfer.TransferError) as raised:
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    rollback = raised.value.detail["rollback"]
    assert rollback["attachment_safe"] is False
    assert rollback["target_destroyed"] is False
    assert adapter._find(NEW)["state"] == "stopped"


def test_wrong_or_multiply_attached_volume_refuses_before_target_start(tmp_path):
    _state_dir, cfg, adapter = _fixture(tmp_path)
    adapter._volume_records[f"{NAME}-home"]["attachments"].append(
        {
            "instance": "rogue-instance",
            "device": "home",
            "path": "/home/agent",
            "writable": True,
        }
    )
    with pytest.raises(transfer.TransferRefused, match="attachment"):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    assert not any(call == ("start", NEW) for call in adapter.mutation_log)


def test_preexisting_stopped_target_without_attachment_is_not_adopted(tmp_path):
    _state_dir, cfg, adapter = _fixture(tmp_path)
    adapter.create_instance(NEW, "tribe-base/test", "tribe-agent")
    adapter.mutation_log.clear()
    with pytest.raises(transfer.TransferRefused, match="outside this transfer"):
        transfer.run_transfer(NAME, NEW, cfg, adapter, actor="test")
    assert adapter._find(NEW)["state"] == "stopped"
    assert not any(call[0] == "detach_volume" for call in adapter.mutation_log)


def test_target_lock_blocks_transfer_before_storage_mutation(tmp_path):
    state_dir, _cfg, adapter = _fixture(tmp_path)
    lock_dir = state_dir / "locks"
    lock_dir.mkdir(parents=True)
    (lock_dir / f"{NEW}.lock").write_text(
        json.dumps(
            {"operation": "create", "pid": os.getpid(), "ts_ms": int(time.time() * 1000)}
        ),
        encoding="utf-8",
    )
    adapter.mutation_log.clear()
    code, _out, _err = _cli(
        state_dir,
        "transfer",
        NAME,
        "--to",
        NEW,
        "--idempotency-key",
        "99999999-9999-4999-8999-999999999999",
        "--json",
        adapter=adapter,
    )
    assert code == 6
    assert not any(call[0] in {"detach_volume", "attach_volume"} for call in adapter.mutation_log)
    assert not (lock_dir / f"{NAME}.lock").exists()


def test_same_source_and_target_refuses_without_lock_or_mutation(tmp_path):
    state_dir, _cfg, adapter = _fixture(tmp_path)
    adapter.mutation_log.clear()
    code, _out, _err = _cli(
        state_dir,
        "transfer",
        NAME,
        "--to",
        NAME,
        "--idempotency-key",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "--json",
        adapter=adapter,
    )
    assert code == 6
    assert adapter.mutation_log == []
    assert not (state_dir / "locks" / f"{NAME}.lock").exists()


def test_outer_journal_closes_manifest_volume_and_fence_position(tmp_path):
    state_dir, _cfg, adapter = _fixture(tmp_path)
    before = adapter.volume_observation(f"{NAME}-home")
    code, out, _err = _cli(
        state_dir,
        "transfer",
        NAME,
        "--to",
        NEW,
        "--idempotency-key",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "--json",
        adapter=adapter,
    )
    assert code == 6
    assert out == ""
    assert adapter.volume_observation(f"{NAME}-home") == before


def _ed25519_signer(path: Path, key_id: str) -> Ed25519Signer:
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


class _FenceCrash(BaseException):
    pass


@pytest.mark.parametrize(
    "fault", [None, "response-loss", "process-crash", "target-start-failure"]
)
def test_transfer_binds_and_advances_exact_production_fence_position(
    tmp_path, fault
):
    state_dir, cfg, adapter = _fixture(tmp_path)
    owner = _ed25519_signer(tmp_path / "owner.pem", "cluster-owner-test")
    holder = _ed25519_signer(tmp_path / "holder.pem", "holder-test")
    store = ResourceFenceStore.production(
        state_dir / "production-fence",
        signer=owner,
        key_id=owner.key_id,
        holder_registrars={owner.key_id: owner.public_key},
    )
    resource_ref = NAME + "@daimonmatrix"
    now_ms = int(time.time() * 1000)
    store.admit_holder(
        create_holder_enrollment(
            owner,
            holder_key_id=holder.key_id,
            holder_pubkey=holder.public_key,
            being_ref="dm:being:volume-relocation-test",
            body_ref=resource_ref,
            embodiment_id="embodiment:11111111-1111-4111-8111-111111111111",
            incarnation_id="incarnation:22222222-2222-4222-8222-222222222222",
            activation_id="dm:activation:volume-relocation-test",
            credential_id="dm:credential:volume-relocation-test",
            manifest_hash="sha256:" + "a" * 64,
            issued_ms=now_ms - 1,
            nonce="volume-relocation-holder-enrollment",
        )
    )
    empty = store.position(resource_ref)
    acquire_auth = create_holder_authorization(
        holder,
        operation="acquire",
        body_ref=resource_ref,
        embodiment_id="embodiment:11111111-1111-4111-8111-111111111111",
        incarnation_id="incarnation:22222222-2222-4222-8222-222222222222",
        resource_ref=resource_ref,
        expected_epoch=empty["epoch"],
        expected_proof=empty["proof"],
        issued_ms=now_ms - 1,
        ttl_s=60,
        nonce="h3-acquire",
    )
    store.acquire(
        resource_ref,
        holder.public_key,
        ed25519_fingerprint(holder.public_key),
        holder_embodiment_id="embodiment:11111111-1111-4111-8111-111111111111",
        body_ref=resource_ref,
        holder_incarnation_id="incarnation:22222222-2222-4222-8222-222222222222",
        holder_key_id=holder.key_id,
        expected_epoch=empty["epoch"],
        expected_proof=empty["proof"],
        authorization=acquire_auth,
    )
    before = store.position(resource_ref)

    def renew(production_store, resource, expected):
        issued = int(time.time() * 1000)
        authorization = create_holder_authorization(
            holder,
            operation="renew",
            body_ref=resource_ref,
            embodiment_id="embodiment:11111111-1111-4111-8111-111111111111",
            incarnation_id="incarnation:22222222-2222-4222-8222-222222222222",
            resource_ref=resource,
            expected_epoch=expected["epoch"],
            expected_proof=expected["proof"],
            issued_ms=issued,
            ttl_s=60,
            nonce="h3-renew",
        )
        result = production_store.renew(
            resource,
            expected_epoch=expected["epoch"],
            expected_proof=expected["proof"],
            authorization=authorization,
        )
        if fault == "response-loss":
            raise RuntimeError("lost fence response")
        if fault == "process-crash":
            raise _FenceCrash
        return result

    call = {
        "actor": "test",
        "fence_store": store,
        "expected_fence_position": before,
        "fence_transition": renew,
    }
    if fault == "target-start-failure":
        original_start = adapter.start

        def fail_target_start(name):
            if name == NEW:
                raise RuntimeError("synthetic production target start failure")
            return original_start(name)

        adapter.start = fail_target_start
        with pytest.raises(transfer.TransferError):
            transfer.run_transfer(NAME, NEW, cfg, adapter, **call)
        after = store.position(resource_ref)
        assert after["epoch"] == before["epoch"] + 1
        assert adapter._find(NEW) is None
        assert adapter.volume_observation(f"{NAME}-home")["attachments"] == [
            {
                "instance": NAME,
                "device": "home",
                "path": "/home/agent",
                "writable": True,
            }
        ]
        rollback = json.loads(
            transfer._transfer_state_path(cfg, NAME, NEW).read_text()
        )["rollback"]
        assert rollback["fence_safe"] is True
        assert rollback["fence_advanced"] is True
        return
    if fault == "process-crash":
        with pytest.raises(_FenceCrash):
            transfer.run_transfer(NAME, NEW, cfg, adapter, **call)
        call["fence_transition"] = lambda *_args: pytest.fail(
            "committed fence successor must be recovered without redispatch"
        )
    result = transfer.run_transfer(NAME, NEW, cfg, adapter, **call)
    after = store.position(resource_ref)
    assert after["epoch"] == before["epoch"] + 1 == result["fence_epoch"]
    receipt = json.loads(Path(result["transfer_record"]).read_text())
    assert receipt["fence_before"] == before


class _RollbackAttachmentFailure(FakeAdapter):
    def start(self, name):
        if name == NEW:
            raise RuntimeError("synthetic target start failure")
        return super().start(name)

    def attach_volume(self, volume_name, instance, **kwargs):
        if instance == NAME and self._find(NEW) is not None:
            raise RuntimeError("synthetic source reattach failure")
        return super().attach_volume(volume_name, instance, **kwargs)


def test_rollback_attachment_failure_stays_degraded_and_target_stopped(
    tmp_path, capsys
):
    state_dir, _cfg, adapter = _fixture(tmp_path, _RollbackAttachmentFailure)
    code, _out, _err = _cli(
        state_dir,
        "transfer",
        NAME,
        "--to",
        NEW,
        "--idempotency-key",
        "77777777-7777-4777-8777-777777777777",
        "--json",
        adapter=adapter,
    )
    assert code == 6
    assert OperationJournal.existing(state_dir) is None
    assert NEW not in {row["name"] for row in adapter.list_instances()}
    capsys.readouterr()


def test_incus_volume_primitives_observe_exact_device_and_identity():
    devices = {
        NAME: {
            "home": {
                "type": "disk",
                "pool": "default",
                "source": f"{NAME}-home",
                "path": "/home/agent",
            }
        },
        NEW: {},
    }
    commands = []

    def runner(argv):
        command = argv[:-2] if argv[-2:] == ["--project", "default"] else argv
        commands.append(command)
        args = command[1:]
        if args[:4] == ["storage", "volume", "show", "default"]:
            attached = [name for name, value in devices.items() if value]
            return yaml.safe_dump(
                {
                    "name": f"{NAME}-home",
                    "type": "custom",
                    "content_type": "filesystem",
                    "project": "default",
                    "created_at": "2026-08-10T00:00:00Z",
                    "used_by": [f"/1.0/instances/{name}" for name in attached],
                }
            )
        if args[:3] == ["config", "device", "show"]:
            return yaml.safe_dump(devices[args[3]])
        if args[:4] == ["storage", "volume", "detach", "default"]:
            devices[args[5]].pop(args[6])
            return ""
        if args[:4] == ["storage", "volume", "attach", "default"]:
            volume, instance, device, path = args[4:8]
            devices[instance][device] = {
                "type": "disk",
                "pool": "default",
                "source": volume,
                "path": path,
            }
            return ""
        raise AssertionError(command)

    adapter = IncusAdapter(runner=runner)
    before = adapter.volume_observation(f"{NAME}-home")
    detached = adapter.detach_volume(f"{NAME}-home", NAME)
    after = adapter.attach_volume(f"{NAME}-home", NEW)
    assert before["identity"] == detached["identity"] == after["identity"]
    assert detached["attachments"] == []
    assert [item["instance"] for item in after["attachments"]] == [NEW]
    assert ["incus", "storage", "volume", "detach", "default", f"{NAME}-home", NAME, "home"] in commands
    assert ["incus", "storage", "volume", "attach", "default", f"{NAME}-home", NEW, "home", "/home/agent"] in commands


def test_incus_attach_rejects_contradictory_existing_device():
    adapter = IncusAdapter(runner=lambda _argv: "")
    adapter.volume_observation = lambda _name: {
        "present": True,
        "attachments": [
            {
                "instance": NEW,
                "device": "other",
                "path": "/srv",
                "writable": True,
            }
        ],
    }
    with pytest.raises(IncusError, match="contradictory"):
        adapter.attach_volume(f"{NAME}-home", NEW)
