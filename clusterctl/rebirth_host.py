"""Foreground supervisor for an installed root-authorized fresh embodiment."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import audit
from .admission import (
    DEFAULT_LEASE_TTL_S,
    AdmissionClient,
    AdmissionEndpoint,
    AdmissionError,
)
from .embodiments import Registry, RegistryError
from .locks import acquire
from .matrix_host import MATRIX_CONTRACT_COMMIT, _matrix_api, matrix_client, matrix_root
from .operation_journal import OperationJournal
from .rebirth import RebirthInstallError, _owner_directory, _read_json

RESULT_SCHEMA = "dm.cluster.rebirth-host-result/v1"
ADMISSION_CLIENT_SCHEMA = "dm.cluster.admission-client/v1"
_SUPERVISORS: dict[int, _AdmissionSupervisor] = {}
_SUPERVISORS_LOCK = threading.Lock()


class RebirthHostError(RuntimeError):
    """Stable refusal at the fresh-embodiment process boundary."""


def _installed_identity(state: Path, embodiment_id: str) -> dict[str, Any]:
    root = _owner_directory(matrix_root(state, embodiment_id))
    bundle = _read_json(root / "runtime.json")
    try:
        authority = _matrix_api()["operator_rebirth"].authority_from_runtime_bundle(
            bundle
        )
        origin = bundle["local_origin"]
    except Exception as exception:
        raise RebirthHostError("rebirth_host_runtime_rejected") from exception
    if not isinstance(origin, dict) or origin.get("embodiment_id") != embodiment_id:
        raise RebirthHostError("rebirth_host_runtime_rejected")
    journal = OperationJournal(state)
    install = journal.latest_completed_for_result(
        "rebirth-install", "embodiment_id", embodiment_id
    )
    result = None if install is None else install.get("result")
    if not isinstance(result, dict):
        raise RebirthHostError("rebirth_host_install_receipt_missing")
    activation_id = result.get("activation_id")
    if not isinstance(activation_id, str):
        raise RebirthHostError("rebirth_host_install_receipt_missing")
    install_target = f"rebirth:{authority.manifest.being_ref}:{activation_id}"
    if (
        install is None
        or install["target"] != install_target
        or install["operation"] != "rebirth-install"
        or install["state"] != "completed"
        or result.get("embodiment_id") != embodiment_id
        or result.get("incarnation_id") != origin.get("incarnation_id")
        or result.get("successor_manifest_hash") != authority.manifest.digest
    ):
        raise RebirthHostError("rebirth_host_install_receipt_missing")
    rollout_id = result.get("rollout_id")
    participants = result.get("participant_embodiment_ids")
    admission_required = result.get("admission_required")
    rollout_gate: dict[str, Any] | None = None
    if any(
        value is not None for value in (rollout_id, participants, admission_required)
    ):
        if (
            not isinstance(rollout_id, str)
            or not isinstance(participants, list)
            or not participants
            or participants != sorted(participants)
            or len(participants) != len(set(participants))
            or not all(isinstance(item, str) and item for item in participants)
            or admission_required is not True
        ):
            raise RebirthHostError("rebirth_host_install_receipt_missing")
        rollout_gate = {
            "rollout_id": rollout_id,
            "participant_embodiment_ids": participants,
        }
    history = bundle.get("authority_history")
    last_successor = (
        history[-1].get("successor")
        if isinstance(history, list) and history and isinstance(history[-1], dict)
        else None
    )
    recovery_gate = bool(
        isinstance(last_successor, dict)
        and last_successor.get("schema") == "dm.we.recovery-rebirth/v1"
    )
    try:
        member = next(
            row
            for row in authority.manifest.value["embodiments"]
            if row.get("embodiment_id") == embodiment_id
        )
        credential_id = member["embodiment_credential_id"]
    except (KeyError, StopIteration, TypeError) as exception:
        raise RebirthHostError("rebirth_host_runtime_rejected") from exception
    if not isinstance(credential_id, str) or not credential_id:
        raise RebirthHostError("rebirth_host_runtime_rejected")
    return {
        "activation_id": activation_id,
        "being_ref": authority.manifest.being_ref,
        "manifest_hash": authority.manifest.digest,
        "credential_id": credential_id,
        "origin": dict(origin),
        "rollout_gate": rollout_gate,
        "recovery_gate": recovery_gate,
    }


def _response(call: Any, code: str) -> dict[str, Any]:
    try:
        response = call()[1]
    except Exception as exception:
        raise RebirthHostError(code) from exception
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        raise RebirthHostError(code)
    return response["result"]


def _verify_ready(state: Path, identity: Mapping[str, Any]) -> dict[str, Any]:
    origin = identity["origin"]
    embodiment_id = origin["embodiment_id"]
    try:
        client = matrix_client(state, embodiment_id)
    except Exception as exception:
        raise RebirthHostError("rebirth_host_client_rejected") from exception
    status = _response(client.runtime_status, "rebirth_host_status_rejected")
    me = _response(client.scope_me, "rebirth_host_me_rejected")
    we = _response(client.scope_we, "rebirth_host_we_rejected")
    active_ids = {
        row.get("embodiment_id")
        for row in we.get("embodiments", [])
        if isinstance(row, dict) and row.get("manifest_status") == "active"
    }
    if (
        status.get("integrity") != "ok"
        or status.get("being_ref") != identity["being_ref"]
        or status.get("manifest_hash") != identity["manifest_hash"]
        or status.get("local_origin") != origin
        or me.get("origin") != origin
        or me.get("body", {}).get("state") != "running"
        or embodiment_id not in active_ids
    ):
        raise RebirthHostError("rebirth_host_readiness_mismatch")
    return {
        "integrity": "ok",
        "active_embodiment_ids": sorted(active_ids),
    }


def _wait_ready(
    descriptor: int, process: subprocess.Popen[bytes], timeout_s: float
) -> None:
    selector = selectors.DefaultSelector()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        events = selector.select(timeout_s)
        ready = os.read(descriptor, 64) if events else b""
    finally:
        selector.close()
        os.close(descriptor)
    if ready != b"READY\n":
        if process.poll() is None:
            process.terminate()
        try:
            _stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            _stdout, stderr = process.communicate(timeout=10)
        diagnostic = "rebirth_host_startup_refused"
        if 1 <= len(stderr) <= 4096:
            try:
                value = json.loads(stderr)
                code = value.get("code") if isinstance(value, dict) else None
                if isinstance(code, str) and code.replace("_", "").isalnum():
                    diagnostic = f"rebirth_host_startup_diagnostic:{code}"
            except (UnicodeDecodeError, json.JSONDecodeError):
                diagnostic = "rebirth_host_startup_diagnostic"
        raise RebirthHostError(diagnostic)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)


def _terminate_without_consuming_output(process: subprocess.Popen[bytes]) -> None:
    """Revoke execution immediately while leaving pipes to the owning caller."""

    if process.poll() is None:
        process.kill()
    process.wait(timeout=2)


def _owner_file(path: Path) -> Path:
    try:
        info = path.lstat()
    except OSError as exception:
        raise RebirthHostError("rebirth_host_admission_config_missing") from exception
    if (
        info.st_uid != os.geteuid()
        or not stat.S_ISREG(info.st_mode)
        or info.st_mode & 0o077
    ):
        raise RebirthHostError("rebirth_host_admission_config_rejected")
    return path


def _configured_admission_client(
    state: Path, identity: Mapping[str, Any]
) -> AdmissionClient:
    try:
        config = _read_json(_owner_file(state / "admission-client.json"))
    except RebirthHostError:
        raise
    except RebirthInstallError as exception:
        raise RebirthHostError(
            "rebirth_host_admission_config_rejected"
        ) from exception
    required = {
        "schema",
        "endpoint",
        "holder_key_path",
        "holder_key_id",
        "authority_key_id",
        "authority_public_key",
        "lease_ttl_s",
    }
    if not isinstance(config, dict) or set(config) != required:
        raise RebirthHostError("rebirth_host_admission_config_rejected")
    if config.get("schema") != ADMISSION_CLIENT_SCHEMA:
        raise RebirthHostError("rebirth_host_admission_config_rejected")
    if not all(
        isinstance(config.get(field), str) and config[field]
        for field in (
            "holder_key_path",
            "holder_key_id",
            "authority_key_id",
            "authority_public_key",
        )
    ):
        raise RebirthHostError("rebirth_host_admission_config_rejected")
    endpoint_config = config.get("endpoint")
    if not isinstance(endpoint_config, dict):
        raise RebirthHostError("rebirth_host_admission_config_rejected")
    try:
        if set(endpoint_config) == {"transport", "path"} and endpoint_config.get(
            "transport"
        ) == "unix-local-fixture":
            endpoint = AdmissionEndpoint.local_fixture(endpoint_config["path"])
        elif set(endpoint_config) == {"transport", "host", "port"} and endpoint_config.get(
            "transport"
        ) == "tcp-authenticated":
            endpoint = AdmissionEndpoint.network(
                endpoint_config["host"], endpoint_config["port"]
            )
        else:
            raise AdmissionError("unsupported admission endpoint")
    except (AdmissionError, KeyError, TypeError):
        raise RebirthHostError("rebirth_host_admission_config_rejected") from None
    lease_ttl_s = config["lease_ttl_s"]
    if (
        isinstance(lease_ttl_s, bool)
        or not isinstance(lease_ttl_s, int)
        or not 3 <= lease_ttl_s <= 300
    ):
        raise RebirthHostError("rebirth_host_admission_config_rejected")
    try:
        from .fences import Ed25519Signer

        signer = Ed25519Signer(config["holder_key_path"], config["holder_key_id"])
        return AdmissionClient(
            endpoint,
            holder_signer=signer,
            authority_key_id=config["authority_key_id"],
            authority_public_key=config["authority_public_key"],
            being_ref=identity["being_ref"],
            body_ref=identity["origin"]["body_ref"],
            embodiment_id=identity["origin"]["embodiment_id"],
            incarnation_id=identity["origin"]["incarnation_id"],
            activation_id=identity["activation_id"],
            credential_id=identity["credential_id"],
            manifest_hash=identity["manifest_hash"],
            lease_ttl_s=lease_ttl_s,
        )
    except (AdmissionError, KeyError) as exception:
        raise RebirthHostError("rebirth_host_admission_config_rejected") from exception


class _AdmissionSupervisor:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        client: AdmissionClient,
        receipt: dict[str, Any],
        ttl_s: int,
        *,
        lease_started_monotonic: float,
    ):
        self.process = process
        self.client = client
        self.receipt = receipt
        self.ttl_s = ttl_s
        self._lease_deadline = lease_started_monotonic + ttl_s
        self._condition = threading.Condition()
        self._client_lock = threading.Lock()
        self._finished = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name=f"rebirth-admission-{process.pid}",
            daemon=True,
        )
        self.watchdog = threading.Thread(
            target=self._watchdog,
            name=f"rebirth-admission-hard-deadline-{process.pid}",
            daemon=True,
        )

    def start(self) -> None:
        with _SUPERVISORS_LOCK:
            _SUPERVISORS[self.process.pid] = self
        self.watchdog.start()
        self.thread.start()

    def _hard_kill_at(self) -> float:
        return self._lease_deadline - self.ttl_s / 4

    def _watchdog(self) -> None:
        """Kill independently of renew I/O or either host's wall clock."""

        while not self._finished.is_set() and self.process.poll() is None:
            with self._condition:
                remaining = self._hard_kill_at() - time.monotonic()
                if remaining > 0:
                    self._condition.wait(timeout=min(remaining, 0.25))
                    continue
            _terminate_without_consuming_output(self.process)
            return

    def verify_current(self, *, minimum_remaining_s: float) -> dict[str, Any] | None:
        with self._client_lock:
            current = self.client.current()
        with self._condition:
            enough_budget = (
                self._lease_deadline - time.monotonic() > minimum_remaining_s
            )
        if (
            not enough_budget
            or current is None
            or current.get("session_id") != self.client.session_id
        ):
            return None
        return current

    def _run(self) -> None:
        try:
            while self.process.poll() is None:
                with self._condition:
                    renew_at = self._lease_deadline - self.ttl_s * 3 / 4
                interval = max(
                    0.01,
                    min(0.25, renew_at - time.monotonic()),
                )
                try:
                    self.process.wait(timeout=interval)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if time.monotonic() < renew_at:
                    continue
                try:
                    renew_started = time.monotonic()
                    with self._client_lock:
                        receipt = self.client.renew(ttl_s=self.ttl_s)
                except AdmissionError:
                    _terminate_without_consuming_output(self.process)
                    return
                with self._condition:
                    self.receipt = receipt
                    # The remote authority can only create this TTL after the
                    # local request began, so request-start + TTL is a safe,
                    # conservative deadline independent of wall-clock skew.
                    self._lease_deadline = renew_started + self.ttl_s
                    if time.monotonic() >= self._hard_kill_at():
                        _terminate_without_consuming_output(self.process)
                        return
                    self._condition.notify_all()
            try:
                with self._client_lock:
                    self.client.release()
            except AdmissionError:
                pass
        finally:
            self._finished.set()
            with self._condition:
                self._condition.notify_all()
            with _SUPERVISORS_LOCK:
                _SUPERVISORS.pop(self.process.pid, None)


def launch_rebirth_host(
    state_dir: str | Path,
    embodiment_id: str,
    password_descriptor: int,
    *,
    actor: str = "clusterctl-rebirth-host",
    timeout_s: float = 30.0,
    production_fence_verifier: bool = False,
    admission_client: AdmissionClient | None = None,
    admission_lease_ttl_s: int = DEFAULT_LEASE_TTL_S,
) -> tuple[subprocess.Popen[bytes], dict[str, Any]]:
    """Admit, start and authenticate one installed fresh embodiment."""

    if (
        password_descriptor < 0
        or timeout_s <= 0
        or timeout_s > 300
        or isinstance(admission_lease_ttl_s, bool)
        or not 3 <= admission_lease_ttl_s <= 300
    ):
        raise RebirthHostError("rebirth_host_argument_rejected")
    state = _owner_directory(Path(state_dir), create=True)
    identity = _installed_identity(state, embodiment_id)
    origin = identity["origin"]
    rollout_gate = identity["rollout_gate"]
    if rollout_gate is not None:
        try:
            from .distributed_rebirth import require_target_admission

            require_target_admission(
                state,
                rollout_gate["rollout_id"],
                rollout_gate["participant_embodiment_ids"],
                identity["manifest_hash"],
            )
        except Exception as exception:
            os.close(password_descriptor)
            raise RebirthHostError(
                "rebirth_host_rollout_admission_missing"
            ) from exception
    if identity["recovery_gate"]:
        recovery = OperationJournal(state).latest_completed_for_result(
            "rebirth-recovery-restore", "activation_id", identity["activation_id"]
        )
        recovery_result = None if recovery is None else recovery.get("result")
        if (
            not isinstance(recovery_result, dict)
            or recovery_result.get("embodiment_id") != embodiment_id
            or recovery_result.get("successor_manifest_hash")
            != identity["manifest_hash"]
            or recovery_result.get("state") != "installed-restored-stopped"
            or recovery_result.get("custody_free_transfer") is not True
        ):
            os.close(password_descriptor)
            raise RebirthHostError("rebirth_host_recovery_restore_missing")
    try:
        client = admission_client or _configured_admission_client(state, identity)
        if admission_client is None:
            admission_lease_ttl_s = client.lease_ttl_s
        if any(
            getattr(client, field) != expected
            for field, expected in (
                ("being_ref", identity["being_ref"]),
                ("body_ref", origin["body_ref"]),
                ("embodiment_id", embodiment_id),
                ("incarnation_id", origin["incarnation_id"]),
                ("activation_id", identity["activation_id"]),
                ("credential_id", identity["credential_id"]),
                ("manifest_hash", identity["manifest_hash"]),
            )
        ):
            raise AdmissionError("admission client identity mismatch")
    except RebirthHostError:
        os.close(password_descriptor)
        raise
    except AdmissionError as exception:
        os.close(password_descriptor)
        raise RebirthHostError("rebirth_host_admission_refused") from exception
    journal = OperationJournal(state)
    target = f"rebirth-start:{embodiment_id}:{identity['activation_id']}"
    try:
        with acquire(state, embodiment_id, "rebirth-start"):
            intent = {
                "schema": "dm.cluster.rebirth-host-intent/v1",
                "activation_id": identity["activation_id"],
                "origin": origin,
                "successor_manifest_hash": identity["manifest_hash"],
                "runtime_call": {
                    "operation": "matrix-host",
                    "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
                },
            }
            record = journal.latest_for_target(target)
            if record is None:
                record = journal.plan(
                    operation="rebirth-start",
                    target=target,
                    idempotency_key=f"rebirth-start:{identity['activation_id']}",
                    intent=intent,
                    expected_precondition={"install_state": "completed"},
                    intended_transition={
                        "registry_status": "running",
                        "incarnation_id": origin["incarnation_id"],
                    },
                    audit_identity={"actor": actor, "target": embodiment_id},
                )
            elif (
                record["operation"] != "rebirth-start"
                or record["intent"] != intent
                or record["state"]
                not in {
                    "planned",
                    "runtime-dispatching",
                    "runtime-applied",
                    "logical-committed",
                    "audited",
                    "completed",
                }
            ):
                raise RebirthHostError("rebirth_host_journal_conflict")
            if record["state"] == "planned":
                record = journal.advance(record["operation_id"], "runtime-dispatching")
            # Acquire only after the local operation lock and durable intent,
            # but before registry or process effects.
            try:
                lease_started_monotonic = time.monotonic()
                admission_receipt = client.acquire(ttl_s=admission_lease_ttl_s)
            except AdmissionError as exception:
                raise RebirthHostError("rebirth_host_admission_refused") from exception
            conservative_deadline = (
                lease_started_monotonic + admission_lease_ttl_s
            )

            def require_current_admission(
                code: str, *, minimum_remaining_s: float
            ) -> dict[str, Any]:
                try:
                    current = client.current()
                except AdmissionError as exception:
                    raise RebirthHostError(code) from exception
                if (
                    current is None
                    or current.get("session_id") != client.session_id
                    or current.get("proof_ref")
                    != admission_receipt.get("proof_ref")
                    or conservative_deadline - time.monotonic()
                    <= minimum_remaining_s
                ):
                    raise RebirthHostError(code)
                return current

            require_current_admission(
                "rebirth_host_admission_lost_before_effect",
                minimum_remaining_s=admission_lease_ttl_s / 2,
            )
            registry = Registry(state)
            registry_started_here = False
            operation_id = record["operation_id"]

            def compensate_registry_start(code: str) -> None:
                nonlocal record, registry_started_here
                if not registry_started_here:
                    return
                try:
                    registry.rollback_start(
                        embodiment_id,
                        incarnation_id=origin["incarnation_id"],
                    )
                    record = journal.advance(
                        operation_id,
                        "runtime-dispatching",
                        runtime_observation={
                            "registry_start_compensated": True,
                            "embodiment_id": embodiment_id,
                            "incarnation_id": origin["incarnation_id"],
                            "reason": code,
                        },
                        last_error=code,
                    )
                    registry_started_here = False
                except Exception as exception:
                    journal.advance(
                        operation_id,
                        "degraded",
                        last_error="rebirth_host_registry_compensation_failed",
                    )
                    raise RebirthHostError(
                        "rebirth_host_registry_compensation_failed"
                    ) from exception

            try:
                registered = registry.status(embodiment_id)
                if (
                    registered["status"] == "stopped"
                    and registered["current_incarnation_id"] is None
                ):
                    require_current_admission(
                        "rebirth_host_admission_lost_before_registry",
                        minimum_remaining_s=admission_lease_ttl_s / 2,
                    )
                    registry.start(
                        embodiment_id,
                        incarnation_id=origin["incarnation_id"],
                        started_at_ms=int(time.time_ns() // 1_000_000),
                    )
                    registry_started_here = True
                    try:
                        require_current_admission(
                            "rebirth_host_admission_lost_after_registry",
                            minimum_remaining_s=admission_lease_ttl_s / 3,
                        )
                    except RebirthHostError:
                        compensate_registry_start(
                            "rebirth_host_admission_lost_after_registry"
                        )
                        raise
                    registered = registry.status(embodiment_id)
            except RegistryError as exception:
                compensate_registry_start("rebirth_host_registry_rejected")
                raise RebirthHostError("rebirth_host_registry_rejected") from exception
            if (
                registered.get("body_ref") != origin["body_ref"]
                or registered.get("status") != "running"
                or registered.get("current_incarnation_id")
                != origin["incarnation_id"]
            ):
                compensate_registry_start("rebirth_host_registry_rejected")
                raise RebirthHostError("rebirth_host_registry_rejected")

            # The shared lease is acquired inside the local operation lock,
            # after all recovery/journal checks.  Its signed current position is
            # re-read at the last boundary before the runtime effect.
            try:
                require_current_admission(
                    "rebirth_host_admission_lost_before_spawn",
                    minimum_remaining_s=admission_lease_ttl_s / 3,
                )
            except RebirthHostError:
                compensate_registry_start("rebirth_host_admission_lost_before_spawn")
                raise RebirthHostError("rebirth_host_admission_lost_before_spawn")
            ready_read, ready_write = os.pipe()
            command = [
                sys.executable,
                "-m",
                "clusterctl.matrix_host",
                "--state-dir",
                str(state),
                "--embodiment-id",
                embodiment_id,
                "--password-fd",
                str(password_descriptor),
                "--ready-fd",
                str(ready_write),
                "--guardian-pid",
                str(os.getpid()),
            ]
            if production_fence_verifier:
                command.append("--production-fence-verifier")
            process: subprocess.Popen[bytes] | None = None
            try:
                process = subprocess.Popen(
                    command,
                    pass_fds=(password_descriptor, ready_write),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except BaseException:
                os.close(ready_read)
                compensate_registry_start("rebirth_host_spawn_failed")
                raise
            finally:
                os.close(password_descriptor)
                os.close(ready_write)
            assert process is not None
            supervisor = _AdmissionSupervisor(
                process,
                client,
                admission_receipt,
                admission_lease_ttl_s,
                lease_started_monotonic=lease_started_monotonic,
            )
            supervisor.start()
            try:
                _wait_ready(ready_read, process, timeout_s)
                ready_admission = supervisor.verify_current(
                    minimum_remaining_s=admission_lease_ttl_s / 4
                )
                if ready_admission is None:
                    raise RebirthHostError("rebirth_host_admission_lost_at_ready")
                observation = _verify_ready(state, identity)
                if record["state"] == "runtime-dispatching":
                    record = journal.advance(
                        record["operation_id"],
                        "runtime-applied",
                        runtime_observation=observation,
                    )
                if record["state"] == "runtime-applied":
                    record = journal.advance(
                        record["operation_id"],
                        "logical-committed",
                        logical_observation={
                            "embodiment_id": embodiment_id,
                            "incarnation_id": origin["incarnation_id"],
                            "status": "running",
                        },
                    )
                result = {
                    "schema": RESULT_SCHEMA,
                    "activation_id": identity["activation_id"],
                    "being_ref": identity["being_ref"],
                    "embodiment_id": embodiment_id,
                    "incarnation_id": origin["incarnation_id"],
                    "successor_manifest_hash": identity["manifest_hash"],
                    "integrity": observation["integrity"],
                    "active_embodiment_ids": observation["active_embodiment_ids"],
                    "state": "running-ready",
                }
                if record["state"] == "logical-committed":
                    audit.append_event(
                        state,
                        actor=actor,
                        action="rebirth-start",
                        target=embodiment_id,
                        result="ok",
                        detail={
                            "activation_id": identity["activation_id"],
                            "successor_manifest_hash": identity["manifest_hash"],
                        },
                        idempotency_key=f"rebirth-start:{identity['activation_id']}",
                        event_id=record["audit_event_id"],
                    )
                    record = journal.advance(record["operation_id"], "audited")
                if record["state"] == "audited":
                    record = journal.advance(
                        record["operation_id"], "completed", result=result
                    )
                if record["state"] != "completed" or record["result"] != result:
                    raise RebirthHostError("rebirth_host_result_conflict")
                return process, {**result, "admission": supervisor.receipt}
            except BaseException:
                _terminate(process)
                raise
    except BaseException:
        try:
            os.close(password_descriptor)
        except OSError:
            pass
        try:
            client.release()
        except AdmissionError:
            pass
        raise


def _diagnostic(code: str) -> None:
    print(
        json.dumps(
            {"schema": "dm.cluster.rebirth-host-diagnostic/v1", "code": code},
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stderr,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--embodiment-id", required=True)
    parser.add_argument("--password-fd", type=int, required=True)
    parser.add_argument("--ready-fd", type=int)
    parser.add_argument("--production-fence-verifier", action="store_true")
    args = parser.parse_args(argv)
    try:
        process, result = launch_rebirth_host(
            args.state_dir,
            args.embodiment_id,
            args.password_fd,
            production_fence_verifier=args.production_fence_verifier,
        )
        if args.ready_fd is not None:
            os.write(args.ready_fd, b"READY\n")
            os.close(args.ready_fd)

        def stop(_number: int, _frame: object) -> None:
            if process.poll() is None:
                process.terminate()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        return_code = process.wait()
        if return_code != 0:
            raise RebirthHostError("rebirth_host_process_failed")
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except RebirthHostError as exception:
        _diagnostic(str(exception))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RESULT_SCHEMA",
    "RebirthHostError",
    "launch_rebirth_host",
    "main",
]
