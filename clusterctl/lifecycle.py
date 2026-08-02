"""Lifecycle mutation commands (issue #11).

Commands: ``create``, ``start``, ``stop``, ``restart``, ``logs``,
``destroy-plan``. Every mutation (and every rejected mutation) applies
the same contracts:

- **admission** — declared-state/incus checks before any effect
- **idempotency** — ``--idempotency-key`` replay/conflict semantics
  (``clusterctl.idempotency``)
- **locking** — per-instance lock for the mutation duration
  (``clusterctl.locks``); conflicts exit 6 with holder info
- **audit** — one ``audit-event/v1`` line per attempt
  (``clusterctl.audit``); ``detail`` never contains secrets

``logs`` and ``destroy-plan`` do not mutate incus, but both are audited
(log access touches potentially sensitive data; destroy-plan is the
prepare half of the destroy prepare/confirm pair). Read commands
(``list``, ``status``, ``config-show``) stay strictly side-effect free.

Exit codes (same values as clusterctl.cli): 0 ok, 3 not found /
undeclared, 6 conflict (duplicate, idempotency, lock), 10 internal.
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import yaml

from . import audit, embodiments, fences, idempotency, locks
from .inventory import SPEC_SCHEMA, load_spec_raw, load_specs, update_spec

EXIT_OK = 0
EXIT_NOT_FOUND = 3
EXIT_CONFLICT = 6
EXIT_INTERNAL = 10

DEFAULT_IMAGE = "tribe-base/latest"
LOGS_DEFAULT_LINES = 100
LOGS_MAX_LINES = 1000
STOP_DEFAULT_TIMEOUT = 30

# Secret redaction for `logs`: simple case-insensitive substring match.
REDACT_PATTERNS = ("private key", "api_key", "token=", "bearer ", "sk-", "aiza")
REDACTED = "[REDACTED]"

DESTROY_PLAN_SCHEMA = "destroy-plan/v1"


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def _actor(args) -> str:
    return getattr(args, "actor", None) or "clusterctl-cli"


def _idem_key(args) -> str | None:
    return getattr(args, "idempotency_key", None)

def _request_id(args) -> str | None:
    return getattr(args, "request_id", None)

def _action_digest(args) -> str | None:
    return getattr(args, "action_digest", None)


def _emit(args, payload: dict, human: str) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
    else:
        print(human)


def _fail(args, cfg, action: str, target: str, message: str, code: int,
          *, audit_result: str = "denied", detail: dict | None = None,
          err_extra: dict | None = None) -> int:
    """Audit a rejected/failed mutation, print the error, return exit code."""
    det = {"error": message}
    if detail:
        det.update(detail)
    audit.append_event(
        cfg.state_dir,
        actor=_actor(args),
        action=action,
        target=target,
        result=audit_result,
        detail=det,
        idempotency_key=_idem_key(args),
        request_id=_request_id(args),
        action_digest=_action_digest(args),
    )
    if getattr(args, "json", False):
        payload = {"error": message, "action": action, "target": target}
        if err_extra:
            payload.update(err_extra)
        print(json.dumps(payload), file=sys.stderr)
    else:
        suffix = f" ({json.dumps(err_extra)})" if err_extra else ""
        print(f"clusterctl: {action} {target}: {message}{suffix}", file=sys.stderr)
    return code


def _audit_ok(args, cfg, action: str, target: str, detail: dict | None = None) -> dict:
    return audit.append_event(
        cfg.state_dir,
        actor=_actor(args),
        action=action,
        target=target,
        result="ok",
        detail=detail or {},
        idempotency_key=_idem_key(args),
        request_id=_request_id(args),
        action_digest=_action_digest(args),
    )


def _check_idempotency(args, cfg, operation: str, name: str, store: dict,
                       adapter) -> int | None:
    """Replay only when the recorded effect still matches reality.

    An idempotency hit is a replay *candidate*, not proof that the effect is
    still true. Contradictory or safely re-checkable effects execute again so
    the operation converges; unverifiable non-convergent effects fail closed.
    """
    status, entry = idempotency.check(store, _idem_key(args), operation, name)
    if status == "replay":
        recorded = entry.get("result") or {}
        truth, observed = _verify_effect(cfg, adapter, operation, name, recorded)
        if truth == "matches":
            _audit_ok(args, cfg, operation, name, {
                "idempotent_replay": True,
                "effect_truth": "verified",
                "observed": observed,
            })
            payload = dict(recorded)
            payload["idempotent-replay"] = True
            payload["effect-truth"] = "verified"
            _emit(
                args, payload,
                f"idempotent-replay: {operation} {name} "
                f"(key {_idem_key(args)}) — verified no-op",
            )
            return EXIT_OK
        if not _effect_reexecution_is_safe(operation, recorded, truth):
            return _fail(
                args, cfg, operation, name,
                f"recorded effect for key {_idem_key(args)} cannot be "
                f"verified as current and {operation} is not safely "
                "convergent; refusing",
                EXIT_INTERNAL, audit_result="error",
                detail={
                    "kind": "effect-truth-refused",
                    "recorded_effect": recorded,
                    "observed": observed,
                    "verdict": truth,
                },
            )
        audit.append_event(
            cfg.state_dir, actor=_actor(args), action=operation, target=name,
            result="error",
            detail={
                "kind": "effect-truth-discrepancy",
                "recorded_effect": recorded,
                "observed": observed,
                "verdict": truth,
                "idempotency_key": _idem_key(args),
            },
            idempotency_key=_idem_key(args),
            request_id=_request_id(args),
            action_digest=_action_digest(args),
        )
        return None
    if status == "conflict":
        return _fail(
            args, cfg, operation, name,
            f"idempotency key {_idem_key(args)} already used for "
            f"{entry.get('operation')} on {entry.get('name')}",
            EXIT_CONFLICT,
            err_extra={"idempotency_conflict": {
                "key": _idem_key(args),
                "held_operation": entry.get("operation"),
                "held_name": entry.get("name"),
            }},
        )
    return None


def _verify_effect(cfg, adapter, operation: str, name: str,
                   recorded: dict) -> tuple[str, dict]:
    """Compare one operation's recorded postcondition with current reality.

    A runtime state is not a universal effect verifier: a quiesced writer can
    live in a running container, and handoff operations also bind durable
    records and resource-fence generations.  Keep the checks operation-shaped
    so adding a lifecycle verb cannot silently inherit the wrong semantics.
    """
    if operation == "snapshot-create":
        snap_name = recorded.get("snap_name")
        if not isinstance(snap_name, str) or not snap_name:
            return "unverifiable", {"reason": "missing recorded snapshot"}
        try:
            present = bool(adapter.incus_snapshot_verify(name, snap_name))
        except Exception as exc:
            return "unverifiable", {"error": str(exc)}
        manifest = _path_observation(recorded.get("manifest"))
        observed = {
            "snapshot": snap_name,
            "present": present,
            "manifest": manifest,
        }
        return (
            "matches" if present and manifest.get("present") else "contradicts",
            observed,
        )

    if operation == "provision-prepare":
        spec = load_spec_raw(cfg.instances_dir, name)
        try:
            present = any(
                item.get("name") == name for item in adapter.list_instances()
            )
        except Exception as exc:
            return "unverifiable", {"error": str(exc)}
        token = _confirmation_observation(cfg, name, recorded.get("token"))
        observed = {
            "spec_present": spec is not None,
            "spec_state": None if spec is None else spec.get("state"),
            "container_present": present,
            "confirmation": token,
        }
        matches = (
            spec is not None
            and spec.get("state") == "provisioned-pending-activation"
            and present
            and token.get("valid") is True
        )
        return ("matches" if matches else "contradicts", observed)

    observed_name = str(recorded.get("target") or name)
    runtime_truth, observed = _runtime_state_observation(
        adapter, observed_name, operation, recorded,
    )
    if runtime_truth != "matches":
        return runtime_truth, observed

    if operation == "park" and recorded.get("manifest"):
        manifest = _path_observation(recorded.get("manifest"))
        checkpoint_matches = _json_file_matches(
            recorded.get("manifest"), recorded.get("checkpoint"),
        )
        fence = _resource_fence_observation(cfg, name, recorded)
        observed.update({
            "manifest": manifest,
            "checkpoint_matches": checkpoint_matches,
            "resource_fence": fence,
        })
        matches = (
            manifest.get("present") is True
            and checkpoint_matches is True
            and fence.get("matches") is True
        )
        return ("matches" if matches else "contradicts", observed)

    if operation in {"wake", "transfer"}:
        record_key = "wake_record" if operation == "wake" else "transfer_record"
        durable_record = _path_observation(recorded.get(record_key))
        manifest = _path_observation(recorded.get("manifest"))
        fence = _resource_fence_observation(cfg, name, recorded)
        observed.update({
            record_key: durable_record,
            "manifest": manifest,
            "resource_fence": fence,
        })
        matches = (
            durable_record.get("present") is True
            and manifest.get("present") is True
            and fence.get("matches") is True
        )
        return ("matches" if matches else "contradicts", observed)

    return "matches", observed


def _runtime_state_observation(adapter, observed_name: str, operation: str,
                               recorded: dict) -> tuple[str, dict]:
    """Verify only substrate state; never infer writer quiescence from it."""
    try:
        actual = {
            item.get("name"): item for item in adapter.list_instances()
            if item.get("name")
        }
    except Exception as exc:
        return "unverifiable", {"name": observed_name, "error": str(exc)}
    observed_instance = actual.get(observed_name)
    observed_state = str((observed_instance or {}).get("state") or "").lower()
    observed = {
        "name": observed_name,
        "present": observed_instance is not None,
        "state": observed_state or None,
    }
    if observed_instance is None:
        return "contradicts", observed

    # Plain park only SIGSTOPs writers; Incus correctly remains "running".
    # There is no read-only adapter probe for that postcondition, so a retry
    # must execute the convergent quiesce operation instead of claiming truth.
    if operation == "park" and not recorded.get("manifest"):
        return "unverifiable", {
            **observed,
            "reason": "writer quiescence is not observable",
        }

    expected = {
        "create": "stopped",
        "start": "running",
        "stop": "stopped",
        "restart": "running",
        "park": "stopped",       # full --handoff park
        "wake": "running",
        "transfer": "running",  # target selected above
    }.get(operation)
    if expected is None:
        return "unverifiable", {
            **observed,
            "reason": f"no verifier for operation {operation}",
        }
    observed["expected_state"] = expected
    return ("matches" if observed_state == expected else "contradicts", observed)


def _path_observation(value) -> dict:
    if not isinstance(value, str) or not value:
        return {"path": value, "present": False}
    return {"path": value, "present": Path(value).is_file()}


def _json_file_matches(value, expected) -> bool:
    if not isinstance(value, str) or not isinstance(expected, dict):
        return False
    try:
        actual = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return actual == expected


def _confirmation_observation(cfg, name: str, token) -> dict:
    if not isinstance(token, str) or not token:
        return {"token": token, "present": False, "valid": False}
    try:
        if str(uuid.UUID(token)) != token:
            raise ValueError
    except ValueError:
        return {"token": token, "present": False, "valid": False}
    path = Path(cfg.state_dir) / "confirmations" / f"{token}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"token": token, "present": path.is_file(), "valid": False}
    created_ms = value.get("created_ms")
    ttl_s = value.get("ttl_s")
    temporal_shape = (
        isinstance(created_ms, int) and not isinstance(created_ms, bool)
        and isinstance(ttl_s, int) and not isinstance(ttl_s, bool)
        and ttl_s >= 0
    )
    expired = (
        not temporal_shape
        or audit.now_ms() > created_ms + ttl_s * 1000
    )
    valid = (
        value.get("schema") == "confirmation/v1"
        and value.get("operation") == "provision-activate"
        and value.get("target") == name
        and value.get("token") == token
        and value.get("used") is False
        and not expired
    )
    return {
        "token": token,
        "present": True,
        "used": value.get("used"),
        "expired": expired,
        "valid": valid,
    }


def _resource_fence_observation(cfg, name: str, recorded: dict) -> dict:
    checkpoint = recorded.get("checkpoint")
    checkpoint = checkpoint if isinstance(checkpoint, dict) else {}
    expected_epoch = recorded.get("fence_epoch")
    if expected_epoch is None:
        expected_epoch = checkpoint.get("resource_fence_epoch")
    fence_required = expected_epoch is not None
    if not fence_required:
        return {"required": False, "matches": True}
    spec = load_spec_raw(cfg.instances_dir, name) or {}
    resource_ref = str(
        spec.get("body_ref") or spec.get("daimon_id")
        or f"resource:body:{name}"
    )
    try:
        status = fences.ResourceFenceStore(cfg.state_dir).status(resource_ref)
    except fences.FenceError as exc:
        return {
            "required": True,
            "resource_ref": resource_ref,
            "expected_epoch": expected_epoch,
            "matches": False,
            "error": str(exc),
        }
    matches = (
        status.get("present") is True
        and status.get("expired") is False
        and status.get("last_epoch") == expected_epoch
    )
    return {
        "required": True,
        "resource_ref": resource_ref,
        "expected_epoch": expected_epoch,
        "observed_epoch": status.get("last_epoch"),
        "present": status.get("present"),
        "expired": status.get("expired"),
        "matches": matches,
    }


def _effect_reexecution_is_safe(operation: str, recorded: dict,
                                verdict: str) -> bool:
    """Whether the existing workflow can converge after a stale receipt.

    Durable handoff workflows have their own resume journals. Re-entering a
    journal whose terminal records or fence have drifted can return the same
    stale terminal output, so those cases fail closed until an explicit repair
    protocol exists. Plain writer park/wake and power state changes are
    repeatable. A missing snapshot is a contradiction that permits a new
    capture; an unreachable snapshot backend does not.
    """
    if operation in {"start", "stop"}:
        return True
    if operation == "park":
        return not recorded.get("manifest")
    if operation == "wake":
        return not recorded.get("wake_record")
    if operation == "snapshot-create":
        return verdict == "contradicts"
    return False


def _record_idempotency(args, cfg, operation: str, name: str,
                        store: dict, result: dict) -> None:
    key = _idem_key(args)
    if key:
        idempotency.record(store, key, operation, name, result)
        idempotency.save_store(cfg.state_dir, store)


def _lock_or_fail(args, cfg, operation: str, name: str):
    """Return a lock context manager, or an exit code on conflict."""
    try:
        return locks.acquire(cfg.state_dir, name, operation)
    except locks.LockConflict as exc:
        return _fail(
            args, cfg, operation, name, str(exc), EXIT_CONFLICT,
            err_extra={"holder": exc.holder},
        )


def _stale_detail(acquired) -> dict:
    if acquired.stale_holder:
        return {"stale_lock_broken": True, "previous_holder": acquired.stale_holder}
    return {}


def _write_spec(instances_dir: Path, spec: dict) -> Path:
    instances_dir.mkdir(parents=True, exist_ok=True)
    path = instances_dir / f"{spec['name']}.yaml"
    path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# create
# --------------------------------------------------------------------------

def cmd_create(args, cfg, adapter) -> int:
    name, operation = args.name, "create"
    store = idempotency.load_store(cfg.state_dir)
    rc = _check_idempotency(args, cfg, operation, name, store, adapter)
    if rc is not None:
        return rc

    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        # Admission: name must be absent from BOTH state_dir and incus.
        specs = load_specs(cfg.instances_dir)
        actual_names = {inst["name"] for inst in adapter.list_instances()}
        if name in specs or name in actual_names:
            where = "declared in state_dir" if name in specs else "present in incus"
            return _fail(args, cfg, operation, name,
                         f"instance {name!r} already exists ({where})",
                         EXIT_CONFLICT, detail=stale)

        image_version = adapter.resolve_image(args.image)
        budgets = adapter.profile_budgets(cfg.profile)
        spec = {
            "schema": SPEC_SCHEMA,
            "name": name,
            "species": args.species,
            "image_version": image_version,
            "budgets": budgets,
            "created_ms": audit.now_ms(),
            "created_by": _actor(args),
            "idempotency_key": _idem_key(args),
            "body_ref": f"cluster:{cfg.host_id}:{name}",
            "embodiment_id": embodiments.new_id("embodiment"),
            "current_incarnation_id": None,
        }
        _write_spec(cfg.instances_dir, spec)

        try:
            adapter.create_instance(name, args.image, cfg.profile)
        except Exception as exc:
            # Reversal: delete any partially-created container so nothing
            # is left untracked, and mark the spec creation-failed.
            cleanup_error = None
            try:
                adapter.delete(name)
            except Exception as cleanup_exc:  # pragma: no cover - defensive
                cleanup_error = str(cleanup_exc)
            spec["state"] = "creation-failed"
            spec["state_reason"] = str(exc)
            _write_spec(cfg.instances_dir, spec)
            detail = {"reversed": True, **stale}
            if cleanup_error:
                detail["cleanup_error"] = cleanup_error
            return _fail(args, cfg, operation, name,
                         f"create failed ({exc}); container reversed, "
                         f"spec marked creation-failed",
                         EXIT_INTERNAL, audit_result="error", detail=detail)

        try:
            embodiments.Registry(cfg.state_dir).register(
                body_ref=spec["body_ref"], embodiment_id=spec["embodiment_id"]
            )
        except embodiments.RegistryError as exc:
            try:
                adapter.delete(name)
            except Exception:
                pass
            spec["state"] = "creation-failed"
            spec["state_reason"] = str(exc)
            _write_spec(cfg.instances_dir, spec)
            return _fail(args, cfg, operation, name,
                         f"embodiment registration failed: {exc}", EXIT_INTERNAL,
                         audit_result="error", detail={"reversed": True, **stale})

        result = {
            "operation": operation,
            "name": name,
            "result": "ok",
            "species": args.species,
            "image": args.image,
            "image_version": image_version,
            "budgets": budgets,
            "state": "stopped",
            "body_ref": spec["body_ref"],
            "embodiment_id": spec["embodiment_id"],
            "incarnation_id": None,
            "idempotency_key": _idem_key(args),
        }
        _record_idempotency(args, cfg, operation, name, store, result)
        _audit_ok(args, cfg, operation, name,
                  {"species": args.species, "image": args.image,
                   "image_version": image_version, "budgets": budgets, **stale})
        _emit(args, result,
              f"created {name} (species {args.species}, image {image_version}, state stopped)")
        return EXIT_OK


# --------------------------------------------------------------------------
# start / stop / restart
# --------------------------------------------------------------------------

def cmd_power(args, cfg, adapter, operation: str) -> int:
    name = args.name
    store = idempotency.load_store(cfg.state_dir)
    rc = _check_idempotency(args, cfg, operation, name, store, adapter)
    if rc is not None:
        return rc

    # Operate on declared instances only.
    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        try:
            if operation == "start":
                adapter.start(name)
            elif operation == "stop":
                adapter.stop(name, getattr(args, "timeout", STOP_DEFAULT_TIMEOUT))
            else:  # restart
                adapter.restart(name)
        except Exception as exc:
            return _fail(args, cfg, operation, name,
                         f"{operation} failed: {exc}", EXIT_INTERNAL,
                         audit_result="error", detail=stale)

        state = "stopped" if operation == "stop" else "running"
        raw_spec = load_spec_raw(cfg.instances_dir, name) or {}
        embodiment_id = raw_spec.get("embodiment_id")
        incarnation_id = raw_spec.get("current_incarnation_id")
        if embodiment_id:
            try:
                registry = embodiments.Registry(cfg.state_dir)
                if operation == "stop":
                    registry.stop(embodiment_id)
                    incarnation_id = None
                else:
                    if operation == "restart" or registry.status(
                        embodiment_id
                    )["status"] == "running":
                        registry.stop(embodiment_id)
                    incarnation_id = registry.start(embodiment_id)["incarnation_id"]
                update_spec(cfg.instances_dir, name, {"current_incarnation_id": incarnation_id})
            except embodiments.RegistryError as exc:
                return _fail(args, cfg, operation, name,
                             f"lifecycle registry failed after runtime mutation: {exc}",
                             EXIT_INTERNAL, audit_result="error", detail=stale)
        result = {
            "operation": operation,
            "name": name,
            "result": "ok",
            "state": state,
            "idempotency_key": _idem_key(args),
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnation_id,
        }
        _record_idempotency(args, cfg, operation, name, store, result)
        _audit_ok(args, cfg, operation, name,
                  {"state": state, "embodiment_id": embodiment_id,
                   "incarnation_id": incarnation_id, **stale})
        _emit(args, result, f"{operation} {name}: ok (state {state})")
        return EXIT_OK


# --------------------------------------------------------------------------
# park / wake (issue #23) — quiesce primitives as first-class mutations
# --------------------------------------------------------------------------

PARK_QUIESCE_TIMEOUT_S = 30


def cmd_parkwake(args, cfg, adapter, operation: str) -> int:
    """``park`` freezes the daimon's writers (SIGSTOP hermes); ``wake``
    resumes them (SIGCONT). Same admission/idempotency/lock/audit contract
    as every other lifecycle mutation; the adapter only executes."""
    name = args.name
    store = idempotency.load_store(cfg.state_dir)
    rc = _check_idempotency(args, cfg, operation, name, store, adapter)
    if rc is not None:
        return rc

    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        try:
            if operation == "park":
                ok = bool(adapter.exec_quiesce_park(
                    name, PARK_QUIESCE_TIMEOUT_S))
            else:  # wake
                ok = bool(adapter.exec_unpark(name))
        except Exception as exc:
            return _fail(args, cfg, operation, name,
                         f"{operation} failed: {exc}", EXIT_INTERNAL,
                         audit_result="error", detail=stale)
        if not ok:
            return _fail(args, cfg, operation, name,
                         f"{operation} failed: daimon did not quiesce"
                         if operation == "park" else
                         f"{operation} failed: daimon did not resume",
                         EXIT_INTERNAL, audit_result="error", detail=stale)

        state = "parked" if operation == "park" else "running"
        result = {
            "operation": operation,
            "name": name,
            "result": "ok",
            "state": state,
            "idempotency_key": _idem_key(args),
        }
        _record_idempotency(args, cfg, operation, name, store, result)
        _audit_ok(args, cfg, operation, name, {"state": state, **stale})
        _emit(args, result, f"{operation} {name}: ok (state {state})")
        return EXIT_OK

# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------

def redact_line(line: str) -> str:
    low = line.lower()
    return REDACTED if any(p in low for p in REDACT_PATTERNS) else line


def cmd_logs(args, cfg, adapter) -> int:
    name, operation = args.name, "logs"
    specs = load_specs(cfg.instances_dir)
    actual_names = {inst["name"] for inst in adapter.list_instances()}
    if name not in specs and name not in actual_names:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} not found", EXIT_NOT_FOUND)

    requested = getattr(args, "lines", LOGS_DEFAULT_LINES)
    max_lines = max(1, min(requested, LOGS_MAX_LINES))
    try:
        raw = adapter.logs(name, max_lines)
    except Exception as exc:
        return _fail(args, cfg, operation, name,
                     f"logs failed: {exc}", EXIT_INTERNAL, audit_result="error")

    lines = raw.splitlines()
    redacted = [redact_line(line) for line in lines]
    n_redacted = sum(1 for a, b in zip(lines, redacted) if a != b)
    # Audit detail carries counts only — never log content (may hold secrets).
    _audit_ok(args, cfg, operation, name,
              {"lines_requested": requested, "lines_returned": len(redacted),
               "redacted": n_redacted})
    payload = {
        "name": name,
        "lines": redacted,
        "line_count": len(redacted),
        "redacted_count": n_redacted,
    }
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2))
    else:
        for line in redacted:
            print(line)
    return EXIT_OK


# --------------------------------------------------------------------------
# destroy-plan (plan only — destroy execution lands with the archive flow)
# --------------------------------------------------------------------------

def cmd_destroy_plan(args, cfg, adapter) -> int:
    name, operation = args.name, "destroy-plan"
    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    delete_volumes = bool(getattr(args, "delete_volumes", False))
    deletion_order = ["container", "spec"] + (["volume"] if delete_volumes else [])
    plan = {
        "schema": DESTROY_PLAN_SCHEMA,
        "operation": "destroy",
        "target": name,
        "dry_run": True,
        "executes": False,
        "archive_evidence": {
            "required": True,
            "manifest_schema": "cluster-backup-manifest/v1",
            "field": "backup_manifest_id",
            "note": "destroy execution refuses without a verified archived "
                    "backup manifest id for the target",
        },
        "confirmation": {
            "required": True,
            "schema": "cluster-confirmation/v1",
            "single_use": True,
            "operation": "destroy",
            "ttl_s": 900,
        },
        "deletion_order": deletion_order,
        "delete_volumes": delete_volumes,
        "notes": [
            "plan only — nothing was deleted",
            "volumes are kept unless --delete-volumes is given",
        ],
    }
    _audit_ok(args, cfg, operation, name, {"delete_volumes": delete_volumes})
    human = "\n".join([
        f"destroy plan for {name} (PLAN ONLY — nothing deleted)",
        "  archive evidence required: cluster-backup-manifest/v1 id "
        "(verified archived backup)",
        "  confirmation: single-use token, operation \"destroy\", TTL 900s",
        f"  deletion order: {' -> '.join(deletion_order)}",
        f"  volumes: {'deleted' if delete_volumes else 'kept'}",
    ])
    _emit(args, plan, human)
    return EXIT_OK


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------

def dispatch(args, cfg, adapter) -> int:
    """Route a mutation subcommand to its handler.

    LockConflict is caught here (not only in ``_lock_or_fail``) because a
    context-manager lock raises at ``__enter__``, outside the helper's try —
    the contract (exit 6 + holder info) must hold for every mutation.
    """
    try:
        if args.command == "create":
            return cmd_create(args, cfg, adapter)
        if args.command in ("start", "stop", "restart"):
            return cmd_power(args, cfg, adapter, args.command)
        if args.command == "park":
            if getattr(args, "handoff", False):
                # Lazy import: park imports helpers from this module.
                from . import park as park_mod
                return park_mod.cmd_park(args, cfg, adapter)
            return cmd_parkwake(args, cfg, adapter, args.command)
        if args.command == "wake":
            if getattr(args, "handoff", False):
                # Lazy import: transfer imports helpers from this module.
                from . import transfer as transfer_mod
                return transfer_mod.cmd_wake(args, cfg, adapter)
            return cmd_parkwake(args, cfg, adapter, args.command)
        if args.command == "transfer":
            # Lazy import: transfer imports helpers from this module.
            from . import transfer as transfer_mod
            return transfer_mod.cmd_transfer(args, cfg, adapter)
        if args.command == "logs":
            return cmd_logs(args, cfg, adapter)
        if args.command == "destroy-plan":
            return cmd_destroy_plan(args, cfg, adapter)
        if args.command == "provision":
            # Lazy import: provision imports helpers from this module.
            from . import provision
            if getattr(args, "provision_command", None) == "prepare":
                return provision.cmd_provision_prepare(args, cfg, adapter)
            if getattr(args, "provision_command", None) == "confirm":
                return provision.cmd_provision_confirm(args, cfg, adapter)
        if args.command == "snapshot":
            # Lazy import: snapshot imports helpers from this module.
            from . import snapshot
            if getattr(args, "snapshot_command", None) == "create":
                return snapshot.cmd_snapshot_create(args, cfg, adapter)
    except locks.LockConflict as exc:
        return _fail(
            args, cfg, args.command, getattr(args, "name", "?"), str(exc),
            EXIT_CONFLICT, err_extra={"holder": exc.holder},
        )
    raise ValueError(f"unknown lifecycle command {args.command!r}")  # pragma: no cover
