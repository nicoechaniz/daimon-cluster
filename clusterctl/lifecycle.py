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
from pathlib import Path

import yaml

from . import audit, idempotency, locks
from .inventory import SPEC_SCHEMA, load_specs

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


def _check_idempotency(args, cfg, operation: str, name: str, store: dict):
    """Handle replay/conflict. Returns an exit code, or None to proceed."""
    status, entry = idempotency.check(store, _idem_key(args), operation, name)
    if status == "replay":
        _audit_ok(args, cfg, operation, name, {"idempotent_replay": True})
        payload = dict(entry.get("result") or {})
        payload["idempotent-replay"] = True
        _emit(args, payload,
              f"idempotent-replay: {operation} {name} (key {_idem_key(args)}) — no-op")
        return EXIT_OK
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
    rc = _check_idempotency(args, cfg, operation, name, store)
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

        result = {
            "operation": operation,
            "name": name,
            "result": "ok",
            "species": args.species,
            "image": args.image,
            "image_version": image_version,
            "budgets": budgets,
            "state": "stopped",
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
    rc = _check_idempotency(args, cfg, operation, name, store)
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
