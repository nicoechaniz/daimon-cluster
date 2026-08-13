"""clusterd handlers — adapt clusterctl calls; NO business logic here.

Every handler either:

- invokes ``clusterctl.cli.run`` programmatically with ``--json``
  (stdout/stderr captured) — the SAME code path as the CLI, so
  admission, idempotency, locking and audit contracts are applied by
  clusterctl itself (``clusterctl.lifecycle``), never reimplemented
  here; or
- reads state files clusterctl writes (backup manifests).

Security note: no handler ever passes user input to a shell — all
delegation is through clusterctl's Python API with an argv list.
Clusterctl calls are serialized behind a module-level lock because
stdout/stderr capture is process-global (the ThreadingHTTPServer may
otherwise interleave output from concurrent requests).

Exit-code -> HTTP mapping (mirrors clusterctl.cli):
    0 -> 200, 2 -> 400, 3 -> 404, 6 -> 409, 10 -> 500
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import io
import json
import os
import re
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from clusterctl import audit
from clusterctl import cli
from clusterctl import lifecycle
from clusterctl import operation_journal
from clusterctl.config import load_config

from . import __version__
from . import paging
import steward_tools.mutations as mutations

# clusterctl.cli.run prints JSON to stdout/stderr; capture is
# process-global, so serialize invocations (ThreadingHTTPServer serves
# requests concurrently). clusterctl's own locking is unaffected.
_CLI_LOCK = threading.Lock()

EXIT_TO_HTTP = {0: 200, 2: 400, 3: 404, 6: 409, 10: 500}

HEALTH_SCHEMA = "clusterd-health/v1"
BACKUP_SUMMARY_SCHEMA = "clusterd-backup-summary/v1"

# Instance names as clusterctl specs allow them (defense in depth for the
# logs route — the steward validates too, but the daemon never trusts).
INSTANCE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")

# verify_chain is a full-log scan; cache per state_dir for 30s so the
# public health probe stays cheap (issue #19).
_AUDIT_CHAIN_CACHE_TTL_S = 30.0
_audit_chain_cache: dict[str, tuple[float, bool]] = {}


def _audit_chain_ok(state_dir: str) -> bool:
    now = time.monotonic()
    cached = _audit_chain_cache.get(state_dir)
    if cached and now - cached[0] < _AUDIT_CHAIN_CACHE_TTL_S:
        return cached[1]
    try:
        ok = bool(audit.verify_chain(state_dir)["ok"])
    except Exception:
        ok = False  # an unreadable audit log is NOT a healthy one
    _audit_chain_cache[state_dir] = (now, ok)
    return ok


def _mirror_state(state_dir: str) -> str:
    """ "not-configured" | "ok" | "failing" (design §4 mirror placeholder).

    The v1 mirror is a directory stub (``state_dir/mirror/``); issue #15
    replaces it with real off-host targets. Configured-but-unwritable
    (or a recorded mirror error from the last append) is "failing" —
    health degrades WITHOUT dropping local events: audit.append_event
    never raises on mirror failure, it only records ``mirror-last-error``.
    """
    mirror_dir = Path(state_dir) / audit.MIRROR_DIR
    if not mirror_dir.is_dir():
        return "not-configured"
    if (Path(state_dir) / audit.MIRROR_ERROR_FILE).exists():
        return "failing"
    try:
        probe = mirror_dir / ".probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError:
        return "failing"
    return "ok"


def _operation_journal_state(state_dir: str | None) -> dict:
    if not state_dir:
        return {"state": "unavailable", "open": 0, "degraded": 0}
    try:
        journal = operation_journal.OperationJournal.existing(state_dir)
        if journal is not None:
            journal.validate()
        rows = [] if journal is None else journal.open_operations()
    except operation_journal.JournalError:
        return {"state": "unavailable", "open": 0, "degraded": 0}
    degraded = sum(row["state"] == "degraded" for row in rows)
    return {
        "state": "clean" if not rows else "attention-required",
        "open": len(rows),
        "degraded": degraded,
    }


@dataclasses.dataclass(frozen=True)
class Deps:
    """Server-level dependencies (injected; tests pass a FakeAdapter)."""

    config_path: str
    state_dir: str | None = None
    adapter_factory: Callable[[], object] | None = None
    matrix_client_factory: Callable[[str], object] | None = None
    fence_store_factory: Callable[[str], Any] | None = None
    clusterd_base_url: str = "http://127.0.0.1:8785"
    pager: paging.SnapshotPager = dataclasses.field(
        default_factory=paging.SnapshotPager
    )


@dataclasses.dataclass(frozen=True)
class RequestContext:
    """Per-request envelope (design §1).

    ``scope_token`` is the raw bearer token as sent (used ONLY for
    resolution, never logged). After auth enforcement (#18) ``actor``
    is the authenticated token actor and ``token_record`` carries the
    validated auth-token/v1 record (minus nothing — it never contains
    raw token material).
    """

    request_id: str
    actor: str
    scope_token: str | None
    idempotency_key: str | None = None
    token_record: dict | None = None
    action_digest: str | None = None  # consumed confirmation digest (#19)


@dataclasses.dataclass(frozen=True)
class Response:
    status: int
    body: object  # dict/list -> JSON, str -> raw
    content_type: str = "application/json"


def _error(
    status: int, message: str, action: str, target: str, request_id: str
) -> Response:
    """Structured error envelope mirroring clusterctl's error JSON."""
    return Response(
        status,
        {
            "error": message,
            "action": action,
            "target": target,
            "request_id": request_id,
        },
    )


def _adapter(deps: Deps):
    if deps.adapter_factory is None:
        return None  # clusterctl builds the live IncusAdapter itself
    return deps.adapter_factory()


def _run_cli(deps: Deps, ctx: RequestContext, argv: list[str]) -> Response:
    """Invoke clusterctl.cli.run with captured output; map exit -> HTTP.

    ``argv`` is a Python list built from a validated route and path
    params — never interpolated into a shell string.
    """
    full_argv = ["--config", deps.config_path]
    if deps.state_dir is not None:
        full_argv += ["--state-dir", deps.state_dir]
    full_argv += ["--actor", ctx.actor]
    full_argv += ["--request-id", ctx.request_id]
    if ctx.action_digest:
        full_argv += ["--action-digest", ctx.action_digest]
    full_argv += argv

    out_buf, err_buf = io.StringIO(), io.StringIO()
    with _CLI_LOCK:
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            code = cli.run(full_argv, adapter=_adapter(deps))
    out, err = out_buf.getvalue().strip(), err_buf.getvalue().strip()
    status = EXIT_TO_HTTP.get(code, 500)

    action = argv[0] if argv else "?"
    target = argv[1] if len(argv) > 1 else "?"
    if code == 0:
        try:
            return Response(status, json.loads(out) if out else {})
        except json.JSONDecodeError:
            return _error(
                500,
                f"clusterctl emitted non-JSON output: {out[:200]}",
                action,
                target,
                ctx.request_id,
            )
    # Error: clusterctl prints {error, action, target} JSON to stderr.
    try:
        payload = json.loads(err) if err else {}
    except json.JSONDecodeError:
        payload = {
            "error": err or f"clusterctl exited {code}",
            "action": action,
            "target": target,
        }
    payload["request_id"] = ctx.request_id
    return Response(status, payload)


# --------------------------------------------------------------------------
# route handlers
# --------------------------------------------------------------------------


def health(deps: Deps, ctx: RequestContext, **params) -> Response:
    """Liveness + clusterctl reachability probe.

    Reachable means a full read path (config load + spec load +
    adapter list) succeeds via the same code path as `clusterctl list`.
    Degraded answers 200 — the service itself is alive.
    """
    reachable = True
    try:
        adapter = _adapter(deps)
        with _CLI_LOCK:
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                argv = ["--config", deps.config_path]
                if deps.state_dir is not None:
                    argv += ["--state-dir", deps.state_dir]
                code = cli.run(argv + ["list", "--json"], adapter=adapter)
        reachable = code == 0
    except Exception:
        reachable = False
    state_dir = deps.state_dir
    if state_dir is None:
        try:
            state_dir = load_config(deps.config_path).state_dir
        except Exception:
            state_dir = None
    chain_ok = _audit_chain_ok(state_dir) if state_dir else False
    mirror = _mirror_state(state_dir) if state_dir else "failing"
    operations = _operation_journal_state(state_dir)
    # A broken audit chain or a configured-but-failing mirror degrades
    # health; local events are NEVER dropped for a mirror failure
    # (design §4 — the local log is the source of truth).
    healthy = (
        reachable
        and chain_ok
        and mirror != "failing"
        and operations["state"] == "clean"
    )
    return Response(
        200,
        {
            "schema": HEALTH_SCHEMA,
            "status": "ok" if healthy else "degraded",
            "version": __version__,
            "clusterctl_reachable": reachable,
            "audit_chain_ok": chain_ok,
            "mirror_state": mirror,
            "operation_journal": operations,
        },
    )


def openapi_yaml(deps: Deps, ctx: RequestContext, **params) -> Response:
    from .openapi import dump_openapi

    return Response(200, dump_openapi(), content_type="application/yaml")


def _request_owner(ctx: RequestContext) -> str:
    return str((ctx.token_record or {}).get("owner") or "*")


def _owner_instance_names(state_dir: str, owner: str) -> set[str] | None:
    """Declared instance allowlist; ``None`` means wildcard visibility."""
    if owner == "*":
        return None
    allowed: set[str] = set()
    inst_dir = Path(state_dir) / "instances"
    if not inst_dir.is_dir():
        return allowed
    for spec_file in inst_dir.glob("*.yaml"):
        try:
            raw = yaml.safe_load(spec_file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if (
            isinstance(raw, dict)
            and raw.get("created_by") == owner
            and isinstance(raw.get("name"), str)
        ):
            allowed.add(raw["name"])
    return allowed


def _cursor_error(ctx: RequestContext, exc: paging.CursorError) -> Response:
    return _error(
        409 if exc.stale else 400,
        exc.reason,
        "page",
        "cursor",
        ctx.request_id,
    )


def _page_or_resume(
    deps: Deps,
    ctx: RequestContext,
    *,
    query: dict | None,
    kind: str,
    filters: dict | None,
    build: Callable[[], tuple[list[object], int, bool]],
) -> Response:
    try:
        limit = paging.parse_limit(query)
        cursor = paging.query_cursor(query)
        binding = deps.pager.binding(kind, _request_owner(ctx), filters)
        if cursor is not None:
            return Response(
                200,
                deps.pager.resume(cursor, binding=binding, limit=limit),
            )
        items, observed_at_ms, truncated = build()
        return Response(
            200,
            deps.pager.first(
                items,
                binding=binding,
                limit=limit,
                observed_at_ms=observed_at_ms,
                truncated=truncated,
            ),
        )
    except paging.CursorError as exc:
        return _cursor_error(ctx, exc)


def _enrich_instance_records(deps: Deps, records: list[dict]) -> list[dict]:
    """Attach independently observed registry and Matrix-process states."""
    from clusterctl.embodiments import Registry, RegistryError

    observed_at_ms = int(time.time() * 1000)
    try:
        registry_by_id = {
            row["embodiment_id"]: row
            for row in Registry(_state_dir(deps)).list_all()
            if isinstance(row.get("embodiment_id"), str)
        }
        registry_error = None
    except RegistryError:
        registry_by_id = {}
        registry_error = "registry-unavailable"

    enriched: list[dict] = []
    for original in records:
        record = dict(original)
        observations = {
            key: dict(value)
            for key, value in (record.get("observations") or {}).items()
            if isinstance(value, dict)
        }
        embodiment_id = record.get("embodiment_id")
        registry = registry_by_id.get(embodiment_id)
        if registry_error is not None:
            embodiment = {
                "state": "unavailable",
                "observed_at_ms": observed_at_ms,
                "reason": registry_error,
            }
            incarnation = dict(embodiment)
        elif not isinstance(embodiment_id, str):
            embodiment = {"state": "absent", "observed_at_ms": observed_at_ms}
            incarnation = {"state": "absent", "observed_at_ms": observed_at_ms}
        elif registry is None:
            embodiment = {
                "state": "missing",
                "observed_at_ms": observed_at_ms,
                "embodiment_id": embodiment_id,
            }
            incarnation = {
                "state": "unavailable",
                "observed_at_ms": observed_at_ms,
                "reason": "embodiment-missing",
            }
        else:
            registry_state = str(registry.get("status") or "unknown")
            embodiment = {
                "state": registry_state,
                "observed_at_ms": observed_at_ms,
                "embodiment_id": embodiment_id,
                "body_ref": registry.get("body_ref"),
            }
            declared_incarnation = record.get("incarnation_id")
            current = registry.get("current_incarnation_id")
            if declared_incarnation and current and declared_incarnation != current:
                incarnation = {
                    "state": "contradictory",
                    "observed_at_ms": observed_at_ms,
                    "declared_incarnation_id": declared_incarnation,
                    "registry_incarnation_id": current,
                }
            elif current:
                open_record = next(
                    (
                        item
                        for item in registry.get("incarnations", [])
                        if item.get("incarnation_id") == current
                    ),
                    None,
                )
                incarnation = {
                    "state": (
                        "open"
                        if isinstance(open_record, dict)
                        and open_record.get("stopped_at_ms") is None
                        else "contradictory"
                    ),
                    "observed_at_ms": observed_at_ms,
                    "incarnation_id": current,
                }
            else:
                incarnation = {
                    "state": "absent",
                    "observed_at_ms": observed_at_ms,
                }

        if not isinstance(embodiment_id, str):
            matrix_process = {
                "state": "absent",
                "observed_at_ms": observed_at_ms,
            }
        elif deps.matrix_client_factory is None:
            matrix_process = {
                "state": "not-configured",
                "observed_at_ms": observed_at_ms,
            }
        elif registry is None or registry.get("status") != "running":
            matrix_process = {
                "state": "not-observed",
                "observed_at_ms": observed_at_ms,
                "reason": "embodiment-not-running",
            }
        else:
            try:
                client = deps.matrix_client_factory(embodiment_id)
                runtime = _matrix_result(getattr(client, "runtime_status", None))
                matrix_process = {
                    "state": "available",
                    "observed_at_ms": observed_at_ms,
                    "ledger_integrity": runtime.get("integrity"),
                }
            except Exception:  # noqa: BLE001 - redact process boundary
                matrix_process = {
                    "state": "down",
                    "observed_at_ms": observed_at_ms,
                }

        observations["embodiment"] = embodiment
        observations["incarnation"] = incarnation
        observations["matrix_process"] = matrix_process
        record["observations"] = observations
        enriched.append(record)
    return enriched


def list_instances(
    deps: Deps, ctx: RequestContext, query=None, **params
) -> Response:
    owner = _request_owner(ctx)

    def build() -> tuple[list[object], int, bool]:
        response = _run_cli(deps, ctx, ["list", "--json"])
        if response.status != 200 or not isinstance(response.body, list):
            raise RuntimeError("instance-inventory-unavailable")
        allowed = _owner_instance_names(_state_dir(deps), owner)
        visible = [
            row
            for row in response.body
            if allowed is None or row.get("name") in allowed
        ]
        truncated = len(visible) > paging.MAX_SNAPSHOT_ITEMS
        visible = visible[: paging.MAX_SNAPSHOT_ITEMS]
        enriched = _enrich_instance_records(deps, visible)
        observed = max(
            (int(row.get("observed_at_ms") or 0) for row in enriched),
            default=int(time.time() * 1000),
        )
        return list(enriched), observed, truncated

    return _page_or_resume(
        deps,
        ctx,
        query=query,
        kind="instances",
        filters=None,
        build=build,
    )


def get_instance(deps: Deps, ctx: RequestContext, name: str, **params) -> Response:
    owner = _request_owner(ctx)
    allowed = _owner_instance_names(_state_dir(deps), owner)
    if allowed is not None and name not in allowed:
        return _error(404, "instance not found", "status", name, ctx.request_id)
    response = _run_cli(deps, ctx, ["status", name, "--json"])
    if response.status == 200 and isinstance(response.body, dict):
        response = Response(
            200, _enrich_instance_records(deps, [response.body])[0]
        )
    return response


def logs(deps: Deps, ctx: RequestContext, name: str, query=None, **params) -> Response:
    """GET /v1/instances/{name}/logs?lines=N — bounded, redacted (issue #22).

    Pure delegation to ``clusterctl logs``: the bounded read and the
    secret redaction both live in clusterctl.lifecycle.cmd_logs; this
    handler only validates the name and binds the lines parameter.
    """
    if not INSTANCE_NAME_RE.fullmatch(name):
        return _error(
            400, f"invalid instance name {name!r}", "logs", name, ctx.request_id
        )
    raw = (query or {}).get("lines", [None])[0]
    if raw is None:
        n = lifecycle.LOGS_DEFAULT_LINES
    else:
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return _error(
                400, f"invalid lines parameter {raw!r}", "logs", name, ctx.request_id
            )
    n = max(1, min(n, lifecycle.LOGS_MAX_LINES))
    return _run_cli(deps, ctx, ["logs", name, "--lines", str(n), "--json"])


def power(deps: Deps, ctx: RequestContext, name: str, route=None, **params) -> Response:
    """POST /v1/instances/{name}/start|stop|restart.

    Idempotency-Key is REQUIRED (HTTP-side admission, mirrors the CLI
    contract); replay/dedupe itself is clusterctl's own store.
    """
    operation = route.path.rsplit("/", 1)[-1]
    if not ctx.idempotency_key:
        return _error(
            400, "Idempotency-Key header is required", operation, name, ctx.request_id
        )
    return _run_cli(
        deps, ctx, [operation, name, "--idempotency-key", ctx.idempotency_key, "--json"]
    )


def snapshot(
    deps: Deps, ctx: RequestContext, name: str, route=None, **params
) -> Response:
    """POST /v1/instances/{name}/snapshot — quiesced snapshot (issue #23).

    Pure delegation to ``clusterctl snapshot create``: the quiesce
    (park+checkpoint), capture, verify and manifest write all live in
    ``clusterctl.snapshot``. The CLI requires an idempotency key, so one
    is generated from the request id when the caller did not send an
    Idempotency-Key header (the steward's gated flow always sends one).
    """
    key = ctx.idempotency_key or f"clusterd-{ctx.request_id}"
    return _run_cli(
        deps, ctx, ["snapshot", "create", name, "--idempotency-key", key, "--json"]
    )


def park_wake(
    deps: Deps, ctx: RequestContext, name: str, route=None, **params
) -> Response:
    """POST /v1/instances/{name}/park|wake (issue #23).

    Delegates to the thin ``clusterctl park|wake`` commands, which apply
    the full lifecycle contract (admission, idempotency, lock, audit)
    around adapter.exec_quiesce_park / exec_unpark. Same shape as
    ``power``: Idempotency-Key required, dedupe is clusterctl's store.
    """
    operation = route.path.rsplit("/", 1)[-1]
    if not ctx.idempotency_key:
        return _error(
            400, "Idempotency-Key header is required", operation, name, ctx.request_id
        )
    return _run_cli(
        deps, ctx, [operation, name, "--idempotency-key", ctx.idempotency_key, "--json"]
    )


def list_backups(deps: Deps, ctx: RequestContext, **params) -> Response:
    """Newest cluster-backup-manifest/v1 per daimon.

    Reads the same manifest files ``clusterctl snapshot create`` writes
    under ``state_dir/backups/<name>/`` — no reimplementation of any
    capture logic, read-only.
    """
    state_dir = deps.state_dir
    if state_dir is None:
        state_dir = load_config(deps.config_path).state_dir
    backups_root = Path(state_dir) / "backups"
    allowed = _owner_instance_names(state_dir, _request_owner(ctx))
    entries = []
    if backups_root.is_dir():
        for daimon_dir in sorted(p for p in backups_root.iterdir() if p.is_dir()):
            if allowed is not None and daimon_dir.name not in allowed:
                continue
            manifests = sorted(daimon_dir.glob("*.json"))
            if not manifests:
                continue
            latest = manifests[-1]
            entry: dict[str, object] = {
                "schema": BACKUP_SUMMARY_SCHEMA,
                "name": daimon_dir.name,
            }
            try:
                entry["manifest"] = json.loads(latest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                entry["manifest"] = None
                entry["error"] = f"unreadable manifest: {exc}"
            entries.append(entry)
    return Response(200, entries)


# Secret redaction patterns mirror clusterctl.lifecycle.REDACT_PATTERNS.
_AUDIT_REDACT_PATTERNS = ("private key", "api_key", "token=", "bearer ", "sk-", "aiza")


def _redact_event_fields(event: dict) -> dict:
    """Apply case-insensitive redaction to event detail (defense in depth).

    The audit log is already redacted by clusterctl at append time, but
    this pass ensures no secret ever leaks through the read API.
    """
    detail = event.get("detail")
    if isinstance(detail, dict):
        redacted_detail = {}
        for k, v in detail.items():
            if isinstance(v, str):
                lower = v.lower()
                for pat in _AUDIT_REDACT_PATTERNS:
                    if pat in lower:
                        redacted_detail[k] = "[REDACTED]"
                        break
                else:
                    redacted_detail[k] = v
            else:
                redacted_detail[k] = v
        event = {**event, "detail": redacted_detail}
    # Also redact the target and action fields if they contain secrets
    # (belt-and-suspenders: clusterctl already redacts before append).
    for field in ("target", "action"):
        val = event.get(field)
        if isinstance(val, str):
            lower = val.lower()
            for pat in _AUDIT_REDACT_PATTERNS:
                if pat in lower:
                    event = {**event, field: "[REDACTED]"}
                    break
    return event


def audit_tail(deps: Deps, ctx: RequestContext, query=None, **params) -> Response:
    """GET /v1/audit — bounded snapshot tail with owner scoping."""
    state_dir = deps.state_dir
    if state_dir is None:
        state_dir = load_config(deps.config_path).state_dir

    q = query or {}
    filter_actor = (q.get("actor", [None])[0] or "").strip() or None
    filter_target = (q.get("target", [None])[0] or "").strip() or None
    filter_action = (q.get("action", [None])[0] or "").strip() or None
    owner = _request_owner(ctx)
    filters = {
        "actor": filter_actor,
        "target": filter_target,
        "action": filter_action,
    }

    def build() -> tuple[list[object], int, bool]:
        owner_allowlist = _owner_instance_names(state_dir, owner)
        if owner_allowlist is not None and not owner_allowlist:
            return [], int(time.time() * 1000), False
        events, scan_truncated = _bounded_reverse_audit_events(state_dir)
        result: list[object] = []
        truncated = scan_truncated
        for event in events:
            target = event.get("target") or ""
            if owner_allowlist is not None and target not in owner_allowlist:
                continue
            if filter_actor is not None and event.get("actor") != filter_actor:
                continue
            if filter_target is not None and target != filter_target:
                continue
            if filter_action is not None and event.get("action") != filter_action:
                continue
            if len(result) >= paging.MAX_SNAPSHOT_ITEMS:
                truncated = True
                break
            result.append(_redact_event_fields(event))
        return result, int(time.time() * 1000), truncated

    return _page_or_resume(
        deps,
        ctx,
        query=q,
        kind="audit",
        filters=filters,
        build=build,
    )


_AUDIT_SCAN_MAX_BYTES = 4 * 1024 * 1024
_AUDIT_SCAN_MAX_LINES = 10_000


def _bounded_reverse_audit_events(state_dir: str) -> tuple[list[dict], bool]:
    """Read a fixed append-only suffix; never load the whole audit log."""
    path = audit.audit_path(state_dir)
    if not path.is_file():
        return [], False
    with path.open("rb") as stream:
        descriptor = stream.fileno()
        end = stream.seek(0, 2)
        start = max(0, end - _AUDIT_SCAN_MAX_BYTES)
        raw = os.pread(descriptor, end - start, start)
        cut_first = start > 0 and os.pread(descriptor, 1, start - 1) != b"\n"
    lines = raw.splitlines()
    if cut_first and lines:
        lines = lines[1:]
    truncated = start > 0 or len(lines) > _AUDIT_SCAN_MAX_LINES
    lines = lines[-_AUDIT_SCAN_MAX_LINES:]
    result: list[dict] = []
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(event, dict):
            result.append(event)
    return result, truncated


def _state_dir(deps: Deps) -> str:
    return deps.state_dir or load_config(deps.config_path).state_dir


def list_embodiments(deps: Deps, ctx: RequestContext, **params) -> Response:
    """GET /v1/embodiments — body and incarnation registry."""
    return Response(200, _visible_embodiment_records(deps, ctx))


def list_resource_fences(deps: Deps, ctx: RequestContext, **params) -> Response:
    """GET /v1/resource-fences — active fences for concrete resources.

    These fences never assert exclusive presence for a being. They exclude
    concurrent writers only when their exact ``resource_ref`` is equal.
    """
    from clusterctl.fences import ResourceFenceStore

    state_dir = _state_dir(deps)
    store = (
        deps.fence_store_factory(state_dir)
        if deps.fence_store_factory is not None
        else ResourceFenceStore(state_dir)
    )
    fences = store.list_all()
    visible_ids = None if _request_owner(ctx) == "*" else {
        row.get("embodiment_id") for row in _visible_embodiment_records(deps, ctx)
    }
    return Response(200, [
        row for row in fences
        if not row.get("expired", True)
        and (visible_ids is None or row.get("holder_embodiment_id") in visible_ids)
    ])


def _matrix_result(call: object) -> dict:
    if not callable(call):
        raise TypeError("matrix_client_method_unavailable")
    _request, response = call()
    if (
        not isinstance(response, dict)
        or response.get("ok") is not True
        or not isinstance(response.get("result"), dict)
    ):
        raise RuntimeError("matrix_client_response_rejected")
    return response["result"]


def _projection_summary(value: object) -> dict:
    if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
        raise TypeError("matrix_projection_rejected")
    allowed = (
        "decision_event_id",
        "event_id",
        "invalid_projection_receipt_ids",
        "kind",
        "local_decision_chain",
        "origin",
        "projection_receipt_ids",
        "remote_decision_event_ids",
        "remote_projection_receipt_ids",
        "state",
        "subject",
    )
    return {
        "schema": value.get("schema"),
        "being_ref": value.get("being_ref"),
        "manifest_hash": value.get("manifest_hash"),
        "local_embodiment_id": value.get("local_embodiment_id"),
        "projection_hash": value.get("projection_hash"),
        "entries": [
            {field: entry.get(field) for field in allowed}
            for entry in value["entries"]
            if isinstance(entry, dict)
        ],
    }


_MATRIX_STATUS_MAX_ROWS = 100
_MATRIX_STATUS_MAX_MEMBERS = 100
_MATRIX_STATUS_MAX_TARGETS = 100
_MATRIX_STATUS_MAX_SUMMARIES = 100
_MATRIX_STATUS_MAX_ROW_BYTES = 64 * 1024
_MATRIX_STATUS_MAX_RESPONSE_BYTES = 1024 * 1024


def _visible_embodiment_records(deps: Deps, ctx: RequestContext) -> list[dict]:
    from clusterctl.embodiments import Registry

    records = Registry(_state_dir(deps)).list_all()
    owner = _request_owner(ctx)
    if owner == "*":
        return records
    visible_ids: set[str] = set()
    inst_dir = Path(_state_dir(deps)) / "instances"
    if inst_dir.is_dir():
        for path in inst_dir.glob("*.yaml"):
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                continue
            if (
                isinstance(raw, dict)
                and raw.get("created_by") == owner
                and isinstance(raw.get("embodiment_id"), str)
            ):
                visible_ids.add(raw["embodiment_id"])
    return [row for row in records if row.get("embodiment_id") in visible_ids]


def _matrix_sync_plan(client: object) -> dict:
    method = getattr(client, "scope_sync_plan", None)
    if not callable(method):
        raise TypeError("matrix_client_method_unavailable")
    _request, response = method(
        {"request_id": str(uuid.uuid4()), "limit": _MATRIX_STATUS_MAX_TARGETS}
    )
    if (
        not isinstance(response, dict)
        or response.get("ok") is not True
        or not isinstance(response.get("result"), dict)
    ):
        raise RuntimeError("matrix_client_response_rejected")
    return response["result"]


def _queue_observation(counts: dict) -> dict:
    incomplete = counts.get("incomplete_events")
    pending = counts.get("pending_rpc")
    if not isinstance(incomplete, int) or not isinstance(pending, int):
        state = "unknown"
    elif incomplete == 0 and pending == 0:
        state = "clean"
    else:
        state = "attention-required"
    return {
        "state": state,
        "incomplete_events": incomplete,
        "pending_rpc": pending,
        "scope": "owner-local",
    }


def _peer_reachability(topology: list[dict], local_id: str) -> dict:
    peers = [row for row in topology if row.get("embodiment_id") != local_id]
    available = sum(row.get("availability") == "available" for row in peers)
    offline = len(peers) - available
    if not peers:
        state = "none-observed"
    elif available == len(peers):
        state = "available"
    elif available:
        state = "partial"
    else:
        state = "offline"
    return {
        "state": state,
        "peer_count": len(peers),
        "available": available,
        "offline_or_unknown": offline,
    }


def _caught_up_observation(
    *, local_integrity: object, queue_state: str, peer_state: str,
    known_differences: int, partial: bool
) -> dict:
    if local_integrity != "ok":
        state, reason = "unknown", "owner-local-ledger-not-ok"
    elif queue_state != "clean":
        state, reason = "no", "owner-local-queue-not-clean"
    elif peer_state in {"offline", "partial"}:
        state, reason = "unknown", "peer-unreachable"
    elif peer_state == "none-observed":
        state, reason = "unknown", "no-peer-observation"
    elif partial:
        state, reason = "unknown", "matrix-view-partial"
    elif known_differences:
        state, reason = "no", "known-differences"
    else:
        state, reason = "yes", "all-observed-peers-caught-up"
    return {"state": state, "reason": reason}


def _matrix_alerts(
    *, integrity: object, queue_state: str, peer_state: str,
    known_differences: int, partial: bool,
) -> list[dict]:
    """Typed alerts; none of them aliases local cleanliness to convergence."""
    alerts: list[dict] = []
    if integrity != "ok":
        alerts.append({"code": "owner-local-ledger-not-ok", "severity": "critical"})
    if queue_state == "attention-required":
        alerts.append({"code": "owner-local-queue-attention", "severity": "warning"})
    elif queue_state == "unknown":
        alerts.append({"code": "owner-local-queue-unknown", "severity": "warning"})
    if peer_state in {"offline", "partial"}:
        alerts.append({"code": f"peer-{peer_state}", "severity": "warning"})
    elif peer_state == "none-observed":
        alerts.append({"code": "peer-observation-absent", "severity": "info"})
    if known_differences:
        alerts.append({
            "code": "known-peer-differences", "severity": "info",
            "count": known_differences,
        })
    if partial:
        alerts.append({"code": "matrix-view-partial", "severity": "warning"})
    return alerts


def _matrix_status_row(deps: Deps, record: dict, observed_at_ms: int) -> dict:
    embodiment_id = record["embodiment_id"]
    base = {
        "embodiment_id": embodiment_id,
        "incarnation_id": record.get("current_incarnation_id"),
        "embodiment_observation": {
            "state": record.get("status") or "unknown",
            "observed_at_ms": observed_at_ms,
        },
    }
    if deps.matrix_client_factory is None:
        return {
            **base,
            "matrix_process": {
                "state": "not-configured",
                "observed_at_ms": observed_at_ms,
            },
            "owner_local": {"state": "unavailable"},
            "peer_sync": {"state": "unavailable"},
            "alerts": [{"code": "matrix-not-configured", "severity": "info"}],
        }
    if record.get("status") != "running":
        return {
            **base,
            "matrix_process": {
                "state": "not-observed",
                "reason": "embodiment-not-running",
                "observed_at_ms": observed_at_ms,
            },
            "owner_local": {"state": "unavailable"},
            "peer_sync": {"state": "unavailable"},
            "alerts": [{"code": "embodiment-not-running", "severity": "info"}],
        }
    try:
        client = deps.matrix_client_factory(embodiment_id)
        runtime = _matrix_result(getattr(client, "runtime_status", None))
        me = _matrix_result(getattr(client, "scope_me", None))
        we = _matrix_result(getattr(client, "scope_we", None))
        difference = _matrix_result(getattr(client, "scope_diff", None))
        plan = _matrix_sync_plan(client)
    except Exception:  # noqa: BLE001 - membership-safe process boundary
        return {
            **base,
            "matrix_process": {
                "state": "down",
                "observed_at_ms": observed_at_ms,
            },
            "owner_local": {"state": "unavailable"},
            "peer_sync": {"state": "unavailable"},
            "alerts": [{"code": "matrix-process-down", "severity": "critical"}],
        }

    raw_counts = runtime.get("counts")
    counts: dict = raw_counts if isinstance(raw_counts, dict) else {}
    queue = _queue_observation(counts)
    raw_topology = [
        row for row in we.get("embodiments", []) if isinstance(row, dict)
    ]
    topology = [
        {
            field: member.get(field)
            for field in (
                "availability", "body_ref", "embodiment_id", "evidence_ref",
                "incarnation_id", "manifest_status",
            )
        }
        for member in raw_topology[:_MATRIX_STATUS_MAX_MEMBERS]
    ]
    reachability = _peer_reachability(raw_topology, embodiment_id)
    raw_entries = [
        row for row in difference.get("entries", []) if isinstance(row, dict)
    ]
    raw_summaries = [
        row for row in difference.get("origin_summaries", [])
        if isinstance(row, dict)
    ]
    raw_targets = [row for row in plan.get("targets", []) if isinstance(row, dict)]
    targets = []
    for target in raw_targets[:_MATRIX_STATUS_MAX_TARGETS]:
        request_hash = hashlib.sha256(
            json.dumps(
                target.get("request"), sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        targets.append({
            "availability": target.get("availability"),
            "embodiment_id": target.get("embodiment_id"),
            "evidence_ref": target.get("evidence_ref"),
            "incarnation_id": target.get("incarnation_id"),
            "request_hash": request_hash,
        })
    partial = bool(we.get("partial") or plan.get("partial"))
    caught_up = _caught_up_observation(
        local_integrity=runtime.get("integrity"),
        queue_state=queue["state"],
        peer_state=reachability["state"],
        known_differences=len(raw_entries),
        partial=partial,
    )
    alerts = _matrix_alerts(
        integrity=runtime.get("integrity"),
        queue_state=queue["state"],
        peer_state=reachability["state"],
        known_differences=len(raw_entries),
        partial=partial,
    )
    raw_effective = me.get("effective")
    effective: dict = raw_effective if isinstance(raw_effective, dict) else {}
    raw_heads = me.get("heads")
    heads: dict = raw_heads if isinstance(raw_heads, dict) else {}
    raw_authority_epoch = runtime.get("authority_epoch")
    authority_epoch: dict = (
        raw_authority_epoch if isinstance(raw_authority_epoch, dict) else {}
    )
    raw_body = me.get("body")
    body: dict = raw_body if isinstance(raw_body, dict) else {}
    return {
        **base,
        "matrix_process": {"state": "available", "observed_at_ms": observed_at_ms},
        "alerts": alerts,
        "owner_local": {
            "state": "observed",
            "observed_at_ms": observed_at_ms,
            "ledger_integrity": runtime.get("integrity"),
            "queue": queue,
            "known_events": counts.get("known_events"),
            "ledger_schema_version": runtime.get("ledger_schema_version"),
            "authority_epoch": {
                field: authority_epoch.get(field)
                for field in (
                    "schema", "active_manifest_hash",
                    "accepted_manifest_hashes", "epoch_count",
                )
            },
        },
        "identity_view": {
            "being_ref": me.get("being_ref"),
            "manifest_hash": me.get("manifest_hash"),
            "evaluated_at_ms": me.get("evaluated_at_ms"),
            "body": {
                field: body.get(field)
                for field in (
                    "schema", "body_ref", "embodiment_id", "incarnation_id",
                    "observed_at_ms", "state", "resource_fences",
                )
            },
            "head_count": len(heads),
            "effective": {
                "schema": effective.get("schema"),
                "projection_hash": effective.get("projection_hash"),
                "entry_count": len(effective.get("entries", []))
                if isinstance(effective.get("entries"), list) else None,
            },
        },
        "peer_sync": {
            "state": "observed",
            "observed_at_ms": observed_at_ms,
            "reachability": reachability,
            "last_successful_sync": {
                "state": "unavailable",
                "at_ms": None,
                "reason": "not-exposed-by-matrix-contract",
            },
            "known_difference_count": len(raw_entries),
            "caught_up": caught_up,
            "partial": partial,
            "topology": topology,
            "topology_count": len(raw_topology),
            "topology_truncated": len(raw_topology) > len(topology),
            "origin_summaries": [
                {
                    "embodiment_id": summary.get("embodiment_id"),
                    "states": summary.get("states"),
                }
                for summary in raw_summaries[:_MATRIX_STATUS_MAX_SUMMARIES]
            ],
            "origin_summaries_truncated": (
                len(raw_summaries) > _MATRIX_STATUS_MAX_SUMMARIES
            ),
            "sync_targets": targets,
            "sync_target_count": len(raw_targets),
            "sync_targets_truncated": len(raw_targets) > len(targets),
            "differences_path": (
                "/v1/weave/differences?embodiment_id=" + embodiment_id
            ),
        },
    }


def _redacted_matrix_status(deps: Deps, ctx: RequestContext) -> Response:
    from clusterctl.matrix_host import MATRIX_CONTRACT_COMMIT, MATRIX_STATUS_SCHEMA

    observed_at_ms = int(time.time() * 1000)
    records = _visible_embodiment_records(deps, ctx)
    rows: list[dict] = []
    admitted_bytes = 0
    for record in records[:_MATRIX_STATUS_MAX_ROWS]:
        row = _matrix_status_row(deps, record, observed_at_ms)
        encoded = json.dumps(
            row, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(encoded) > _MATRIX_STATUS_MAX_ROW_BYTES:
            identifier = record.get("embodiment_id")
            if not isinstance(identifier, str) or len(identifier) > 256:
                identifier = "[oversized-identifier]"
            row = {
                "embodiment_id": identifier,
                "embodiment_observation": {
                    "state": record.get("status") or "unknown",
                    "observed_at_ms": observed_at_ms,
                },
                "matrix_process": {
                    "state": "available",
                    "observed_at_ms": observed_at_ms,
                },
                "owner_local": {
                    "state": "unavailable", "reason": "read-model-overflow",
                },
                "peer_sync": {
                    "state": "unavailable", "reason": "read-model-overflow",
                },
            }
            encoded = json.dumps(row, separators=(",", ":")).encode()
        if admitted_bytes + len(encoded) > _MATRIX_STATUS_MAX_RESPONSE_BYTES:
            break
        rows.append(row)
        admitted_bytes += len(encoded)
    return Response(200, {
        "schema": MATRIX_STATUS_SCHEMA,
        "read_model_version": 2,
        "configured": deps.matrix_client_factory is not None,
        "implementation": "installed-daimon-matrix",
        "matrix_contract_commit": MATRIX_CONTRACT_COMMIT,
        "observed_at_ms": observed_at_ms,
        "embodiments": rows,
        "embodiment_count": len(records),
        "embodiments_truncated": len(records) > len(rows),
        "response_budget_bytes": _MATRIX_STATUS_MAX_RESPONSE_BYTES,
    })


def weave_status(deps: Deps, ctx: RequestContext, **params) -> Response:
    """GET /v1/weave/status; partial failures remain per embodiment."""
    try:
        return _redacted_matrix_status(deps, ctx)
    except Exception:  # noqa: BLE001 - membership-safe HTTP failure boundary
        return Response(503, {
            "schema": "dm.cluster-matrix-status/v1",
            "read_model_version": 2,
            "configured": deps.matrix_client_factory is not None,
            "implementation": "installed-daimon-matrix",
            "error": "matrix-status-unavailable",
            "action": "status",
            "target": "weave",
            "request_id": ctx.request_id,
        })


def weave_differences(
    deps: Deps, ctx: RequestContext, query=None, **params
) -> Response:
    """Paginated, redacted Matrix differences for one visible embodiment."""
    q = query or {}
    embodiment_id = (q.get("embodiment_id", [None])[0] or "").strip()
    if not embodiment_id:
        return _error(
            400, "embodiment_id is required", "differences", "weave",
            ctx.request_id,
        )
    visible = {
        row.get("embodiment_id"): row for row in _visible_embodiment_records(deps, ctx)
    }
    record = visible.get(embodiment_id)
    if record is None:
        return _error(404, "embodiment not found", "differences", embodiment_id,
                      ctx.request_id)

    def build() -> tuple[list[object], int, bool]:
        if deps.matrix_client_factory is None:
            raise RuntimeError("matrix-client-not-configured")
        if record.get("status") != "running":
            raise RuntimeError("matrix-process-not-running")
        client = deps.matrix_client_factory(embodiment_id)
        difference = _matrix_result(getattr(client, "scope_diff", None))
        projection = _projection_summary({
            **difference,
            "schema": "dm.we.projection/v1",
        })
        entries = projection["entries"]
        truncated = len(entries) > paging.MAX_SNAPSHOT_ITEMS
        return (
            entries[:paging.MAX_SNAPSHOT_ITEMS],
            int(time.time() * 1000),
            truncated,
        )

    try:
        return _page_or_resume(
            deps,
            ctx,
            query=q,
            kind="weave-differences",
            filters={"embodiment_id": embodiment_id},
            build=build,
        )
    except Exception:  # noqa: BLE001 - membership-safe Matrix boundary
        return Response(503, {
            "error": "matrix-differences-unavailable",
            "action": "differences",
            "target": "weave",
            "request_id": ctx.request_id,
        })


def dashboard(deps: Deps, ctx: RequestContext, **params) -> Response:
    """GET /v1/dashboard — HTMX fleet dashboard (single-page app).

    Serves a static HTML shell that uses HTMX + the same /v1 API
    endpoints as the steward tools. No parallel logic — every data
    section fetches from the read routes.
    """
    html = _DASHBOARD_HTML
    return Response(200, html, content_type="text/html; charset=utf-8")


def destroy(
    deps: Deps, ctx: RequestContext, name: str, route=None, **params
) -> Response:
    """POST /v1/instances/{name}/destroy — destructive-class placeholder.

    The confirmation machinery (challenge issue/validate/consume) runs
    in server middleware BEFORE this handler; reaching here means a
    valid single-use confirmation was consumed. Execution (archive-first
    destroy, #8 §3) is a later milestone.
    """
    return _error(
        501,
        "destroy confirmed; execution is a later milestone",
        "destroy",
        name,
        ctx.request_id,
    )


def dashboard_prepare(
    deps: Deps, ctx: RequestContext, route=None, query=None, _body=None, **params
) -> Response:
    """POST /v1/dashboard/prepare — propose a mutation, return plan JSON.

    Reads operation + target from JSON body, calls the appropriate
    steward_tools.mutations.propose_<op>, returns the MutationPlan as JSON.
    NO mutation occurs. For restore: checks instance state first (409 if running).
    """
    body = _body or {}
    operation = str(body.get("operation", "")).strip()
    target = str(body.get("target", "")).strip()

    if not operation or not target:
        return _error(
            400,
            "operation and target are required",
            operation or "?",
            target or "?",
            ctx.request_id,
        )

    valid_ops = {"start", "stop", "restart", "snapshot", "destroy", "restore"}
    if operation not in valid_ops:
        return _error(
            400, f"unknown operation {operation!r}", operation, target, ctx.request_id
        )

    # restore pre-condition: instance must not be running
    if operation == "restore":
        resp = get_instance(deps, ctx, target)
        if resp.status == 200 and isinstance(resp.body, dict):
            state = str(resp.body.get("state", "")).lower()
            if state == "running":
                return _error(
                    409,
                    "instance must be stopped before restore",
                    operation,
                    target,
                    ctx.request_id,
                )

    proposers: dict[str, Callable[..., mutations.MutationPlan]] = {
        "start": mutations.propose_start,
        "stop": mutations.propose_stop,
        "restart": mutations.propose_restart,
        "snapshot": mutations.propose_snapshot,
        "destroy": mutations.propose_destroy,
        "restore": mutations.propose_restore,
    }
    _propose = proposers[operation]

    try:
        # The dashboard's own bearer token authorizes the mutation call —
        # propose_destroy talks to clusterd for its challenge; a bare
        # MutationClient would read the steward's token FILE, which does
        # not exist on the host (FileNotFoundError, drill #26 finding).
        if operation == "destroy":
            mc = mutations.MutationClient(token_override=ctx.scope_token)
            plan = _propose(target, client=mc)
        else:
            plan = _propose(target)
    except ValueError as exc:
        return _error(400, str(exc), operation, target, ctx.request_id)
    except Exception as exc:
        return _error(
            502, f"clusterd internal: {exc!r}", operation, target, ctx.request_id
        )

    plan_dict = dataclasses.asdict(plan)
    return Response(200, plan_dict)


def _plan_from_json(plan_json: dict) -> mutations.MutationPlan:
    """Reconstruct a MutationPlan from its JSON dict representation."""
    return mutations.MutationPlan(
        operation=plan_json.get("operation", ""),
        target=plan_json.get("target", ""),
        impact=plan_json.get("impact", ""),
        destructive=plan_json.get("destructive", False),
        action_digest=plan_json.get("action_digest", ""),
        created_ms=plan_json.get("created_ms", 0),
        ttl_s=plan_json.get("ttl_s", mutations.PLAN_TTL_S),
        challenge_token=plan_json.get("challenge_token"),
        display_text=plan_json.get("display_text", ""),
        actor=plan_json.get("actor", mutations.PLAN_ACTOR),
        args=dict(plan_json.get("args") or {}),
        used=plan_json.get("used", False),
    )


def dashboard_confirm(
    deps: Deps, ctx: RequestContext, route=None, query=None, _body=None, **params
) -> Response:
    """POST /v1/dashboard/confirm — execute a previously proposed plan.

    Reconstructs the MutationPlan from the JSON body, validates typed-name
    for destructive operations, then calls confirm_plan with the dashboard's
    bearer token as the mutation auth. Returns the result dict inline.
    """
    body = _body or {}
    operation = str(body.get("operation", "")).strip()
    target = str(body.get("target", "")).strip()
    plan_json = body.get("plan") or {}
    human_turn_id = str(body.get("human_turn_id", str(int(time.time()))))

    if not plan_json:
        return _error(
            400,
            "plan is required (field 'plan' missing)",
            operation or "?",
            target or "?",
            ctx.request_id,
        )

    plan = _plan_from_json(plan_json)

    # Destroy: server-side typed-name validation (defense in depth —
    # client-side also validates, but we never trust the client).
    if plan.operation == "destroy":
        typed_name = str(body.get("typed_name", "")).strip()
        if not typed_name or typed_name != plan.target:
            return Response(
                400,
                {
                    "schema": mutations.RESULT_SCHEMA,
                    "ok": False,
                    "operation": operation,
                    "target": target,
                    "refused": "typed-name-mismatch",
                    "error": "typed_name must EXACTLY match the target (case-sensitive)",
                },
            )
    else:
        typed_name = None

    # Use the dashboard's bearer token for the mutation call.
    mc = mutations.MutationClient(token_override=ctx.scope_token)
    result = mutations.confirm_plan(
        plan,
        human_turn_id=human_turn_id,
        typed_name=typed_name,
        client=mc,
    )

    if result.get("ok"):
        return Response(200, result)
    elif result.get("refused"):
        return Response(400, result)
    else:
        return Response(500, result)


def restore_instance(
    deps: Deps, ctx: RequestContext, name: str, route=None, **params
) -> Response:
    """POST /v1/instances/{name}/restore — placeholder.

    Execution (snapshot-to-instance restore) is a later milestone.
    The pre-condition check (instance must be stopped) runs in the
    dashboard_prepare route.
    """
    return _error(
        501,
        "restore confirmed; execution is a later milestone",
        "restore",
        name,
        ctx.request_id,
    )


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Daimon Fleet Dashboard</title>
<script src="https://unpkg.com/htmx.org@1.9.12"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#c9d1d9;--muted:#8b949e;--accent:#58a6ff;
  --ok:#3fb950;--degraded:#d29922;--bad:#f85149;--info:#79c0ff;
}
html,body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5}
body{max-width:1000px;margin:0 auto;padding:16px}
h1{font-size:1.4rem;font-weight:600;margin-bottom:4px}
h2{font-size:1rem;font-weight:600;margin-bottom:8px;color:var(--text)}
.badge{display:inline-block;padding:1px 8px;border-radius:12px;font-size:0.75rem;font-weight:600;text-transform:uppercase}
.badge-ok{background:var(--ok);color:#000}
.badge-degraded{background:var(--degraded);color:#000}
.badge-bad{background:var(--bad);color:#fff}
.badge-info{background:var(--info);color:#000}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:10px}
.row{display:flex;flex-wrap:wrap;gap:10px}
.col{flex:1;min-width:200px}
.section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
.muted{color:var(--muted);font-size:0.82rem}
.bar-wrap{background:var(--bg);border-radius:4px;height:8px;margin:3px 0;overflow:hidden}
.bar{height:100%;border-radius:4px;transition:width .3s}
.bar-ok{background:var(--ok)}.bar-warn{background:var(--degraded)}.bar-crit{background:var(--bad)}
.tag{display:inline-block;padding:0 6px;border-radius:4px;font-size:0.72rem;background:var(--bg);color:var(--muted);margin-right:4px}
.btn{display:inline-block;padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;font-size:0.85rem;text-decoration:none}
.btn:hover{background:#1f2937;border-color:var(--accent)}
.btn-active{background:var(--accent);color:#000;border-color:var(--accent)}
.btn-sm{padding:3px 10px;font-size:0.75rem}
input{border:1px solid var(--border);border-radius:6px;padding:7px 12px;background:var(--bg);color:var(--text);font-size:0.9rem;width:100%}
input:focus{outline:none;border-color:var(--accent)}
.alert{background:var(--surface);border:1px solid var(--degraded);border-radius:8px;padding:12px;color:var(--degraded)}
.alert a{color:var(--accent);cursor:pointer}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
@media(max-width:700px){.grid-2{grid-template-columns:1fr}.row{flex-direction:column}}
#auth-prompt{max-width:420px;margin:60px auto;text-align:center}
#auth-prompt h1{margin-bottom:16px}
#auth-prompt input{margin-bottom:10px}
.activity-list{max-height:320px;overflow-y:auto}
.activity-item{padding:5px 0;border-bottom:1px solid var(--border);font-size:0.82rem}
.activity-item:last-child{border-bottom:none}
.filter-bar{margin-bottom:8px;display:flex;gap:6px;flex-wrap:wrap}
.retry-link{color:var(--accent);cursor:pointer;text-decoration:underline;font-size:0.82rem}
.digest-trunc{font-family:monospace;font-size:0.7rem;color:var(--muted)}
.kbd{font-size:0.7rem;color:var(--muted);margin-left:auto}
</style>
</head>
<body>

<div id="auth-prompt">
  <h1>⚡ Daimon Fleet</h1>
  <p class="muted" style="margin-bottom:14px">Paste your clusterd bearer token to view the fleet.</p>
  <input type="password" id="token-input" placeholder="dcd_..." autocomplete="off">
  <button class="btn btn-active" style="width:100%;margin-top:6px" onclick="authenticate()">Authenticate</button>
  <p id="auth-error" style="color:var(--bad);margin-top:8px;display:none"></p>
</div>

<div id="dashboard" style="display:none">
  <div class="section-header" style="margin-bottom:12px">
    <h1>⚡ Daimon Fleet</h1>
    <span class="kbd">Tab to navigate · auto-refresh 30s</span>
  </div>

  <!-- Health Row -->
  <div class="card" id="health-card">
    <div class="section-header"><h2>System Health</h2></div>
    <div id="health-content" hx-get="/v1/health" hx-trigger="load, every 30s"
         hx-swap="innerHTML" hx-target="#health-content"
         hx-on::after-request="renderHealth(event)">
      <p class="muted">Loading...</p>
    </div>
  </div>

  <!-- Fleet View -->
  <div class="card" id="fleet-card">
    <div class="section-header"><h2>Fleet</h2></div>
    <div id="fleet-content" hx-get="/v1/instances" hx-trigger="load, every 10s, refresh"
         hx-swap="innerHTML" hx-target="#fleet-content"
         hx-on::after-request="renderFleet(event)">
      <p class="muted">Loading...</p>
    </div>
  </div>

  <!-- Same-being plurality and synchronization -->
  <div class="card" id="we-card">
    <div class="section-header"><h2>/we — Embodiments and Weave</h2></div>
    <div id="weave-content" hx-get="/v1/weave/status" hx-trigger="load, every 10s"
         hx-swap="innerHTML" hx-target="#weave-content"
         hx-on::after-request="renderWeave(event)"><p class="muted">Loading...</p></div>
    <div class="grid-2" style="margin-top:8px">
      <div id="embodiments-content" hx-get="/v1/embodiments" hx-trigger="load, every 10s"
           hx-swap="innerHTML" hx-target="#embodiments-content"
           hx-on::after-request="renderEmbodiments(event)"><p class="muted">Loading embodiments...</p></div>
      <div id="fences-content" hx-get="/v1/resource-fences" hx-trigger="load, every 10s"
           hx-swap="innerHTML" hx-target="#fences-content"
           hx-on::after-request="renderFences(event)"><p class="muted">Loading resource fences...</p></div>
    </div>
  </div>

  <!-- Backups -->
  <div class="card" id="backups-card">
    <div class="section-header"><h2>Snapshots (per-daimon)</h2></div>
    <div id="backups-content" hx-get="/v1/backups" hx-trigger="load, every 30s"
         hx-swap="innerHTML" hx-target="#backups-content"
         hx-on::after-request="renderBackups(event)">
      <p class="muted">Loading...</p>
    </div>
  </div>

  <!-- Activity Stream -->
  <div class="card" id="activity-card">
    <div class="section-header"><h2>Activity</h2></div>
    <div class="filter-bar" id="activity-filters">
      <button class="btn btn-sm btn-active filter-btn" data-filter="all">all</button>
      <button class="btn btn-sm filter-btn" data-filter="actor">by actor</button>
      <button class="btn btn-sm filter-btn" data-filter="action">by action</button>
    </div>
    <div id="activity-content" hx-get="/v1/audit?limit=30" hx-trigger="load, every 10s, refresh"
         hx-swap="innerHTML" hx-target="#activity-content"
         hx-on::after-request="renderActivity(event)">
      <p class="muted">Loading...</p>
    </div>
  </div>
</div>

<script>
// ── Token management ──────────────────────────────────────────────
function getToken(){return sessionStorage.getItem('clusterd_token')||''}
function setToken(t){sessionStorage.setItem('clusterd_token',t)}
function clearToken(){sessionStorage.removeItem('clusterd_token')}

function authenticate(){
  var tok=document.getElementById('token-input').value.trim();
  var err=document.getElementById('auth-error');
  if(!tok){err.textContent='Enter a bearer token';err.style.display='block';return}
  setToken(tok);
  document.body.addEventListener('htmx:configRequest',function(ev){
    ev.detail.headers['Authorization']='Bearer '+getToken();
  });
  // Verify token works by hitting health
  fetch('/v1/health',{headers:{'Authorization':'Bearer '+tok}})
    .then(function(r){
      if(!r.ok)throw new Error('Invalid token ('+r.status+')');
      document.getElementById('auth-prompt').style.display='none';
      document.getElementById('dashboard').style.display='block';
      htmx.trigger('#health-content','load');
      htmx.trigger('#fleet-content','load');
      htmx.trigger('#weave-content','load');
      htmx.trigger('#embodiments-content','load');
      htmx.trigger('#fences-content','load');
      htmx.trigger('#backups-content','load');
      htmx.trigger('#activity-content','load');
    })
    .catch(function(e){
      clearToken();
      err.textContent=e.message;err.style.display='block';
    });
}

// On page load, if token exists, try it
(function(){
  var tok=getToken();
  if(tok){
    document.body.addEventListener('htmx:configRequest',function(ev){
      ev.detail.headers['Authorization']='Bearer '+getToken();
    });
    document.getElementById('token-input').value=tok;
    authenticate();
  }
})();

// ── Render helpers ────────────────────────────────────────────────
function stateBadge(s){
  if(!s)return '<span class="badge badge-degraded">unknown</span>';
  var lower=s.toLowerCase();
  if(lower==='running'||lower==='ok'||lower==='awake'||lower==='coherent'||lower==='local')return '<span class="badge badge-ok">'+s+'</span>';
  if(lower==='degraded'||lower==='pending'||lower==='unknown')return '<span class="badge badge-degraded">'+s+'</span>';
  if(lower==='stopped'||lower==='error'||lower==='unreachable'||lower==='gap'||lower==='quarantined')return '<span class="badge badge-bad">'+s+'</span>';
  return '<span class="badge badge-info">'+s+'</span>';
}

function capBar(pct,label){
  var cls='bar-ok'; if(pct>70)cls='bar-warn'; if(pct>90)cls='bar-crit';
  return '<div style="font-size:0.72rem;display:flex;justify-content:space-between"><span>'+label+'</span><span>'+Math.round(pct)+'%</span></div>'
    +'<div class="bar-wrap"><div class="bar '+cls+'" style="width:'+Math.min(pct,100)+'%"></div></div>';
}

function ageStr(ms){
  if(ms==null)return '—';
  var s=ms/1000,m=s/60,h=m/60,d=h/24;
  if(d>=1)return Math.round(d)+'d ago';
  if(h>=1)return Math.round(h)+'h ago';
  if(m>=1)return Math.round(m)+'m ago';
  return Math.round(s)+'s ago';
}

function ageClass(ms,amberH,redH){
  if(ms==null)return'badge-info';
  var h=ms/3600000;
  if(h>redH)return'badge-bad';
  if(h>amberH)return'badge-degraded';
  return'badge-ok';
}

function truncDigest(d){return d?d.substring(0,10):'—';}

// ── Section renderers (called by hx-on::after-request) ────────────
function renderHealth(event){
  var el=document.getElementById('health-content');
  try{
    var d=JSON.parse(event.detail.xhr.responseText);
    var h='<div class="row">';
    h+='<div class="col"><span class="muted">Status </span>'+stateBadge(d.status)
      +' <span class="tag">v'+d.version+'</span></div>';
    h+='<div class="col"><span class="muted">Audit Chain </span>'
      +(d.audit_chain_ok?'<span class="badge badge-ok">ok</span>':'<span class="badge badge-bad">broken</span>')+'</div>';
    h+='<div class="col"><span class="muted">Mirror </span>'+stateBadge(d.mirror_state)+'</div>';
    h+='</div>';
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No data <span class="retry-link" onclick="htmx.trigger(\'#health-content\',\'load\')">retry</span></div>'}
}

function renderFleet(event){
  var el=document.getElementById('fleet-content');
  try{
    var page=JSON.parse(event.detail.xhr.responseText);
    var daimons=page&&Array.isArray(page.items)?page.items:[];
    if(!Array.isArray(daimons)||daimons.length===0){el.innerHTML='<p class="muted">No daimons declared.</p>';return}
    var h='';
    daimons.forEach(function(d,i){
      var tabindex=i+1;
      var uptime=d.uptime_s!=null?Math.round(d.uptime_s/3600)+'h':'—';
      h+='<div class="card" tabindex="'+tabindex+'" style="cursor:default">';
      h+='<div class="section-header">';
      h+='<strong style="font-size:0.95rem">'+escHtml(d.name)+'</strong>';
      h+='<span>'+stateBadge(d.state)+'</span></div>';
      h+='<div class="muted">';
      h+='<span>species: '+escHtml(d.species||'—')+'</span>';
      h+='<span style="margin-left:12px">image: '+escHtml(d.image_version||'—')+'</span>';
      h+='<span style="margin-left:12px">uptime: '+uptime+'</span>';
      h+='</div>';
      var o=d.observations||{};
      h+='<div class="muted" style="margin-top:4px">declared '
        +stateBadge((o.declared||{}).state)+' · runtime '+stateBadge((o.runtime||{}).state)
        +' · embodiment '+stateBadge((o.embodiment||{}).state)
        +' · incarnation '+stateBadge((o.incarnation||{}).state)
        +' · Matrix process '+stateBadge((o.matrix_process||{}).state)+'</div>';
      var b=d.budgets||{};
      var u=d.usage||{};
      var cpuPct=u.cpu_pct!=null?u.cpu_pct:0;
      var memPct=u.mem_pct!=null?u.mem_pct:0;
      var diskPct=u.disk_pct!=null?u.disk_pct:0;
      if(cpuPct||memPct||diskPct){
        h+='<div style="margin-top:6px">';
        h+=capBar(cpuPct,'CPU');h+=capBar(memPct,'MEM');h+=capBar(diskPct,'Disk');
        h+='</div>';
      }
      h+='<div id="confirm-'+escHtml(d.name)+'" style="margin-top:6px"></div>';
      h+='<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">';
      var st=d.state?d.state.toLowerCase():'';
      if(st!=='running')h+='<button class="btn btn-sm" onclick="dashPrepare(\''+escHtml(d.name)+'\',\'start\')">\u25b6 Start</button>';
      if(st==='running')h+='<button class="btn btn-sm" onclick="dashPrepare(\''+escHtml(d.name)+'\',\'stop\')">\u23f9 Stop</button>';
      if(st==='running')h+='<button class="btn btn-sm" onclick="dashPrepare(\''+escHtml(d.name)+'\',\'restart\')">\u21bb Restart</button>';
      h+='<button class="btn btn-sm" onclick="dashPrepare(\''+escHtml(d.name)+'\',\'snapshot\')">\ud83d\udcf8 Backup</button>';
      h+='<button class="btn btn-sm" style="border-color:var(--bad);color:var(--bad)" onclick="dashPrepare(\''+escHtml(d.name)+'\',\'destroy\')">\ud83d\uddd1 Destroy</button>';
      if(st==='stopped')h+='<button class="btn btn-sm" onclick="dashPrepare(\''+escHtml(d.name)+'\',\'restore\')">\u267b Restore</button>';
      h+='</div>';
      h+='</div>';
    });
    if(page.page&&page.page.truncated)h+='<p class="alert">Inventory snapshot was bounded; refine the owner scope before acting.</p>';
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No data <span class="retry-link" onclick="htmx.trigger(\'#fleet-content\',\'load\')">retry</span></div>'}
}

function renderWeave(event){
  var el=document.getElementById('weave-content');
  try{
    var d=JSON.parse(event.detail.xhr.responseText);
    if(!d.configured){el.innerHTML='<p class="muted">Weave runtime not configured on this host.</p>';return}
    var rows=Array.isArray(d.embodiments)?d.embodiments:[];
    var h='';
    if(!rows.length)h='<p class="muted">No visible embodiments registered.</p>';
    rows.forEach(function(row){
      var local=row.owner_local||{}, peer=row.peer_sync||{}, reach=peer.reachability||{};
      var queue=local.queue||{}, caught=peer.caught_up||{};
      h+='<div class="activity-item"><code>'+escHtml(row.embodiment_id)+'</code> · embodiment '
        +stateBadge((row.embodiment_observation||{}).state)+' · Matrix process '
        +stateBadge((row.matrix_process||{}).state)+'<br>';
      h+='<span class="muted">owner-local ledger: '+escHtml(local.ledger_integrity||local.state||'unavailable')
        +' · owner-local queue: '+escHtml(queue.state||'unavailable')
        +' · peer reachability: '+escHtml(reach.state||peer.state||'unavailable')
        +' · known differences: '+escHtml(peer.known_difference_count==null?'unknown':peer.known_difference_count)
        +' · caught up: '+escHtml(caught.state||'unknown')+' ('+escHtml(caught.reason||'not observed')+')</span></div>';
      (row.alerts||[]).forEach(function(alert){
        var cls=alert.severity==='critical'?'badge-bad':alert.severity==='warning'?'badge-degraded':'badge-info';
        h+='<span class="badge '+cls+'" style="margin-right:4px">'+escHtml(alert.code)+'</span>';
      });
    });
    if(d.embodiments_truncated)h+='<p class="alert">Embodiment status is bounded; not every visible record is shown.</p>';
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No Weave status</div>'}
}

function renderEmbodiments(event){
  var el=document.getElementById('embodiments-content');
  try{
    var rows=JSON.parse(event.detail.xhr.responseText);
    var h='<strong style="font-size:0.85rem">Embodiments</strong>';
    if(!rows.length){el.innerHTML=h+'<p class="muted">None registered.</p>';return}
    rows.forEach(function(row){h+='<div class="activity-item">'+stateBadge(row.status)
      +' <code>'+escHtml(row.body_ref)+'</code><br><span class="muted">'
      +escHtml(row.embodiment_id)+' · incarnation '+escHtml(row.current_incarnation_id||'stopped')+'</span></div>'});
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No embodiment data</div>'}
}

function renderFences(event){
  var el=document.getElementById('fences-content');
  try{
    var rows=JSON.parse(event.detail.xhr.responseText);
    var h='<strong style="font-size:0.85rem">Resource fences</strong>';
    if(!rows.length){el.innerHTML=h+'<p class="muted">No active fences.</p>';return}
    rows.forEach(function(row){h+='<div class="activity-item"><code>'+escHtml(row.resource_ref||'?')
      +'</code> <span class="tag">epoch '+escHtml(row.last_epoch)+'</span><br><span class="muted">holder '
      +escHtml(row.holder_embodiment_id||'?')+'</span></div>'});
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No resource-fence data</div>'}
}

function renderBackups(event){
  var el=document.getElementById('backups-content');
  try{
    var backups=JSON.parse(event.detail.xhr.responseText);
    if(!Array.isArray(backups)||backups.length===0){el.innerHTML='<p class="muted">No backups found.</p>';return}
    var now=Date.now();
    var h='<div class="grid-2">';
    backups.forEach(function(b){
      var m=b.manifest;
      var ageMs=m&&m.created_ms?now-m.created_ms:null;
      var cls=ageClass(ageMs,24,48);
      h+='<div class="card" style="padding:8px 12px">';
      h+='<div style="display:flex;justify-content:space-between">';
      h+='<strong style="font-size:0.85rem">'+escHtml(b.name)+'</strong>';
      h+='<span class="badge '+cls+'">'+ageStr(ageMs)+'</span>';
      h+='</div>';
      if(b.error)h+='<div class="muted" style="color:var(--bad)">'+escHtml(b.error)+'</div>';
      h+='</div>';
    });
    h+='</div>';
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No data <span class="retry-link" onclick="htmx.trigger(\'#backups-content\',\'load\')">retry</span></div>'}
}

function renderActivity(event){
  var el=document.getElementById('activity-content');
  try{
    var page=JSON.parse(event.detail.xhr.responseText);
    var events=page&&Array.isArray(page.items)?page.items:[];
    if(!Array.isArray(events)||events.length===0){el.innerHTML='<p class="muted">No activity yet.</p>';return}
    var h='<div class="activity-list">';
    events.forEach(function(e){
      var tsMs=e.ts_ms||0;
      var resultCls=e.result==='ok'?'badge-ok':e.result==='denied'?'badge-bad':e.result==='error'?'badge-degraded':'badge-info';
      h+='<div class="activity-item">';
      h+='<span class="badge '+resultCls+'" style="margin-right:4px">'+(e.result||'?')+'</span>';
      h+='<strong>'+escHtml(e.actor||'?')+'</strong>';
      h+=' <span class="muted">→</span> ';
      h+='<span>'+escHtml(e.target||'?')+'</span>';
      h+=' <span class="tag">'+escHtml(e.action||'?')+'</span>';
      h+=' <span class="muted">'+ageStr(Date.now()-tsMs)+'</span>';
      if(e.event_sha256)h+=' <span class="digest-trunc">'+truncDigest(e.event_sha256)+'</span>';
      h+='</div>';
    });
    h+='</div>';
    if(page.page&&page.page.truncated)h+='<p class="alert">Activity is a bounded tail snapshot; older matching events are not shown.</p>';
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No data <span class="retry-link" onclick="htmx.trigger(\'#activity-content\',\'load\')">retry</span></div>'}
}

function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

// ── Dashboard mutation: prepare → confirm two-phase flow ──────────
var _pendingPlans={};
var _pendingTurns={};

function dashPrepare(target,operation){
  var payload={operation:operation,target:target};
  var bannerEl=document.getElementById('confirm-'+target);
  bannerEl.innerHTML='<span class="muted">Preparing...</span>';
  fetch('/v1/dashboard/prepare',{
    method:'POST',
    headers:{'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  })
  .then(function(r){return r.json().then(function(d){return{status:r.status,data:d}})})
  .then(function(result){
    if(result.status===409){
      bannerEl.innerHTML='<div class="alert">'+escHtml(result.data.error||'Conflict')+'</div>';
      return;
    }
    if(result.status!==200){
      bannerEl.innerHTML='<div class="alert" style="border-color:var(--bad);color:var(--bad)">'+escHtml(result.data.error||'Error '+result.status)+'</div>';
      return;
    }
    _pendingPlans[target]=result.data;
    // The human turn is minted at PREPARE time: it identifies THIS
    // displayed intent. Every confirm click on this banner reuses it,
    // so a double-click dedupes server-side (idempotency key binds
    // digest+turn), while a NEW prepare is a NEW intent and executes.
    _pendingTurns[target]=String(Date.now());
    dashRenderBanner(target,result.data);
  })
  .catch(function(e){
    bannerEl.innerHTML='<div class="alert" style="border-color:var(--bad);color:var(--bad)">'+escHtml(e.message)+'</div>';
  });
}

function dashRenderBanner(target,plan){
  var el=document.getElementById('confirm-'+target);
  var destructive=plan.destructive;
  var digest=plan.action_digest||'';
  var h='<div style="background:var(--bg);border:1px solid '+(destructive?'var(--bad)':'var(--accent)')+';border-radius:6px;padding:10px;margin-top:6px">';
  h+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
  h+='<strong style="font-size:0.85rem">'+escHtml(plan.operation)+' '+escHtml(plan.target)+'</strong>';
  if(destructive)h+='<span class="badge badge-bad">DESTRUCTIVE</span>';
  h+='</div>';
  h+='<div class="muted" style="margin-bottom:6px">'+escHtml(plan.impact)+'</div>';
  h+='<div style="font-size:0.72rem;color:var(--muted);margin-bottom:6px">';
  h+='digest: <code>'+escHtml(digest.substring(0,12))+'\u2026</code> \u00b7 ';
  h+='expires: '+plan.ttl_s+'s';
  h+='</div>';
  if(destructive){
    h+='<input type="text" id="typed-name-'+escHtml(target)+'" placeholder="Type \''+escHtml(plan.target)+'\' to confirm" ';
    h+='oninput="dashCheckTypedName(\''+escHtml(target)+'\')" ';
    h+='style="margin-bottom:6px;font-size:0.85rem">';
  }
  h+='<div style="display:flex;gap:6px">';
  var disabled=destructive?' disabled':'';
  h+='<button class="btn btn-sm" style="background:var(--ok);color:#000;border-color:var(--ok)" id="confirm-btn-'+escHtml(target)+'"'+disabled+' onclick="dashConfirm(\''+escHtml(target)+'\')">Confirm</button>';
  h+='<button class="btn btn-sm" onclick="dashCancel(\''+escHtml(target)+'\')">Cancel</button>';
  h+='</div>';
  h+='<div id="confirm-result-'+escHtml(target)+'" style="margin-top:6px"></div>';
  h+='</div>';
  el.innerHTML=h;
}

function dashCheckTypedName(target){
  var input=document.getElementById('typed-name-'+target);
  var btn=document.getElementById('confirm-btn-'+target);
  var plan=_pendingPlans[target];
  btn.disabled=!input||input.value!==(plan?plan.target:'');
}

function dashConfirm(target){
  var plan=_pendingPlans[target];
  if(!plan)return;
  var resultEl=document.getElementById('confirm-result-'+target);
  var body={operation:plan.operation,target:plan.target,plan:plan,
            human_turn_id:_pendingTurns[target]||String(Date.now())};
  if(plan.destructive){
    body.typed_name=document.getElementById('typed-name-'+target).value;
  }
  fetch('/v1/dashboard/confirm',{
    method:'POST',
    headers:{'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'},
    body:JSON.stringify(body)
  })
  .then(function(r){return r.json().then(function(d){return{status:r.status,data:d}})})
  .then(function(result){
    if(result.data.ok){
      resultEl.innerHTML='<div style="color:var(--ok);font-weight:600;font-size:0.85rem">\u2713 '+escHtml(plan.operation)+' '+escHtml(plan.target)+' \u2014 success</div>';
    }else if(result.data.refused){
      resultEl.innerHTML='<div style="color:var(--degraded);font-weight:600;font-size:0.85rem">\u26a0 '+escHtml(result.data.refused||'refused')+': '+escHtml(result.data.error||'')+'</div>';
    }else{
      resultEl.innerHTML='<div style="color:var(--bad);font-weight:600;font-size:0.85rem">\u2717 Error: '+escHtml(result.data.error||'unknown')+'</div>';
    }
    delete _pendingPlans[target];
    // Immediate refresh: the action already landed server-side — do not
    // leave the card stale until the next poll tick (drill #26 UX).
    if(window.htmx){
      htmx.trigger('#fleet-content','refresh');
      htmx.trigger('#activity-content','refresh');
    }
  })
  .catch(function(e){
    resultEl.innerHTML='<div style="color:var(--bad);font-weight:600;font-size:0.85rem">\u2717 '+escHtml(e.message)+'</div>';
  });
}

function dashCancel(target){
  var el=document.getElementById('confirm-'+target);
  el.innerHTML='';
  delete _pendingPlans[target];
}

// Filter button logic
document.addEventListener('click',function(ev){
  if(!ev.target.classList.contains('filter-btn'))return;
  document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('btn-active')});
  ev.target.classList.add('btn-active');
  var filter=ev.target.dataset.filter;
  // Simple client-side filtering on the already-rendered activity
  var items=document.querySelectorAll('.activity-item');
  items.forEach(function(item){
    if(filter==='all'){item.style.display='';return}
    var text=item.textContent.toLowerCase();
    item.style.display=text.includes(filter)?'':'none';
  });
});
</script>
</body>
</html>"""


HANDLERS = {
    "health": health,
    "openapi_yaml": openapi_yaml,
    "list_instances": list_instances,
    "get_instance": get_instance,
    "logs": logs,
    "power": power,
    "snapshot": snapshot,
    "park_wake": park_wake,
    "destroy": destroy,
    "list_backups": list_backups,
    "audit_tail": audit_tail,
    "dashboard": dashboard,
    "list_embodiments": list_embodiments,
    "list_resource_fences": list_resource_fences,
    "weave_status": weave_status,
    "weave_differences": weave_differences,
    "dashboard_prepare": dashboard_prepare,
    "dashboard_confirm": dashboard_confirm,
    "restore_instance": restore_instance,
}
