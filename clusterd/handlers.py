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
import io
import json
import re
import threading
import time
from pathlib import Path

from clusterctl import audit
from clusterctl import cli
from clusterctl import lifecycle
from clusterctl.config import load_config

from . import __version__

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
    """"not-configured" | "ok" | "failing" (design §4 mirror placeholder).

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


@dataclasses.dataclass(frozen=True)
class Deps:
    """Server-level dependencies (injected; tests pass a FakeAdapter)."""

    config_path: str
    state_dir: str | None = None
    adapter_factory: object | None = None  # callable () -> Adapter, or None=live


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
    body: object                      # dict/list -> JSON, str -> raw
    content_type: str = "application/json"


def _error(status: int, message: str, action: str, target: str,
           request_id: str) -> Response:
    """Structured error envelope mirroring clusterctl's error JSON."""
    return Response(status, {
        "error": message,
        "action": action,
        "target": target,
        "request_id": request_id,
    })


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
        with contextlib.redirect_stdout(out_buf), \
             contextlib.redirect_stderr(err_buf):
            code = cli.run(full_argv, adapter=_adapter(deps))
    out, err = out_buf.getvalue().strip(), err_buf.getvalue().strip()
    status = EXIT_TO_HTTP.get(code, 500)

    action = argv[0] if argv else "?"
    target = argv[1] if len(argv) > 1 else "?"
    if code == 0:
        try:
            return Response(status, json.loads(out) if out else {})
        except json.JSONDecodeError:
            return _error(500, f"clusterctl emitted non-JSON output: {out[:200]}",
                          action, target, ctx.request_id)
    # Error: clusterctl prints {error, action, target} JSON to stderr.
    try:
        payload = json.loads(err) if err else {}
    except json.JSONDecodeError:
        payload = {"error": err or f"clusterctl exited {code}",
                   "action": action, "target": target}
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
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
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
    # A broken audit chain or a configured-but-failing mirror degrades
    # health; local events are NEVER dropped for a mirror failure
    # (design §4 — the local log is the source of truth).
    healthy = reachable and chain_ok and mirror != "failing"
    return Response(200, {
        "schema": HEALTH_SCHEMA,
        "status": "ok" if healthy else "degraded",
        "version": __version__,
        "clusterctl_reachable": reachable,
        "audit_chain_ok": chain_ok,
        "mirror_state": mirror,
    })


def openapi_yaml(deps: Deps, ctx: RequestContext, **params) -> Response:
    from .openapi import dump_openapi
    return Response(200, dump_openapi(), content_type="application/yaml")


def list_instances(deps: Deps, ctx: RequestContext, **params) -> Response:
    return _run_cli(deps, ctx, ["list", "--json"])


def get_instance(deps: Deps, ctx: RequestContext, name: str,
                 **params) -> Response:
    return _run_cli(deps, ctx, ["status", name, "--json"])


def logs(deps: Deps, ctx: RequestContext, name: str, query=None,
         **params) -> Response:
    """GET /v1/instances/{name}/logs?lines=N — bounded, redacted (issue #22).

    Pure delegation to ``clusterctl logs``: the bounded read and the
    secret redaction both live in clusterctl.lifecycle.cmd_logs; this
    handler only validates the name and binds the lines parameter.
    """
    if not INSTANCE_NAME_RE.fullmatch(name):
        return _error(400, f"invalid instance name {name!r}",
                      "logs", name, ctx.request_id)
    raw = (query or {}).get("lines", [None])[0]
    if raw is None:
        n = lifecycle.LOGS_DEFAULT_LINES
    else:
        try:
            n = int(raw)
        except (TypeError, ValueError):
            return _error(400, f"invalid lines parameter {raw!r}",
                          "logs", name, ctx.request_id)
    n = max(1, min(n, lifecycle.LOGS_MAX_LINES))
    return _run_cli(deps, ctx, ["logs", name, "--lines", str(n), "--json"])


def power(deps: Deps, ctx: RequestContext, name: str, route=None,
          **params) -> Response:
    """POST /v1/instances/{name}/start|stop|restart.

    Idempotency-Key is REQUIRED (HTTP-side admission, mirrors the CLI
    contract); replay/dedupe itself is clusterctl's own store.
    """
    operation = route.path.rsplit("/", 1)[-1]
    if not ctx.idempotency_key:
        return _error(400, "Idempotency-Key header is required",
                      operation, name, ctx.request_id)
    return _run_cli(deps, ctx, [operation, name,
                                "--idempotency-key", ctx.idempotency_key,
                                "--json"])


def snapshot(deps: Deps, ctx: RequestContext, name: str, route=None,
             **params) -> Response:
    """POST /v1/instances/{name}/snapshot — quiesced snapshot (issue #23).

    Pure delegation to ``clusterctl snapshot create``: the quiesce
    (park+checkpoint), capture, verify and manifest write all live in
    ``clusterctl.snapshot``. The CLI requires an idempotency key, so one
    is generated from the request id when the caller did not send an
    Idempotency-Key header (the steward's gated flow always sends one).
    """
    key = ctx.idempotency_key or f"clusterd-{ctx.request_id}"
    return _run_cli(deps, ctx, ["snapshot", "create", name,
                                "--idempotency-key", key, "--json"])


def park_wake(deps: Deps, ctx: RequestContext, name: str, route=None,
              **params) -> Response:
    """POST /v1/instances/{name}/park|wake (issue #23).

    Delegates to the thin ``clusterctl park|wake`` commands, which apply
    the full lifecycle contract (admission, idempotency, lock, audit)
    around adapter.exec_quiesce_park / exec_unpark. Same shape as
    ``power``: Idempotency-Key required, dedupe is clusterctl's store.
    """
    operation = route.path.rsplit("/", 1)[-1]
    if not ctx.idempotency_key:
        return _error(400, "Idempotency-Key header is required",
                      operation, name, ctx.request_id)
    return _run_cli(deps, ctx, [operation, name,
                                "--idempotency-key", ctx.idempotency_key,
                                "--json"])


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
    entries = []
    if backups_root.is_dir():
        for daimon_dir in sorted(p for p in backups_root.iterdir() if p.is_dir()):
            manifests = sorted(daimon_dir.glob("*.json"))
            if not manifests:
                continue
            latest = manifests[-1]
            entry = {
                "schema": BACKUP_SUMMARY_SCHEMA,
                "name": daimon_dir.name,
                "manifest_path": str(latest),
            }
            try:
                entry["manifest"] = json.loads(latest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                entry["manifest"] = None
                entry["error"] = f"unreadable manifest: {exc}"
            entries.append(entry)
    return Response(200, entries)


def destroy(deps: Deps, ctx: RequestContext, name: str, route=None,
            **params) -> Response:
    """POST /v1/instances/{name}/destroy — destructive-class placeholder.

    The confirmation machinery (challenge issue/validate/consume) runs
    in server middleware BEFORE this handler; reaching here means a
    valid single-use confirmation was consumed. Execution (archive-first
    destroy, #8 §3) is a later milestone.
    """
    return _error(501, "destroy confirmed; execution is a later milestone",
                  "destroy", name, ctx.request_id)


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
}
