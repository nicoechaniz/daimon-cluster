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
import threading
from pathlib import Path

from clusterctl import cli
from clusterctl.config import load_config

from . import __version__

# clusterctl.cli.run prints JSON to stdout/stderr; capture is
# process-global, so serialize invocations (ThreadingHTTPServer serves
# requests concurrently). clusterctl's own locking is unaffected.
_CLI_LOCK = threading.Lock()

EXIT_TO_HTTP = {0: 200, 2: 400, 3: 404, 6: 409, 10: 500}

HEALTH_SCHEMA = "clusterd-health/v1"
BACKUP_SUMMARY_SCHEMA = "clusterd-backup-summary/v1"


@dataclasses.dataclass(frozen=True)
class Deps:
    """Server-level dependencies (injected; tests pass a FakeAdapter)."""

    config_path: str
    state_dir: str | None = None
    adapter_factory: object | None = None  # callable () -> Adapter, or None=live


@dataclasses.dataclass(frozen=True)
class RequestContext:
    """Per-request envelope (design §1).

    ``scope_token`` is the parsed bearer token. It is attached here for
    audit and future enforcement but is NOT enforced — auth is issue
    #18. See docs/design/clusterd.md §3.
    """

    request_id: str
    actor: str
    scope_token: str | None
    idempotency_key: str | None = None


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
    return Response(200, {
        "schema": HEALTH_SCHEMA,
        "status": "ok" if reachable else "degraded",
        "version": __version__,
        "clusterctl_reachable": reachable,
    })


def openapi_yaml(deps: Deps, ctx: RequestContext, **params) -> Response:
    from .openapi import dump_openapi
    return Response(200, dump_openapi(), content_type="application/yaml")


def list_instances(deps: Deps, ctx: RequestContext, **params) -> Response:
    return _run_cli(deps, ctx, ["list", "--json"])


def get_instance(deps: Deps, ctx: RequestContext, name: str,
                 **params) -> Response:
    return _run_cli(deps, ctx, ["status", name, "--json"])


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


HANDLERS = {
    "health": health,
    "openapi_yaml": openapi_yaml,
    "list_instances": list_instances,
    "get_instance": get_instance,
    "power": power,
    "list_backups": list_backups,
}
