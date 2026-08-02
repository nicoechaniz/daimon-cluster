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

import yaml

from clusterctl import audit
from clusterctl import cli
from clusterctl import lifecycle
from clusterctl.config import load_config

from . import __version__
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
    clusterd_base_url: str = "http://127.0.0.1:8785"


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


# Secret redaction patterns mirror clusterctl.lifecycle.REDACT_PATTERNS.
_AUDIT_REDACT_PATTERNS = ("private key", "api_key", "token=", "bearer ", "sk-",
                          "aiza")


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
    """GET /v1/audit — filtered tail of audit.jsonl with owner scoping.

    Reads audit events via ``clusterctl.audit.read_events``, reverses
    for tail semantics, applies query-param filters, scopes to the
    token owner's declared instances, and redacts before returning.
    """
    state_dir = deps.state_dir
    if state_dir is None:
        state_dir = load_config(deps.config_path).state_dir

    # Parse query params.
    q = query or {}
    try:
        limit = int((q.get("limit", [None])[0] or 50))
    except (TypeError, ValueError):
        limit = 50
    limit = max(1, min(limit, 200))
    filter_actor = (q.get("actor", [None])[0] or "").strip() or None
    filter_target = (q.get("target", [None])[0] or "").strip() or None
    filter_action = (q.get("action", [None])[0] or "").strip() or None

    # Owner scoping: non-"*" owners may only see events about their
    # own declared instances.
    owner = (ctx.token_record or {}).get("owner") or "*"
    owner_allowlist: set[str] | None = None
    if owner != "*":
        inst_dir = Path(state_dir) / "instances"
        owner_allowlist = set()
        if inst_dir.is_dir():
            for spec_file in inst_dir.glob("*.yaml"):
                try:
                    raw = yaml.safe_load(spec_file.read_text(encoding="utf-8"))
                except (yaml.YAMLError, OSError):
                    continue
                if isinstance(raw, dict) and raw.get("created_by") == owner:
                    owner_allowlist.add(raw.get("name", ""))
        # If owner has no declared instances, return empty (never leak).
        if not owner_allowlist:
            return Response(200, [])

    events = audit.read_events(state_dir)
    # Reverse: most recent first (tail semantics).
    events.reverse()

    result = []
    for event in events:
        if len(result) >= limit:
            break
        target = event.get("target") or ""
        # Owner scoping: only include events for this owner's instances.
        if owner_allowlist is not None and target not in owner_allowlist:
            continue
        if filter_actor is not None and event.get("actor") != filter_actor:
            continue
        if filter_target is not None and target != filter_target:
            continue
        if filter_action is not None and event.get("action") != filter_action:
            continue
        result.append(_redact_event_fields(event))

    return Response(200, result)


def list_leases(deps: Deps, ctx: RequestContext, **params) -> Response:
    """GET /v1/leases — list all non-expired daimon presence leases.

    Reads the same ``state_dir/leases/*.json`` files written by
    ``clusterctl.leases.LeaseStore``. Returns a list of status dicts
    filtered to non-expired entries (lease files may exist on disk
    past expiry until garbage-collected — the API filters them out).
    """
    from clusterctl.leases import LeaseStore

    state_dir = deps.state_dir
    if state_dir is None:
        state_dir = load_config(deps.config_path).state_dir
    store = LeaseStore(state_dir)
    all_leases = store.list_all()
    # Filter to non-expired leases.
    non_expired = [st for st in all_leases if not st.get("expired", True)]
    return Response(200, non_expired)


def dashboard(deps: Deps, ctx: RequestContext, **params) -> Response:
    """GET /v1/dashboard — HTMX fleet dashboard (single-page app).

    Serves a static HTML shell that uses HTMX + the same /v1 API
    endpoints as the steward tools. No parallel logic — every data
    section fetches from the read routes.
    """
    html = _DASHBOARD_HTML
    return Response(200, html, content_type="text/html; charset=utf-8")


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


def dashboard_prepare(deps: Deps, ctx: RequestContext, route=None,
                      query=None, _body=None, **params) -> Response:
    """POST /v1/dashboard/prepare — propose a mutation, return plan JSON.

    Reads operation + target from JSON body, calls the appropriate
    steward_tools.mutations.propose_<op>, returns the MutationPlan as JSON.
    NO mutation occurs. For restore: checks instance state first (409 if running).
    """
    body = _body or {}
    operation = str(body.get("operation", "")).strip()
    target = str(body.get("target", "")).strip()

    if not operation or not target:
        return _error(400, "operation and target are required",
                      operation or "?", target or "?", ctx.request_id)

    valid_ops = {"start", "stop", "restart", "snapshot", "destroy", "restore"}
    if operation not in valid_ops:
        return _error(400, f"unknown operation {operation!r}",
                      operation, target, ctx.request_id)

    # restore pre-condition: instance must not be running
    if operation == "restore":
        resp = get_instance(deps, ctx, target)
        if resp.status == 200 and isinstance(resp.body, dict):
            state = str(resp.body.get("state", "")).lower()
            if state == "running":
                return _error(409,
                              "instance must be stopped before restore",
                              operation, target, ctx.request_id)

    _propose = {
        "start": mutations.propose_start,
        "stop": mutations.propose_stop,
        "restart": mutations.propose_restart,
        "snapshot": mutations.propose_snapshot,
        "destroy": mutations.propose_destroy,
        "restore": mutations.propose_restore,
    }[operation]

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
        return _error(502, f"clusterd internal: {exc!r}", operation,
                      target, ctx.request_id)

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


def dashboard_confirm(deps: Deps, ctx: RequestContext, route=None,
                      query=None, _body=None, **params) -> Response:
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
        return _error(400, "plan is required (field 'plan' missing)",
                      operation or "?", target or "?", ctx.request_id)

    plan = _plan_from_json(plan_json)

    # Destroy: server-side typed-name validation (defense in depth —
    # client-side also validates, but we never trust the client).
    if plan.operation == "destroy":
        typed_name = str(body.get("typed_name", "")).strip()
        if not typed_name or typed_name != plan.target:
            return Response(400, {
                "schema": mutations.RESULT_SCHEMA,
                "ok": False,
                "operation": operation,
                "target": target,
                "refused": "typed-name-mismatch",
                "error": "typed_name must EXACTLY match the target (case-sensitive)",
            })
    else:
        typed_name = None

    # Use the dashboard's bearer token for the mutation call.
    mc = mutations.MutationClient(token_override=ctx.scope_token)
    result = mutations.confirm_plan(
        plan, human_turn_id=human_turn_id,
        typed_name=typed_name, client=mc,
    )

    if result.get("ok"):
        return Response(200, result)
    elif result.get("refused"):
        return Response(400, result)
    else:
        return Response(500, result)


def restore_instance(deps: Deps, ctx: RequestContext, name: str,
                     route=None, **params) -> Response:
    """POST /v1/instances/{name}/restore — placeholder.

    Execution (snapshot-to-instance restore) is a later milestone.
    The pre-condition check (instance must be stopped) runs in the
    dashboard_prepare route.
    """
    return _error(501, "restore confirmed; execution is a later milestone",
                  "restore", name, ctx.request_id)


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
  if(lower==='running'||lower==='ok')return '<span class="badge badge-ok">'+s+'</span>';
  if(lower==='degraded')return '<span class="badge badge-degraded">'+s+'</span>';
  if(lower==='stopped'||lower==='error'||lower==='unreachable')return '<span class="badge badge-bad">'+s+'</span>';
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
    var daimons=JSON.parse(event.detail.xhr.responseText);
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
    el.innerHTML=h;
  }catch(e){el.innerHTML='<div class="alert">No data <span class="retry-link" onclick="htmx.trigger(\'#fleet-content\',\'load\')">retry</span></div>'}
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
    var events=JSON.parse(event.detail.xhr.responseText);
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
    "list_leases": list_leases,
    "dashboard_prepare": dashboard_prepare,
    "dashboard_confirm": dashboard_confirm,
    "restore_instance": restore_instance,
}
