"""clusterd route table — the single source of truth for the v1 API.

The OpenAPI document (``clusterd.openapi``) is generated FROM this
table, and the HTTP server (``clusterd.server``) dispatches FROM this
table. Adding a route means adding one ``Route`` entry here plus one handler function in
``clusterd.handlers`` — server and OpenAPI pick it up automatically.

``required_scope`` is ENFORCED (issue #18): every route except
GET /v1/health requires a valid bearer token with the declared scope
(``read`` | ``mutate``); owner and confirmation checks are declared
here too and enforced in ``clusterd.server``.
"""

from __future__ import annotations

import dataclasses
import re


@dataclasses.dataclass(frozen=True)
class Route:
    method: str                 # GET | POST | DELETE
    path: str                   # "/v1/instances/{name}"
    operation_id: str
    summary: str
    handler: str                # function name in clusterd.handlers
    scope: str                  # design-§2 scope label (documentation)
    clusterctl: str             # CLI equivalent ("same code path")
    idempotency_required: bool = False
    mutation: bool = False
    required_scope: str | None = "read"  # None -> public (health only)
    confirmation_required: bool = False  # destructive class (design §2)
    query_params: tuple = ()             # OpenAPI query parameter dicts

    @property
    def public(self) -> bool:
        return self.required_scope is None

    def regex(self) -> re.Pattern:
        pattern = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", self.path)
        return re.compile(f"^{pattern}$")

    def path_params(self) -> list[str]:
        return re.findall(r"\{(\w+)\}", self.path)


ROUTES: list[Route] = [
    Route(
        method="GET",
        path="/v1/health",
        operation_id="getHealth",
        summary="clusterd liveness + clusterctl reachability",
        handler="health",
        scope="none",
        clusterctl="config load + list (reachability probe)",
        required_scope=None,  # public-but-boring (design §1)
    ),
    Route(
        method="GET",
        path="/v1/openapi.yaml",
        operation_id="getOpenapi",
        summary="OpenAPI 3.0 document generated from the route table",
        handler="openapi_yaml",
        scope="none",
        clusterctl="n/a (generated from clusterd.routes)",
    ),
    Route(
        method="GET",
        path="/v1/instances",
        operation_id="listInstances",
        summary="List all instances with reconciled state",
        handler="list_instances",
        scope="fleet:read",
        clusterctl="clusterctl list --json",
    ),
    Route(
        method="GET",
        path="/v1/instances/{name}",
        operation_id="getInstance",
        summary="One instance's reconciled status (404 mirrors CLI exit 3)",
        handler="get_instance",
        scope="fleet:read",
        clusterctl="clusterctl status <name> --json",
    ),
    Route(
        method="GET",
        path="/v1/backups",
        operation_id="listBackups",
        summary="Latest cluster-backup-manifest/v1 summary per daimon",
        handler="list_backups",
        scope="fleet:read",
        clusterctl="reads state_dir/backups/*/ newest .json (same files "
                   "clusterctl snapshot create writes)",
    ),
    Route(
        method="GET",
        path="/v1/instances/{name}/logs",
        operation_id="getInstanceLogs",
        summary="Bounded, secret-redacted instance logs (steward window, "
                "issue #22)",
        handler="logs",
        scope="fleet:read",
        clusterctl="clusterctl logs <name> --lines <n> --json",
        query_params=({
            "name": "lines",
            "in": "query",
            "required": False,
            "description": "Max log lines returned (bounded; clusterctl "
                           "clamps to its own max). Redaction is applied "
                           "by clusterctl before any bytes leave the host.",
            "schema": {"type": "integer", "default": 100, "minimum": 1,
                       "maximum": 1000},
        },),
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/start",
        operation_id="startInstance",
        summary="Start a declared instance",
        handler="power",
        scope="lifecycle:write",
        clusterctl="clusterctl start <name> --idempotency-key <key> --json",
        idempotency_required=True,
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/stop",
        operation_id="stopInstance",
        summary="Stop a declared instance",
        handler="power",
        scope="lifecycle:write",
        clusterctl="clusterctl stop <name> --idempotency-key <key> --json",
        idempotency_required=True,
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/restart",
        operation_id="restartInstance",
        summary="Restart a declared (running) instance",
        handler="power",
        scope="lifecycle:write",
        clusterctl="clusterctl restart <name> --idempotency-key <key> --json",
        idempotency_required=True,
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/destroy",
        operation_id="destroyInstance",
        summary="Destroy an instance (destructive: two-step prepare/confirm; "
                "execution is a later milestone — 501 after validation)",
        handler="destroy",
        scope="destroy:write",
        clusterctl="clusterctl destroy <name> (archive-first; future milestone)",
        mutation=True,
        required_scope="mutate",
        confirmation_required=True,
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/snapshot",
        operation_id="snapshotInstance",
        summary="Quiesced snapshot: park writers, checkpoint DBs, capture, "
                "verify, write backup manifest (issue #23)",
        handler="snapshot",
        scope="backup:write",
        clusterctl="clusterctl snapshot create <name> "
                   "--idempotency-key <key> --json",
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/park",
        operation_id="parkInstance",
        summary="Park a daimon's writers (SIGSTOP hermes; issue #23)",
        handler="park_wake",
        scope="lifecycle:write",
        clusterctl="clusterctl park <name> --idempotency-key <key> --json",
        idempotency_required=True,
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/wake",
        operation_id="wakeInstance",
        summary="Wake a parked daimon (SIGCONT hermes; issue #23)",
        handler="park_wake",
        scope="lifecycle:write",
        clusterctl="clusterctl wake <name> --idempotency-key <key> --json",
        idempotency_required=True,
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="GET",
        path="/v1/audit",
        operation_id="listAuditEvents",
        summary="Tail of the tamper-evident audit log filtered by query params",
        handler="audit_tail",
        scope="fleet:read",
        clusterctl="reads audit.jsonl directly (same file clusterctl appends to)",
        query_params=(
            {
                "name": "limit",
                "in": "query",
                "required": False,
                "description": "Max events returned (bounded; default 50, max 200)",
                "schema": {"type": "integer", "default": 50, "minimum": 1,
                           "maximum": 200},
            },
            {
                "name": "actor",
                "in": "query",
                "required": False,
                "description": "Filter by actor (exact match)",
                "schema": {"type": "string"},
            },
            {
                "name": "target",
                "in": "query",
                "required": False,
                "description": "Filter by target (exact match)",
                "schema": {"type": "string"},
            },
            {
                "name": "action",
                "in": "query",
                "required": False,
                "description": "Filter by action (exact match)",
                "schema": {"type": "string"},
            },
        ),
    ),
    Route(
        method="GET",
        path="/v1/dashboard",
        operation_id="getDashboard",
        summary="HTMX fleet dashboard shell (public static app; ALL data "
                "fetches go through the auth-gated read routes — the shell "
                "itself carries no data)",
        handler="dashboard",
        scope="fleet:read",
        clusterctl="thin client of GET /v1/{instances,health,backups,audit}",
        required_scope=None,  # public shell: a browser navigation sends no
                             # Authorization header; the JS prompts for the
                             # token and attaches it to every HTMX data call
    ),
    Route(
        method="GET",
        path="/v1/embodiments",
        operation_id="listEmbodiments",
        summary="List body embodiments and their incarnation histories",
        handler="list_embodiments",
        scope="fleet:read",
        clusterctl="reads state_dir/embodiments.json (same registry clusterctl writes)",
    ),
    Route(
        method="GET",
        path="/v1/resource-fences",
        operation_id="listResourceFences",
        summary="List active CAS/TTL fences for concrete writable resources",
        handler="list_resource_fences",
        scope="fleet:read",
        clusterctl="reads state_dir/leases/*.json resource-fence/v1 records",
    ),
    Route(
        method="GET",
        path="/v1/weave/status",
        operation_id="getWeaveStatus",
        summary="Show local /we manifest, origin, heads, and durable peer cursors",
        handler="weave_status",
        scope="fleet:read",
        clusterctl="reads state_dir/weave/{being-manifest.json,runtime.json,ledger.sqlite}",
    ),
    Route(
        method="POST",
        path="/v1/dashboard/prepare",
        operation_id="prepareDashboardMutation",
        summary="Phase 1: propose a dashboard mutation, returns plan JSON (no mutation)",
        handler="dashboard_prepare",
        scope="dashboard:prepare",
        clusterctl="n/a (local plan proposal; calls steward_tools.mutations.propose_<op>)",
    ),
    Route(
        method="POST",
        path="/v1/dashboard/confirm",
        operation_id="confirmDashboardMutation",
        summary="Phase 2: execute a dashboard-prepared mutation plan (idempotent via digest-derived key)",
        handler="dashboard_confirm",
        scope="dashboard:confirm",
        clusterctl="n/a (execution; calls steward_tools.mutations.confirm_plan)",
        mutation=True,
        required_scope="mutate",
    ),
    Route(
        method="POST",
        path="/v1/instances/{name}/restore",
        operation_id="restoreInstance",
        summary="Restore an instance from its most recent backup (placeholder; execution is a later milestone)",
        handler="restore_instance",
        scope="restore:write",
        clusterctl="clusterctl restore <name> (placeholder; future milestone)",
        mutation=True,
        required_scope="mutate",
    ),
]


def match(method: str, path: str):
    """Return (route, path_params) or (None, None).

    Raises ``MethodNotAllowed`` if the path matches a route but the
    method does not (so the server can answer 405, not 404).
    """
    path_matched = False
    for route in ROUTES:
        m = route.regex().match(path)
        if not m:
            continue
        path_matched = True
        if route.method == method:
            return route, m.groupdict()
    if path_matched:
        raise MethodNotAllowed(path)
    return None, None


class MethodNotAllowed(Exception):
    """Raised when a path exists but not for the requested method."""
