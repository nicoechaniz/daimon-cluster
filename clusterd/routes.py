"""clusterd route table — the single source of truth for the v1 API.

The OpenAPI document (``clusterd.openapi``) is generated FROM this
table, and the HTTP server (``clusterd.server``) dispatches FROM this
table. Adding a route (e.g. lease routes in a later milestone) means
adding one ``Route`` entry here plus one handler function in
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
    # Lease routes (issue #27 milestone): add Route entries here, e.g.
    #   GET  /v1/leases            -> clusterctl lease list --json
    #   POST /v1/leases/{identity}/park  (idempotency_required, mutation)
    #   POST /v1/leases/{identity}/wake  (idempotency_required, mutation)
    # plus matching handlers — server + OpenAPI pick them up for free.
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
