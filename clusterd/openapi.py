"""OpenAPI 3.0 generation from the clusterd route table.

``clusterd.routes.ROUTES`` is the single source of truth: this module
only renders it. Served at GET /v1/openapi.yaml and written to
``docs/contracts/clusterd-openapi-v1.yaml`` via
``scripts/clusterd --dump-openapi``.
"""

from __future__ import annotations

import yaml

from . import __version__
from .routes import ROUTES

ERROR_ENVELOPE = {
    "type": "object",
    "required": ["error", "action", "target", "request_id"],
    "properties": {
        "error": {"type": "string"},
        "action": {"type": "string"},
        "target": {"type": "string"},
        "request_id": {"type": "string", "format": "uuid"},
    },
}


def _envelope_parameters() -> list[dict]:
    """Headers every request may carry (design §1 envelope)."""
    return [
        {
            "name": "X-Request-Id",
            "in": "header",
            "required": False,
            "description": "Echoed back; a uuid4 is generated when absent.",
            "schema": {"type": "string", "format": "uuid"},
        },
        {
            "name": "X-Actor",
            "in": "header",
            "required": False,
            "description": "Advisory only. Authenticated routes use the "
                           "bearer token actor as the authoritative actor.",
            "schema": {"type": "string", "default": "anonymous"},
        },
    ]


def _operation(route) -> dict:
    parameters = _envelope_parameters()
    for param in route.path_params():
        parameters.append({
            "name": param,
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        })
    for query_param in route.query_params:
        parameters.append(dict(query_param))
    if route.idempotency_required:
        parameters.append({
            "name": "Idempotency-Key",
            "in": "header",
            "required": True,
            "description": "uuid. Retry with the same key replays the "
                           "cached clusterctl result (idempotent-replay: "
                           "true); reuse for a different operation/target "
                           "is a 409 conflict. Dedupe is clusterctl's own "
                           "idempotency store.",
            "schema": {"type": "string", "format": "uuid"},
        })
    if route.mutation:
        parameters.append({
            "name": "X-Human-Approval",
            "in": "header",
            "required": False,
            "description": "Base64url clusterd-human-approval/v1 artifact. "
                           "Required for steward@* execution and signed by "
                           "a separately provisioned human authority over "
                           "the exact 409 intent. Caller attendance headers "
                           "carry no authority.",
            "schema": {"type": "string", "maxLength": 16384},
        })
        parameters.append({
            "name": "X-Confirm",
            "in": "header",
            "required": False,
            "description": "'none' executes non-destructive mutations "
                           "(start/stop/restart) directly. Destructive-"
                           "class routes ALWAYS require a confirmation "
                           "token regardless.",
            "schema": {"type": "string", "enum": ["none"]},
        })
    if route.confirmation_required:
        parameters.append({
            "name": "X-Confirm-Token",
            "in": "header",
            "required": False,
            "description": "Single-use confirmation/v1 token from the "
                           "409 challenge. Validated against the action "
                           "digest (operation+target+actor+args): "
                           "expired/reused/altered/wrong-actor/wrong-"
                           "target -> 409.",
            "schema": {"type": "string"},
        })

    error_ref = {"$ref": "#/components/schemas/ErrorEnvelope"}
    err_content = {"application/json": {"schema": error_ref}}
    responses: dict[str, dict] = {
        "200": {"description": "clusterctl result JSON (exit 0)"},
    }
    if route.handler in {"list_instances", "audit_tail", "weave_differences"}:
        responses["200"] = {
            "description": "Bounded immutable snapshot page",
            "content": {"application/json": {"schema": {
                "$ref": "#/components/schemas/SnapshotPage",
            }}},
        }
        responses["400"] = {
            "description": "invalid limit/cursor or cursor scope mismatch",
            "content": err_content,
        }
        responses["409"] = {
            "description": "cursor snapshot expired or was evicted; restart pagination",
            "content": err_content,
        }
    if route.handler in {"weave_status", "weave_differences"}:
        responses["503"] = {
            "description": "membership-safe Matrix read unavailable",
            "content": err_content,
        }
    if not route.public:
        responses["401"] = {
            "description": "missing/unknown/expired/revoked bearer token "
                           "({error: unauthorized})",
            "content": err_content,
        }
        responses["403"] = {
            "description": "authenticated but denied: insufficient scope, "
                           "not your daimon (owner mismatch), or "
                           "unattended-steward-denied",
            "content": err_content,
        }
    if route.idempotency_required:
        responses["400"] = {"description": "missing Idempotency-Key",
                            "content": err_content}
    if "{" in route.path:
        responses["404"] = {"description": "not found (CLI exit 3)",
                            "content": err_content}
    if route.mutation:
        responses["409"] = {
            "description": "conflict (CLI exit 6: idempotency-key reuse, "
                           "lock held)",
            "content": err_content,
        }
        responses["429"] = {
            "description": "mutation rate limit: 60 mutations/minute per "
                           "token (sliding window)",
            "content": err_content,
        }
    if route.confirmation_required:
        responses["409"] = {
            "description": "confirmation required: body is a "
                           "confirmation/v1 challenge (first POST) or a "
                           "rejection (expired/reused/altered-digest/"
                           "wrong-actor/wrong-target token)",
            "content": {"application/json": {"schema": {
                "oneOf": [
                    {"$ref": "#/components/schemas/ConfirmationChallenge"},
                    error_ref,
                ],
            }}},
        }
        responses["501"] = {
            "description": "confirmation validated; destroy execution is "
                           "a later milestone",
            "content": err_content,
        }
    responses["500"] = {"description": "internal error (CLI exit 10)",
                        "content": err_content}

    security: list[dict] = [] if route.public else [{"bearerAuth": []}]
    return {
        "operationId": route.operation_id,
        "summary": route.summary,
        "description": (
            f"Uses `{route.clusterctl}` as its source; mutations retain the "
            f"same clusterctl business-logic boundary while reads may add "
            f"owner scoping, redaction, observation envelopes, and bounded "
            f"snapshot pagination.\n\n"
            f"Required bearer scope: `{route.required_scope}`"
            + (" (route is public)" if route.public else
               " — enforced (issue #18). Owner-scoped tokens may only "
               "touch daimons whose spec created_by matches the owner.")
        ),
        "parameters": parameters,
        "security": security,
        "responses": responses,
    }


def build_openapi() -> dict:
    paths: dict = {}
    for route in ROUTES:
        paths.setdefault(route.path, {})[route.method.lower()] = _operation(route)
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "clusterd",
            "version": __version__,
            "description": (
                "HTTP API over clusterctl (issue #17; design: "
                "docs/design/clusterd.md). Mutations adapt clusterctl; read "
                "models add owner scoping, redaction, explicit observation "
                "boundaries and bounded snapshot pagination. "
                "Errors mirror clusterctl exit codes: 0->200, 2->400, "
                "3->404, 6->409, 10->500."
            ),
        },
        "servers": [
            {"url": "http://127.0.0.1:8785",
             "description": "loopback (host ops)"},
            {"url": "http://10.105.93.1:8785",
             "description": "incus bridge gateway (steward container; "
                            "private only, never a public bind)"},
        ],
        "paths": paths,
        "components": {
            "schemas": {
                "ErrorEnvelope": ERROR_ENVELOPE,
                "SnapshotPage": {
                    "type": "object",
                    "required": ["schema", "items", "page"],
                    "properties": {
                        "schema": {"type": "string", "enum": ["clusterd-page/v1"]},
                        "items": {"type": "array", "items": {"type": "object"}},
                        "page": {
                            "type": "object",
                            "required": [
                                "limit", "count", "has_more", "next_cursor",
                                "snapshot_id", "observed_at_ms", "expires_in_s",
                                "truncated",
                            ],
                            "properties": {
                                "limit": {"type": "integer", "minimum": 1,
                                          "maximum": 200},
                                "count": {"type": "integer", "minimum": 0,
                                          "maximum": 200},
                                "has_more": {"type": "boolean"},
                                "next_cursor": {"type": "string", "nullable": True},
                                "snapshot_id": {"type": "string"},
                                "observed_at_ms": {"type": "integer"},
                                "expires_in_s": {"type": "integer", "minimum": 0},
                                "truncated": {"type": "boolean"},
                            },
                        },
                    },
                },
                "ConfirmationChallenge": {
                    "type": "object",
                    "required": ["schema", "token", "operation", "target",
                                 "actor", "action_digest", "created_ms",
                                 "ttl_s"],
                    "properties": {
                        "schema": {"type": "string",
                                   "enum": ["confirmation/v1"]},
                        "token": {"type": "string",
                                  "description": "single-use; send back as "
                                                 "X-Confirm-Token"},
                        "operation": {"type": "string"},
                        "target": {"type": "string"},
                        "actor": {"type": "string"},
                        "action_digest": {
                            "type": "string",
                            "description": "sha256 of canonical JSON "
                                           "{operation,target,actor,args} — "
                                           "binds the confirmation to "
                                           "exactly that action",
                        },
                        "created_ms": {"type": "integer"},
                        "ttl_s": {"type": "integer", "default": 900},
                    },
                },
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": (
                        "Scoped bearer token, format dcd_<uuid4hex> "
                        "(issue #18, design §2/§3). ENFORCED: tokens are "
                        "sha256-hashed at rest in "
                        "state_dir/auth/tokens.json (auth-token/v1); "
                        "manage via `scripts/clusterd --token-create | "
                        "--token-revoke | --token-list`. Scopes are exact "
                        "operation classes (fleet:read, lifecycle:write, "
                        "backup:write, etc.). Owner-scoped tokens may only touch their "
                        "own daimons. Revocation takes effect without "
                        "restart. Every route except GET /v1/health "
                        "requires a token (default-deny)."
                    ),
                },
            },
        },
    }


def dump_openapi() -> str:
    return yaml.safe_dump(build_openapi(), sort_keys=False)
