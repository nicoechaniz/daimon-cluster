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
            "description": "Actor recorded in clusterctl audit events "
                           "(default: anonymous).",
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
            "name": "X-Attended",
            "in": "header",
            "required": False,
            "description": "Human presence marker REQUIRED for tokens "
                           "whose actor is steward@* (v1 unattended-"
                           "steward denial; real presence flow lands in "
                           "M5). Missing -> 403 unattended-steward-denied.",
            "schema": {"type": "string", "enum": ["true"]},
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
    responses = {
        "200": {"description": "clusterctl result JSON (exit 0)"},
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

    security = [] if route.public else [{"bearerAuth": []}]
    return {
        "operationId": route.operation_id,
        "summary": route.summary,
        "description": (
            f"Delegates to `{route.clusterctl}` — the same code path as "
            f"the CLI; clusterd adds no business logic.\n\n"
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
                "Thin HTTP API over clusterctl (issue #17; design: "
                "docs/design/clusterd.md). Every route adapts a "
                "clusterctl.cli.run invocation or reads state files "
                "clusterctl writes — no business logic is duplicated. "
                "Errors mirror clusterctl exit codes: 0->200, 2->400, "
                "3->404, 6->409, 10->500."
            ),
        },
        "servers": [{"url": "http://127.0.0.1:8785"}],
        "paths": paths,
        "components": {
            "schemas": {
                "ErrorEnvelope": ERROR_ENVELOPE,
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
                        "--token-revoke | --token-list`. Scopes: read, "
                        "mutate. Owner-scoped tokens may only touch their "
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
