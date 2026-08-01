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

    error_ref = {"$ref": "#/components/schemas/ErrorEnvelope"}
    responses = {
        "200": {"description": "clusterctl result JSON (exit 0)"},
    }
    if route.idempotency_required:
        responses["400"] = {"description": "missing Idempotency-Key",
                            "content": {"application/json": {"schema": error_ref}}}
    if "{" in route.path:
        responses["404"] = {"description": "not found (CLI exit 3)",
                            "content": {"application/json": {"schema": error_ref}}}
    if route.mutation:
        responses["409"] = {
            "description": "conflict (CLI exit 6: idempotency-key reuse, "
                           "lock held)",
            "content": {"application/json": {"schema": error_ref}},
        }
    responses["500"] = {"description": "internal error (CLI exit 10)",
                        "content": {"application/json": {"schema": error_ref}}}

    return {
        "operationId": route.operation_id,
        "summary": route.summary,
        "description": (
            f"Delegates to `{route.clusterctl}` — the same code path as "
            f"the CLI; clusterd adds no business logic.\n\n"
            f"Intended scope: `{route.scope}` — bearer scopes are parsed "
            "and attached to the request context but NOT enforced until "
            "issue #18 (design §3)."
        ),
        "parameters": parameters,
        "security": [{"bearerAuth": []}],
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
            "schemas": {"ErrorEnvelope": ERROR_ENVELOPE},
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": (
                        "Scoped bearer token (design §3). PLACEHOLDER: "
                        "tokens are parsed and attached to the request "
                        "context but NOT enforced until issue #18."
                    ),
                },
            },
        },
    }


def dump_openapi() -> str:
    return yaml.safe_dump(build_openapi(), sort_keys=False)
