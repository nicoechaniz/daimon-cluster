"""Authenticated private seed intake; public HTML contains no owner state."""
from __future__ import annotations

import base64
import hashlib
import re
import time

from clusterctl import being_seed

from . import auth
from .seed_ui import HTML, SCRIPT, agent_guide, agent_markdown, representation


def _owner(ctx):
    return (ctx.token_record or {}).get("owner", "*")


def _call(deps, ctx, fn, *args, **kwargs):
    from . import handlers

    try:
        return handlers.Response(200, fn(handlers._state_dir(deps), *args, owner=_owner(ctx), **kwargs))
    except being_seed.SeedError as error:
        return handlers._error(error.status, str(error), "seed", "intake", ctx.request_id)
    except (OSError, ValueError, KeyError, TypeError):
        return handlers._error(409, "seed_operation_requires_attention", "seed", "intake", ctx.request_id)


def list_seeds(deps, ctx, query=None, **params):
    from . import handlers

    def build():
        rows = being_seed.list_seeds(handlers._state_dir(deps), owner=_owner(ctx))
        return rows, int(time.time() * 1000), False
    return handlers._page_or_resume(deps, ctx, query=query, kind="seeds", filters=None, build=build)


def create_seed(deps, ctx, _body=None, **params):
    return _call(deps, ctx, being_seed.create, _body, key=ctx.idempotency_key)


def seed_access(deps, ctx, _body=None, **params):
    from . import handlers

    if _owner(ctx) != "*":
        return handlers.Response(403, {"error": "seed_operator_access_required"})
    if (not isinstance(_body, dict) or set(_body) != {"owner"}
            or not isinstance(_body["owner"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", _body["owner"])):
        return handlers.Response(400, {"error": "named_seed_owner_required"})
    # Same token store as the existing owner-local issuer. Only the hash is
    # retained; the private human browser receives the raw access once.
    record, token = auth.create_token(handlers._state_dir(deps), actor=_body["owner"],
                                      owner=_body["owner"], scopes=["fleet:read", "seed:write"], ttl_days=3)
    return handlers.Response(200, {"token": token, "token_id": record["token_id"],
                                 "owner": record["owner"], "expires_ms": record["expires_ms"]})


def seed_access_request(deps, ctx, _body=None, **params):
    from . import handlers

    try:
        return handlers.Response(200, auth.request_seed_access(handlers._state_dir(deps), _body))
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})


def seed_access_request_status(deps, ctx, request_id, _access_key=None, **params):
    from . import handlers

    try:
        return handlers.Response(200, auth.seed_access_request_status(handlers._state_dir(deps), request_id, _access_key))
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})


def seed_access_request_claim(deps, ctx, request_id, _access_key=None, _delivery=None, _body=None, **params):
    from . import handlers

    if _body != {} or _delivery not in {None, "browser"}:
        return handlers.Response(400, {"error": "invalid_access_claim"})
    try:
        data = auth.claim_seed_access(handlers._state_dir(deps), request_id, _access_key)
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})
    if _delivery == "browser":
        cookie = ("dm_seed_access=" + data.pop("token")
                  + "; Path=/v1; Secure; HttpOnly; SameSite=Strict; Max-Age=259200")
        return handlers.Response(200, data, headers={"Set-Cookie": cookie})
    return handlers.Response(200, data)


def seed_session(deps, ctx, **params):
    from . import handlers

    record = ctx.token_record
    return handlers.Response(200, {"owner": record["owner"], "expires_ms": record["expires_ms"]})


def seed_session_logout(deps, ctx, **params):
    from . import handlers

    auth.revoke_token(handlers._state_dir(deps), ctx.token_record["token_id"])
    return handlers.Response(200, {"signed_out": True}, headers={"Set-Cookie":
                            "dm_seed_access=; Path=/v1; Secure; HttpOnly; SameSite=Strict; Max-Age=0"})


def upload_seed(deps, ctx, seed, _stream, _length, _sha256, _transfer_encoding=None, **params):
    from . import handlers

    if _transfer_encoding:
        return handlers.Response(400, {"error": "content_length_upload_required"})
    try:
        length = int(_length)
    except (ValueError, TypeError):
        return handlers.Response(411, {"error": "content_length_upload_required"})
    return _call(deps, ctx, being_seed.upload, seed, stream=_stream, length=length, sha256=_sha256)


def discover_seed(deps, ctx, seed, **params):
    return _call(deps, ctx, being_seed.discovery, seed)


def prepare_seed(deps, ctx, seed, _body=None, **params):
    from . import handlers

    if not isinstance(_body, dict) or set(_body) != {"selection"}:
        return handlers.Response(400, {"error": "explicit_receiving_selection_required"})
    return _call(deps, ctx, being_seed.prepare, seed, _body["selection"])


def seed_connections(deps, ctx, seed, _body=None, **params):
    return _call(deps, ctx, being_seed.connections, seed, _body)


def seed_ui(deps, ctx, query=None, _accept="", **params):
    from . import handlers

    headers = {"Vary": "Accept", "Referrer-Policy": "no-referrer",
               "X-Content-Type-Options": "nosniff",
               "Link": '</v1/onboarding?format=markdown>; rel="alternate"; type="text/markdown", '
                       '</v1/onboarding?format=json>; rel="alternate"; type="application/json"'}
    formats = (query or {}).get("format", [])
    if len(formats) > 1 or formats and formats[0] not in {"html", "markdown", "json"}:
        return handlers.Response(400, {"error": "unsupported_onboarding_format"}, headers=headers)
    view = formats[0] if formats else representation(_accept)
    if view == "json":
        return handlers.Response(200, agent_guide(), headers=headers)
    if view == "markdown":
        return handlers.Response(200, agent_markdown(), "text/markdown; charset=utf-8", headers)
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    policy = ("default-src 'none'; script-src 'sha256-" + digest
              + "'; style-src 'unsafe-inline'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
    headers["Content-Security-Policy"] = policy
    return handlers.Response(200, HTML.replace("<!--SCRIPT-->", "<script>" + SCRIPT + "</script>"),
                             "text/html; charset=utf-8", headers)
