"""Authenticated private seed intake; public HTML contains no owner state."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from pathlib import Path

from clusterctl import being_seed, onboarding_consent
from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_progress import Progress

from . import auth
from .seed_ui import HTML, SCRIPT, agent_guide, agent_markdown, representation


def local_body_tool(deps, ctx, tool, **params):
    from . import handlers
    from clusterctl import onboarding_peer, onboarding_release

    root = Path(__file__).resolve().parents[1]
    paths = {'export_local_matrix_identity.py': root / 'tools/export_local_matrix_identity.py',
             'onboarding_peer_native.py': root / 'clusterctl/onboarding_peer_native.py'}
    if tool not in paths:
        return handlers.Response(404, {'error': 'local_body_tool_not_found'})
    try:
        raw = onboarding_release.regular(paths[tool], uid=root.stat().st_uid, limit=100000)
        if tool == 'onboarding_peer_native.py' and hashlib.sha256(raw).hexdigest() != onboarding_peer.TOOL_SHA256:
            raise ValueError
        return handlers.Response(200, raw.decode(), content_type='text/plain; charset=utf-8',
            headers={'X-Content-SHA256': hashlib.sha256(raw).hexdigest(),
                     'Content-Disposition': 'attachment; filename="' + tool + '"'})
    except (OSError, ValueError, OnboardingError):
        return handlers.Response(409, {'error': 'local_body_tool_requires_attention'})


def local_body_requests(deps, ctx, seed=None, _body=None, _submit=False, _diagnostic=False, **params):
    from . import handlers
    from clusterctl.onboarding_local_body import Requests, read, submit, submit_diagnostic

    try:
        if not deps.onboarding_progress:
            return handlers.Response(200, {'items': []})
        requests = Requests(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid)
        state = Path(handlers._state_dir(deps))
        if seed is not None:
            request = requests.read(seed, owner=_owner(ctx))
            value = (submit_diagnostic(state, request, _body) if _diagnostic else
                     submit(state, request, _body) if _submit else read(state, request))
            return handlers.Response(200, value)
        requests._directory()
        items = []
        for path in sorted(requests.root.glob('*' + requests.suffix)):
            candidate = path.name.removesuffix(requests.suffix)
            try:
                request = requests.read(candidate, owner=_owner(ctx))
            except OnboardingError as exc:
                if str(exc) == 'onboarding_job_not_found':
                    continue
                raise
            items.append(read(state, request))
        return handlers.Response(200, {'items': items})
    except FileNotFoundError:
        return handlers.Response(404, {'error': 'local_body_request_not_found'})
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {'error': str(error)})
    except OnboardingError as error:
        if str(error) == 'onboarding_job_not_found':
            return handlers.Response(404, {'error': 'local_body_request_not_found'})
        return handlers.Response(409, {'error': 'local_body_verification_requires_attention'})
    except (OSError, ValueError, KeyError, TypeError):
        return handlers.Response(409, {'error': 'local_body_verification_requires_attention'})


def local_body_report(deps, ctx, **params):
    return local_body_requests(deps, ctx, _submit=True, **params)


def local_body_diagnostic(deps, ctx, **params):
    return local_body_requests(deps, ctx, _diagnostic=True, **params)


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
        if deps.onboarding_progress:
            for row in rows:
                try:
                    row["onboarding"] = Progress(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid).read(
                        row["name"], owner=_owner(ctx))
                    row["active"] = row["onboarding"]["active"]
                except FileNotFoundError:
                    row["onboarding"] = None
                except (OnboardingError, OSError, ValueError, TypeError, KeyError):
                    row["onboarding"] = {"state": "attention-required", "reason": "verification_failed", "active": False}
        return rows, int(time.time() * 1000), False
    return handlers._page_or_resume(deps, ctx, query=query, kind="seeds", filters=None, build=build)


def seed_onboarding_status(deps, ctx, seed, **params):
    from . import handlers

    try:
        being_seed.status(handlers._state_dir(deps), seed, owner=_owner(ctx))
        if not deps.onboarding_progress:
            return handlers.Response(200, {"state": "waiting", "reason": "backend_unavailable", "active": False})
        value = Progress(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))
        return handlers.Response(200, value)
    except FileNotFoundError:
        return handlers.Response(200, {"state": "waiting", "reason": "host_authorization_required", "active": False})
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})
    except (OnboardingError, OSError, ValueError, TypeError, KeyError):
        return handlers.Response(409, {"error": "onboarding_progress_requires_attention"})


def seed_onboarding_action(deps, ctx, seed, **params):
    from . import handlers
    from clusterctl.onboarding_actions import Actions

    try:
        being_seed.status(handlers._state_dir(deps), seed, owner=_owner(ctx))
        if not deps.onboarding_progress:
            return handlers.Response(200, {'action': None})
        value = Actions(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))
        action = value['action']
        if action is not None and action['deadline_ms'] <= int(time.time() * 1000):
            value = {**value, 'action': None}
        return handlers.Response(200, value)
    except FileNotFoundError:
        return handlers.Response(200, {'action': None})
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {'error': str(error)})
    except (OnboardingError, OSError, ValueError, TypeError, KeyError):
        return handlers.Response(409, {'error': 'onboarding_action_requires_attention'})


def seed_onboarding_access(deps, ctx, seed, **params):
    from . import handlers
    from clusterctl.onboarding_ingress import Access

    try:
        being_seed.status(handlers._state_dir(deps), seed, owner=_owner(ctx))
        if not deps.onboarding_progress:
            return handlers.Response(200, {'ssh': None})
        value = Access(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))
        return handlers.Response(200, value)
    except FileNotFoundError:
        return handlers.Response(200, {'ssh': None})
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {'error': str(error)})
    except (OnboardingError, OSError, ValueError, TypeError, KeyError):
        return handlers.Response(409, {'error': 'onboarding_access_requires_attention'})


def seed_onboarding_review(deps, ctx, seed, _body=None, _submit=False, **params):
    from . import handlers

    try:
        state = handlers._state_dir(deps)
        being_seed.status(state, seed, owner=_owner(ctx))
        if not deps.onboarding_progress:
            return handlers.Response(200, {"state": "waiting", "reason": "backend_unavailable"})
        reviews = onboarding_consent.Reviews(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid)
        proposal = reviews.read(seed, owner=_owner(ctx))
        if _submit:
            return handlers.Response(200, onboarding_consent.submit(state, seed, _body, owner=_owner(ctx), reviews=reviews))
        decision = onboarding_consent.read(state, proposal, intake_uid=os.geteuid())
        if decision is None:
            from clusterctl.onboarding_approvals import Status
            try:
                recorded = Status(deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid).read(
                    seed, owner=_owner(ctx))
            except FileNotFoundError:
                recorded = None
            if recorded is not None and recorded['review_digest'] == proposal['review_digest']:
                return handlers.Response(200, {'review': proposal, 'recorded': recorded['recorded'],
                    'matrix_identity_mode': recorded['matrix_identity_mode'],
                    'recorded_by': recorded['recorded_by']})
        return handlers.Response(200, {"review": proposal, "recorded": decision is not None,
                                      "matrix_identity_mode": decision["matrix_identity_mode"] if decision else None})
    except FileNotFoundError:
        return handlers.Response(200, {"state": "waiting", "reason": "host_authorization_required"})
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})
    except (OnboardingError, OSError, ValueError, TypeError, KeyError):
        return handlers.Response(409, {"error": "onboarding_review_requires_attention"})


def seed_onboarding_consent(deps, ctx, seed, **params):
    return seed_onboarding_review(deps, ctx, seed, _submit=True, **params)


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
