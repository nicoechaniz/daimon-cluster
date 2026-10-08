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


SIGNER_MODULES = ("__init__", "being_seed", "onboarding", "onboarding_input", "onboarding_release",
    "onboarding_code_successor", "onboarding_sdk", "onboarding_target", "onboarding_credential",
    "onboarding_peer", "onboarding_peer_native", "onboarding_existing", "onboarding_enrollment",
    "onboarding_local_body", "onboarding_progress", "onboarding_custody", "onboarding_enrollment_root")

def local_body_tool(deps, ctx, tool, **params):
    from . import handlers
    from clusterctl import onboarding_peer, onboarding_release

    root = Path(__file__).resolve().parents[1]
    if tool == "existing_root_signer.zip":
        import io
        import zipfile
        try:
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name in SIGNER_MODULES:
                    path = root / "clusterctl" / (name + ".py")
                    raw = onboarding_release.regular(path, uid=root.stat().st_uid, limit=200000)
                    if name == "onboarding_peer_native" and hashlib.sha256(raw).hexdigest() != onboarding_peer.TOOL_SHA256:
                        raise ValueError
                    info = zipfile.ZipInfo("clusterctl/" + name + ".py", (2026, 10, 8, 0, 0, 0))
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED)
                archive.writestr("README.txt", "Extract into a private directory. Use the qualified Matrix SDK pinned by onboarding_sdk.py; keep your original local body environment unchanged.\nRun: python -B -m clusterctl.onboarding_enrollment_root --handoff PRIVATE_JSON --holder EXISTING_LOCAL_HOLDER --password-fd OPEN_FD --output PRIVATE_REPLY_JSON\nFor a native historical offline Root+Recovery store, replace --holder with --root-custody EXISTING_LOCAL_ROOT_STORE. Runtime Body/capability stores are refused. The maintained V2 credential adapter currently supports Root threshold one.\nThis is a finite owner-invoked signer. Only the public reply goes back through the existing portal. The signer reads no Matrix inbox, starts no daemon and exports no custody.\n")
            raw = output.getvalue()
            return handlers.Response(200, raw, content_type="application/zip",
                headers={"X-Content-SHA256": hashlib.sha256(raw).hexdigest(),
                         "Content-Disposition": 'attachment; filename="existing_root_signer.zip"'})
        except (OSError, ValueError, OnboardingError):
            return handlers.Response(409, {"error": "local_body_tool_requires_attention"})
    paths = {'resume_seed_upload.py': root / 'tools/resume_seed_upload.py',
             'export_local_matrix_identity.py': root / 'tools/export_local_matrix_identity.py',
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


def existing_enrollment(deps, ctx, seed, _body=None, _submit=False, **params):
    from . import handlers
    from clusterctl import onboarding_enrollment as enrollment
    from clusterctl.onboarding_local_body import Requests
    try:
        if not deps.onboarding_progress:
            return handlers.Response(404, {"error": "local_body_request_not_found"})
        progress = Path(deps.onboarding_progress)
        task = Requests(progress, worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))
        if task["expected_being_ref"] is None:
            return handlers.Response(409, {"error": "existing_being_identity_required"})
        state = Path(handlers._state_dir(deps))
        try:
            hosted = Progress(progress, worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))
            hosted_ready = "matrix" in hosted["completed_steps"]
        except FileNotFoundError:
            hosted_ready = False
        if _submit and hosted_ready:
            return handlers.Response(409, {"error": "existing_hosted_identity_preserved"})
        try:
            handoff = enrollment.Handoffs(progress, worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))
        except FileNotFoundError:
            handoff = None
        if _submit:
            return handlers.Response(200, enrollment.submit(state, task, handoff, _body))
        source_path = state / "existing-enrollment" / seed / "source.json"
        source = being_seed._read(source_path) if source_path.exists() else None
        return handlers.Response(200, dict(request_id=task["request_id"], expected_being_ref=task["expected_being_ref"],
            source_received=source is not None, handoff=handoff, hosted_identity_ready=hosted_ready,
            response_path="/v1/onboarding/local-body/" + seed + "/enrollment",
            signer_tools="/v1/onboarding/local-body/tools/existing_root_signer.zip",
            instructions=[
                "Reuse the current being and local Root holder. Do not create genesis or send custody files.",
                "Submit cluster-onboarding-existing-source/v1 with request_id, the exported signed public identity and explicit native peer routes for every active existing body.",
                "When a handoff appears, save its exact public JSON privately. The maintained signer emits the reply for this request digest only.",
                "Run the signer in a separate process with the qualified Matrix SDK; pass the existing holder password by file descriptor. Keep keys and passwords local.",
                "Use --holder for a native isolated Root holder, or --root-custody for the existing offline Root+Recovery store. Never supply a runtime Body/capability store. Root threshold one is currently supported.",
                "Submit the public reply to response_path; the worker verifies it independently and publishes the next credential handoff automatically.",
                "A received reply is evidence pending host verification. It does not prove admission, source-body cutover, delivery or hosted acceptance.",
            ]))
    except FileNotFoundError:
        return handlers.Response(404, {"error": "local_body_request_not_found"})
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})
    except OnboardingError as error:
        if str(error) == "onboarding_job_not_found":
            return handlers.Response(404, {"error": "local_body_request_not_found"})
        return handlers.Response(409, {"error": "existing_enrollment_requires_attention"})
    except (OSError, ValueError, KeyError, TypeError):
        return handlers.Response(409, {"error": "existing_enrollment_requires_attention"})


def existing_enrollment_reply(deps, ctx, **params):
    return existing_enrollment(deps, ctx, _submit=True, **params)


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


def seed_hosted_checks(deps, ctx, seed, _body=None, _submit=False, **params):
    from . import handlers
    from clusterctl.onboarding_acceptance import Requests, read, submit

    try:
        state = Path(handlers._state_dir(deps))
        being_seed.status(state, seed, owner=_owner(ctx))
        if not deps.onboarding_progress:
            return handlers.Response(200, {"request": None})
        request = Requests(
            deps.onboarding_progress, worker_uid=deps.onboarding_worker_uid
        ).read(seed, owner=_owner(ctx))
        value = submit(state, request, _body) if _submit else read(state, request)
        return handlers.Response(200, {"request": value})
    except FileNotFoundError:
        return (
            handlers.Response(200, {"request": None})
            if not _submit
            else handlers.Response(409, {"error": "hosted_checks_not_ready"})
        )
    except being_seed.SeedError as error:
        return handlers.Response(error.status, {"error": str(error)})
    except OnboardingError as error:
        if str(error) == "onboarding_job_not_found":
            return handlers.Response(404, {"error": "seed_not_found"})
        return handlers.Response(409, {"error": "hosted_checks_require_attention"})
    except (OSError, ValueError, KeyError, TypeError):
        return handlers.Response(409, {"error": "hosted_checks_require_attention"})


def seed_hosted_witness(deps, ctx, **params):
    return seed_hosted_checks(deps, ctx, _submit=True, **params)


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


def seed_upload_progress(deps, ctx, seed, **params):
    return _call(deps, ctx, being_seed.upload_progress, seed)


def upload_seed(deps, ctx, seed, _stream, _length, _sha256, _transfer_encoding=None,
                _offset=None, _total=None, _prefix=None, **params):
    from . import handlers

    if _transfer_encoding:
        return handlers.Response(400, {"error": "content_length_upload_required"})
    try:
        length = int(_length)
    except (ValueError, TypeError):
        return handlers.Response(411, {"error": "content_length_upload_required"})
    if _offset is not None or _total is not None or _prefix is not None:
        try:
            offset, total = int(_offset), int(_total)
        except (TypeError, ValueError):
            return handlers.Response(400, {"error": "seed_upload_resume_headers_required"})
        return _call(deps, ctx, being_seed.upload, seed, stream=_stream, length=length,
                     sha256=_sha256, offset=offset, total=total, prefix_sha256=_prefix)
    return _call(deps, ctx, being_seed.upload, seed, stream=_stream, length=length, sha256=_sha256)


def seed_transfer(deps, ctx, seed, _body=None, _submit=False, **params):
    from . import handlers
    from clusterctl import onboarding_transfer
    from clusterctl.onboarding_local_body import Requests

    if _submit and _body != {}:
        return handlers.Response(400, {'error': 'empty_transfer_request_required'})
    expected = None
    if _submit and deps.onboarding_progress:
        try:
            expected = Requests(deps.onboarding_progress,
                worker_uid=deps.onboarding_worker_uid).read(seed, owner=_owner(ctx))['expected_being_ref']
        except FileNotFoundError:
            pass
        except (OnboardingError, OSError, ValueError):
            return handlers.Response(409, {'error': 'transfer_identity_request_requires_attention'})
    if _submit:
        return _call(deps, ctx, onboarding_transfer.request, seed, expected_being_ref=expected)
    return _call(deps, ctx, onboarding_transfer.read, seed)


def seed_transfer_request(deps, ctx, **params):
    return seed_transfer(deps, ctx, _submit=True, **params)


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
