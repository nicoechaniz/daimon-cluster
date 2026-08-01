"""clusterd HTTP server (stdlib http.server only).

ThreadingHTTPServer dispatching the route table (``clusterd.routes``)
to handlers (``clusterd.handlers``). Default bind 127.0.0.1:8785 —
production binds the anyVPN interface (design §1), never public.

Envelope (design §1): every response carries X-Request-Id (echoed or
generated uuid4). Auth is ENFORCED (issue #18, design §2/§3) in
``_enforce`` before any handler runs:

- default-deny: every route except GET /v1/health requires a valid
  bearer token (missing/unknown/expired/revoked -> 401);
- scope check per route (read/mutate -> 403);
- owner check: non-``*`` owners may only touch daimons whose spec
  ``created_by`` matches (-> 403 "not your daimon");
- unattended steward denial: ``steward@*`` actors need
  ``X-Attended: true`` on mutations (-> 403, v1 mechanism; real
  presence flow lands in M5);
- per-token sliding-window rate limit: 60 mutations/minute -> 429;
- destructive-class routes require a consumed confirmation challenge
  (``clusterd.confirm``) — otherwise 409 with the challenge JSON.

Every denial appends an ``audit-event/v1`` (result "denied") with the
actor, request_id and reason — NEVER any token material.
"""

from __future__ import annotations

import dataclasses
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from clusterctl import audit
from clusterctl.config import load_config

from . import __version__, auth, confirm, handlers, routes

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8785


class ClusterdHandler(BaseHTTPRequestHandler):
    server_version = f"clusterd/{__version__}"
    protocol_version = "HTTP/1.1"

    # Quieter logging: keep BaseHTTPRequestHandler format but to stderr
    # (default). Override log_message here to silence if needed.

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    # -- envelope ------------------------------------------------------

    def _context(self) -> handlers.RequestContext:
        request_id = self.headers.get("X-Request-Id") or str(uuid.uuid4())
        actor = self.headers.get("X-Actor") or "anonymous"
        token = None
        auth_header = self.headers.get("Authorization") or ""
        if auth_header.lower().startswith("bearer "):
            token = auth_header[len("bearer "):].strip() or None
        return handlers.RequestContext(
            request_id=request_id,
            actor=actor,
            scope_token=token,
            idempotency_key=self.headers.get("Idempotency-Key"),
        )

    def _respond(self, ctx: handlers.RequestContext,
                 resp: handlers.Response) -> None:
        if resp.content_type == "application/json":
            body = json.dumps(resp.body, indent=2).encode("utf-8")
        else:
            body = str(resp.body).encode("utf-8")
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("X-Request-Id", ctx.request_id)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- auth enforcement (issue #18) ----------------------------------

    def _deny(self, ctx: handlers.RequestContext, route, path: str,
              status: int, error: str, reason: str,
              extra: dict | None = None) -> handlers.Response:
        """Structured denial + security audit event.

        The audit detail carries actor + request_id + reason only —
        NEVER the bearer token, not even a prefix.
        """
        try:
            audit.append_event(
                self.server.state_dir,
                actor=ctx.actor,
                action=route.operation_id,
                target=path,
                result="denied",
                detail={"reason": reason, "request_id": ctx.request_id},
                idempotency_key=ctx.idempotency_key,
                request_id=ctx.request_id,
                action_digest=ctx.action_digest,
            )
        except OSError:
            pass  # fail-closed for mutations is issue #19's audit work
        body = {
            "error": error,
            "action": route.operation_id,
            "target": path,
            "request_id": ctx.request_id,
        }
        if extra:
            body.update(extra)
        return handlers.Response(status, body)

    def _enforce(self, ctx: handlers.RequestContext, route,
                 params: dict, path: str):
        """Return (ctx, None) when allowed, else (ctx, denial Response)."""
        if route.public:
            return ctx, None
        srv = self.server

        # 1. bearer resolution + validity (401) -------------------------
        record, reason = auth.authenticate(srv.token_store, ctx.scope_token)
        if record is None:
            return ctx, self._deny(ctx, route, path, 401,
                                   "unauthorized", reason)
        # The token's actor is authoritative; X-Actor is advisory only.
        ctx = dataclasses.replace(ctx, actor=record["actor"],
                                  token_record=record)

        # 2. scope check (403) ------------------------------------------
        if not auth.has_scope(record, route.required_scope):
            return ctx, self._deny(ctx, route, path, 403,
                                   "insufficient-scope",
                                   f"missing-scope:{route.required_scope}")

        # 3. owner check (403) ------------------------------------------
        owner = record.get("owner") or "*"
        name = params.get("name")
        if owner != "*" and name is not None:
            spec_owner = auth.instance_owner(srv.state_dir, name)
            if spec_owner is not None and spec_owner != owner:
                return ctx, self._deny(ctx, route, path, 403,
                                       "not your daimon",
                                       "owner-mismatch")

        # 4. unattended steward denial (403) — v1 mechanism; M5 lands
        #    the real presence flow (see clusterd.confirm docstring).
        #    Challenge-only requests on confirmation-gated routes are
        #    PREPARATION, not execution: an unattended steward may obtain
        #    a challenge (it mutates nothing — execution still requires
        #    X-Attended AND the single-use digest-bound token).
        challenge_only = (
            getattr(route, "confirmation_required", False)
            and self.headers.get("X-Confirm-Token") is None
        )
        if route.mutation and not challenge_only and \
                confirm.steward_requires_attendance(record["actor"]):
            if (self.headers.get("X-Attended") or "").lower() != \
                    confirm.ATTENDED_HEADER_VALUE:
                return ctx, self._deny(ctx, route, path, 403,
                                       "unattended-steward-denied",
                                       "steward-missing-x-attended")

        # 5. per-token mutation rate limit (429) ------------------------
        if route.mutation:
            if not srv.rate_limiter.allow(record["token_id"]):
                return ctx, self._deny(ctx, route, path, 429,
                                       "rate-limited", "mutation-rate-limit")

        # 6. destructive-class prepare/confirm (409) --------------------
        if route.confirmation_required:
            operation = route.path.rsplit("/", 1)[-1]
            args = {}
            token = self.headers.get("X-Confirm-Token")
            if not token:
                challenge = confirm.issue_challenge(
                    srv.state_dir, operation=operation, target=name,
                    actor=record["actor"], args=args)
                body = {k: challenge[k] for k in (
                    "schema", "token", "operation", "target", "actor",
                    "action_digest", "created_ms", "ttl_s")}
                body["request_id"] = ctx.request_id
                return ctx, handlers.Response(409, body)
            try:
                challenge = confirm.consume_challenge(
                    srv.state_dir, token, operation=operation, target=name,
                    actor=record["actor"], args=args)
            except confirm.ConfirmationError as exc:
                return ctx, self._deny(ctx, route, path, 409,
                                       "confirmation-required", exc.reason)
            # The consumed digest flows into the mutation's audit event
            # (issue #19): the event proves WHICH confirmed action ran.
            ctx = dataclasses.replace(
                ctx, action_digest=challenge.get("action_digest"))

        return ctx, None

    # -- dispatch ------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        ctx = self._context()
        split = urlsplit(self.path)
        path = split.path
        query = parse_qs(split.query)
        # Read POST body for dashboard mutation routes.
        _body: dict = {}
        if method == "POST":
            cl = int(self.headers.get("Content-Length", 0))
            if 0 < cl < 65536:
                try:
                    _body = json.loads(self.rfile.read(cl))
                except (json.JSONDecodeError, Exception):
                    pass
        try:
            route, params = routes.match(method, path)
        except routes.MethodNotAllowed:
            self._respond(ctx, handlers.Response(405, {
                "error": f"method {method} not allowed for {path}",
                "action": method.lower(),
                "target": path,
                "request_id": ctx.request_id,
            }))
            return
        if route is None:
            self._respond(ctx, handlers.Response(404, {
                "error": f"no such route: {method} {path}",
                "action": method.lower(),
                "target": path,
                "request_id": ctx.request_id,
            }))
            return
        ctx, denial = self._enforce(ctx, route, params, path)
        if denial is not None:
            self._respond(ctx, denial)
            return
        handler = handlers.HANDLERS[route.handler]
        try:
            resp = handler(self.server.deps, ctx, route=route, query=query,
                           _body=_body, **params)
        except Exception as exc:  # pragma: no cover - defensive
            resp = handlers.Response(500, {
                "error": f"clusterd internal error: {exc!r}",
                "action": route.operation_id,
                "target": path,
                "request_id": ctx.request_id,
            })
        self._respond(ctx, resp)


class ClusterdServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, bind: str, port: int, deps: handlers.Deps,
                 token_store: auth.TokenStore | None = None,
                 rate_limiter: auth.RateLimiter | None = None):
        super().__init__((bind, port), ClusterdHandler)
        self.deps = deps
        state_dir = deps.state_dir
        if state_dir is None:
            state_dir = load_config(deps.config_path).state_dir
        self.state_dir = state_dir
        # mtime-checked store: revocation takes effect WITHOUT restart.
        # Multi-bind deployments (issue #21) pass SHARED store + limiter:
        # two sockets, one service — a token created/revoked on either
        # bind is honored by both, and mutation rate limits are global.
        self.token_store = token_store or auth.TokenStore(state_dir)
        self.rate_limiter = rate_limiter or auth.RateLimiter()


def make_server(deps: handlers.Deps, bind: str = DEFAULT_BIND,
                port: int = DEFAULT_PORT) -> ClusterdServer:
    return ClusterdServer(bind, port, deps)


def make_servers(deps: handlers.Deps,
                 binds: list[tuple[str, int]]) -> list[ClusterdServer]:
    """One ClusterdServer per bind, sharing ONE token store and ONE rate
    limiter (same service, several sockets — issue #21)."""
    state_dir = deps.state_dir or load_config(deps.config_path).state_dir
    token_store = auth.TokenStore(state_dir)
    rate_limiter = auth.RateLimiter()
    return [ClusterdServer(host, port, deps,
                           token_store=token_store,
                           rate_limiter=rate_limiter)
            for host, port in binds]


def serve(deps: handlers.Deps,
          binds: list[tuple[str, int]] | None = None) -> None:
    """Bind every address in ``binds`` (default 127.0.0.1:8785), each in
    its own daemon thread; block until KeyboardInterrupt, then shut all
    servers down."""
    if not binds:
        binds = [(DEFAULT_BIND, DEFAULT_PORT)]
    servers = make_servers(deps, binds)
    threads = []
    for srv in servers:
        host, actual_port = srv.server_address[:2]
        print(f"clusterd {__version__} listening on http://{host}:{actual_port}")
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()
        for t in threads:
            t.join(timeout=5)
