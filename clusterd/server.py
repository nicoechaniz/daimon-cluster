"""clusterd HTTP server (stdlib http.server only).

ThreadingHTTPServer dispatching the route table (``clusterd.routes``)
to handlers (``clusterd.handlers``). Default bind 127.0.0.1:8785 —
production binds the anyVPN interface (design §1), never public.

Envelope (design §1): every response carries X-Request-Id (echoed or
generated uuid4); X-Actor defaults to "anonymous"; the bearer token is
parsed into the request context but NOT enforced (issue #18).
"""

from __future__ import annotations

import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import __version__, handlers, routes

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
        # Bearer token is PARSED and attached but NOT enforced (#18).
        token = None
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth[len("bearer "):].strip() or None
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

    # -- dispatch ------------------------------------------------------

    def _dispatch(self, method: str) -> None:
        ctx = self._context()
        path = urlsplit(self.path).path
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
        handler = handlers.HANDLERS[route.handler]
        try:
            resp = handler(self.server.deps, ctx, route=route, **params)
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

    def __init__(self, bind: str, port: int, deps: handlers.Deps):
        super().__init__((bind, port), ClusterdHandler)
        self.deps = deps


def make_server(deps: handlers.Deps, bind: str = DEFAULT_BIND,
                port: int = DEFAULT_PORT) -> ClusterdServer:
    return ClusterdServer(bind, port, deps)


def serve(deps: handlers.Deps, bind: str = DEFAULT_BIND,
          port: int = DEFAULT_PORT) -> None:  # pragma: no cover - manual
    server = make_server(deps, bind, port)
    host, actual_port = server.server_address[:2]
    print(f"clusterd {__version__} listening on http://{host}:{actual_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
