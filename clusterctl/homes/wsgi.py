"""Cheroot transport for the existing Homes request routes.

HTTP parsing, connection admission and output backpressure belong to Cheroot.
Only the request/response interface is adapted; policy and route dispatch stay
in service.handler, including per-request proof lifetimes and streaming reads.
"""

from email.message import Message
from contextlib import suppress

from cheroot.server import HTTPConnection, HTTPRequest, HeaderReader

from .service import handler


class CanonicalHeaders(HeaderReader):
    def _allow_header(self, key_name):
        # WSGI maps both '-' and '_' to underscores. Drop the latter before
        # that lossy conversion so a client cannot replace proxy-owned fields.
        return b'_' not in key_name


class CanonicalRequest(HTTPRequest):
    header_reader = CanonicalHeaders()


class ClosingConnection(HTTPConnection):
    RequestHandlerClass = CanonicalRequest

    def close(self):
        try:
            super().close()
        finally:
            # Cheroot11.1.2 closes its reader/socket but leaves the response
            # file to GC. After a timed-out write, Python3.13's finalizer can
            # then retry buffered output against the already-closed socket.
            # Close the writer explicitly; IOBase closes its raw file even
            # when flushing the interrupted response raises OSError.
            with suppress(OSError):
                self.wfile.close()


def application(app, *, owner=False):
    routes = handler(app, owner=owner)

    class Request(routes):
        def __init__(self, environ, start_response):
            # Do not initialize BaseHTTPRequestHandler or parse HTTP twice.
            # Cheroot supplies the raw target as REQUEST_URI. PATH_INFO has
            # already been unquoted and must not select artifact file paths.
            self.path = environ["REQUEST_URI"]
            self.command = environ["REQUEST_METHOD"]
            self.rfile = environ["wsgi.input"]
            self.headers = Message()
            for name, value in environ.items():
                if name.startswith("HTTP_"):
                    self.headers[name[5:].replace("_", "-")] = value
            for name in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                if environ.get(name) is not None:
                    self.headers[name.replace("_", "-")] = environ[name]
            self._start_response = start_response
            self._response_headers = []
            self._headers_sent = False
            self.close_connection = False
            self.wfile = self

        def send_response(self, code, message=None):
            self._status = f"{code} {message if message is not None else self.responses.get(code, ('',))[0]}"
            self._response_headers = []

        def send_header(self, name, value):
            self._response_headers.append((name, str(value)))

        def end_headers(self):
            self._write = self._start_response(self._status, self._response_headers)
            self._headers_sent = True

        def write(self, data):
            # PEP3333's synchronous write preserves existing incremental
            # backend reads. Cheroot writes through the accepted socket's30s timeout here.
            self._write(data)
            return len(data)

    def dispatch(environ, start_response):
        if "REQUEST_URI" not in environ:
            start_response("503 Service Unavailable", [("Content-Length", "0")])
            return []
        request = Request(environ, start_response)
        route = {"GET": request.do_GET, "HEAD": request.do_HEAD,
                 "POST": request.do_POST}.get(request.command)
        if route is None:
            request.respond(405, {}, headers=(("Allow", "GET, HEAD, POST"),))
        else:
            route()
        if request.close_connection:
            # Existing streaming failure paths have already sent headers.
            # Do not acknowledge a truncated stream as a successful iterable.
            raise OSError("incomplete_home_response")
        return []

    return dispatch


def create_server(app, *, port, owner=False):
    from cheroot.wsgi import Server

    workers = 4 if owner else 8
    server = Server(
        ('127.0.0.1', port), application(app, owner=owner),
        numthreads=workers, max=workers,
        request_queue_size=16 if owner else 64,
        accepted_queue_size=4 if owner else 24,
        accepted_queue_timeout=1, timeout=30, shutdown_timeout=5,
    )
    server.keep_alive_conn_limit = 2 if owner else 8
    server.ConnectionClass = ClosingConnection
    server.max_request_header_size = 32768
    # Preserve the existing exceptional note-upload allowance. Other POSTs
    # still have the route's64KiB limit; the owner listener has no note route.
    server.max_request_body_size = 65536 if owner else 5 * 1024 * 1024
    return server


def run(app, config):
    import threading

    servers = []
    try:
        for key, owner in (("viewer_port", False), ("owner_port", True)):
            server = create_server(app, port=config[key], owner=owner)
            servers.append(server)
            server.prepare()
        threading.Thread(target=servers[1].serve, daemon=True).start()
        servers[0].serve()
    finally:
        for server in reversed(servers):
            if server.ready:
                server.stop()
