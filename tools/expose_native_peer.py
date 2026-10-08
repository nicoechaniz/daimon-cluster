#!/usr/bin/env python3
"""Foreground VPN carrier for an unchanged loopback-only native Matrix peer.

No custody, inbox access, inference, daemon restart or service installation.
The existing native peer authenticates and processes its own wire envelopes.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LIMIT = 3 * 1024 * 1024
CONTENT_TYPE = 'application/vnd.daimon.peer+jcs'
NATIVE_PORT = 8687


class Carrier(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.connection.settimeout(30)
        headers = self.headers.get_all('Content-Length', failobj=[])
        if (self.client_address[0] != self.server.allowed_host
                or self.path != '/dm-peer/v1'
                or self.headers.get('Content-Type') != CONTENT_TYPE
                or self.headers.get('Transfer-Encoding') is not None
                or len(headers) != 1 or not headers[0].isdecimal()
                or not 1 <= int(headers[0]) <= LIMIT):
            self.send_error(403)
            return
        connection = http.client.HTTPConnection('127.0.0.1', NATIVE_PORT, timeout=30)
        try:
            raw = self.rfile.read(int(headers[0]))
            if len(raw) != int(headers[0]):
                raise ValueError
            connection.request('POST', '/dm-peer/v1', raw, {'Content-Type': CONTENT_TYPE})
            response = connection.getresponse()
            body = response.read(LIMIT + 1)
            lengths = response.headers.get_all('Content-Length', failobj=[])
            if len(body) > LIMIT or lengths != [str(len(body))]:
                raise ValueError
            self.send_response(response.status)
            self.send_header('Content-Type', response.getheader('Content-Type', CONTENT_TYPE))
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (OSError, ValueError, http.client.HTTPException):
            self.send_error(503)
        finally:
            connection.close()


def addresses(bind: str, host: str) -> tuple[str, str]:
    values = [ipaddress.IPv4Address(value) for value in (bind, host)]
    if any(not value.is_private or value.is_loopback or value.is_unspecified
           or value.is_multicast or value.is_link_local for value in values) or values[0] == values[1]:
        raise ValueError('dedicated_vpn_addresses_required')
    return str(values[0]), str(values[1])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--allow-host', required=True)
    parser.add_argument('--port', type=int, default=18687)
    parser.add_argument('--duration', type=int, default=14400)
    args = parser.parse_args(argv)
    bind, host = addresses(args.bind, args.allow_host)
    if not 1024 <= args.port <= 65535 or not 1 <= args.duration <= 86400:
        raise ValueError('bounded_foreground_carrier_required')
    with ThreadingHTTPServer((bind, args.port), Carrier) as server:
        server.allowed_host = host
        server.timeout = 1
        deadline = time.monotonic() + args.duration
        try:
            while time.monotonic() < deadline:
                server.handle_request()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
