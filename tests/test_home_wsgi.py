"""Real HTTP contract and admission checks for the optional Homes transport."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, closing
from http.client import HTTPConnection, IncompleteRead
import socket
import inspect
import time
import json
import threading
from unittest.mock import patch

import pytest

from clusterctl.homes import service, wsgi
from tests import test_home_gateway as gateway
from tests.test_home_passkeys import system, approved


@contextmanager
def running(app, *, owner=False, routes=None):
    if routes is None:
        server = wsgi.create_server(app, port=0, owner=owner)
    else:
        with patch.object(wsgi, 'handler', return_value=routes):
            server = wsgi.create_server(app, port=0, owner=owner)
    server.prepare()
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stop()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize('contract', [
    gateway.test_http_catalog_files_ranges_and_revocation_use_same_authority,
    gateway.test_owner_identity_approval_and_shared_roster_are_not_reader_powers,
    gateway.test_browser_code_claim_returns_to_same_local_destination,
    gateway.test_owner_publication_uses_one_request_local_actor_catalog,
    gateway.test_http_proof_snapshot_reuses_actor_reads_but_not_later_revocation,
    gateway.test_installed_public_assets_ignore_identity_but_keep_origin_and_private_checks,
])
def test_existing_http_contract_on_wsgi(tmp_path, monkeypatch, contract):
    """Reuse substantive existing checks, replacing only the Homes socket stack."""
    legacy = gateway.serving

    @contextmanager
    def serving(routes):
        if routes.do_GET.__module__ != service.__name__:
            with legacy(routes) as url:
                yield url
        else:
            with running(None, routes=routes) as server:
                yield 'http://127.0.0.1:' + str(server.socket.getsockname()[1])

    monkeypatch.setattr(gateway, 'serving', serving)
    if 'monkeypatch' in inspect.signature(contract).parameters:
        contract(tmp_path, monkeypatch)
    else:
        contract(tmp_path)


def test_partial_headers_and_bodies_do_not_occupy_workers(tmp_path):
    app, _ = system.__wrapped__(tmp_path)
    token, _ = approved(app)
    with running(app) as viewer, running(app, owner=True) as owner:
        assert viewer._connections is not owner._connections
        assert viewer.requests.min == viewer.requests.max == 8
        assert owner.requests.min == owner.requests.max == 4
        assert viewer.requests._queue.maxsize == 24 and owner.requests._queue.maxsize == 4
        partial = []
        try:
            for server in (viewer, owner):
                for body in [b'GET / HTTP/1.1\r\nHost: one.example.test\r\nX-Hold:',
                             b'POST /access/claim HTTP/1.1\r\nHost: one.example.test\r\nContent-Length: 16\r\n\r\nx']:
                    conn = socket.create_connection(('127.0.0.1', int(server.socket.getsockname()[1])), timeout=3)
                    partial.append(conn)
                    conn.sendall(body)

            def read(index):
                server = viewer if index % 4 else owner
                with closing(HTTPConnection('127.0.0.1', int(server.socket.getsockname()[1]), timeout=3)) as conn:
                    conn.request('GET', '/catalog.json', headers={'Host': 'one.example.test', 'Cookie': '__Host-home=' + token})
                    response = conn.getresponse()
                    response.read()
                    assert response.status == (200 if server is viewer else 404)

            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(read, range(16)))
            for server in (viewer, owner):
                assert server.timeout == 30
                assert len(server.requests._threads) <= server.requests.max
            # Observe the configured production inactivity limit, rather than
            # treating a setting or a shortened test timeout as expiry proof.
            for conn in partial:
                conn.settimeout(35)
                data = conn.recv(4096)
                assert not data or data.startswith(b'HTTP/1.1 408 ')
                if data:
                    assert conn.recv(4096) == b''
        finally:
            for conn in partial:
                conn.close()


@pytest.mark.parametrize('wire,status,owner', [
    (b'POST /access/claim HTTP/1.1\r\nHost: one.example.test\r\nContent-Length: 65537\r\n\r\n', 413, True),
    (b'POST /review-notes HTTP/1.1\r\nHost: one.example.test\r\nContent-Length: 5242881\r\n\r\n', 413, False),
    (b'GET / HTTP/1.1\r\nHost: one.example.test\r\nX-Large: ' + b'x' * 32768 + b'\r\n\r\n', 413, False),
], ids=['owner-body', 'viewer-note-body', 'headers'])
def test_parser_rejects_oversized_input_before_application(tmp_path, wire, status, owner):
    app, _ = system.__wrapped__(tmp_path)
    with running(app, owner=owner) as server:
        with closing(socket.create_connection(('127.0.0.1', int(server.socket.getsockname()[1])), timeout=3)) as conn:
            conn.sendall(wire)
            assert int(conn.recv(1024).split(b' ', 2)[1]) == status


def test_stream_failure_is_not_a_complete_success_and_workers_recover(tmp_path):
    app, _ = system.__wrapped__(tmp_path)

    class BrokenStream(service.handler(app)):
        def do_GET(self):
            if self.path == '/truncated':
                self.send_response(200)
                self.send_header('Content-Length', '100')
                self.end_headers()
                self.wfile.write(b'part')
                self.close_connection = True
            else:
                super().do_GET()

    with running(None, routes=BrokenStream) as server:
        for path in ['/truncated', '/catalog.json']:
            with closing(HTTPConnection('127.0.0.1', int(server.socket.getsockname()[1]), timeout=3)) as conn:
                conn.request('GET', path, headers={'Host': 'one.example.test'})
                response = conn.getresponse()
                if path == '/truncated':
                    with pytest.raises(IncompleteRead):
                        response.read()
                else:
                    assert response.status == 200
                    response.read()


def test_existing_note_upload_contract_above_64k(tmp_path, monkeypatch):
    import base64
    import struct
    import zlib
    from tests import test_home_review_notes as notes

    # A real PNG ancillary text chunk makes the existing contract exceed64KiB
    # without huge images, another image library or changes to validation.
    png = base64.b64decode(notes.PNG)
    chunk = b'tEXt' + b'Description\0' + b'A' * 65536
    png = png[:-12] + struct.pack('>I', len(chunk) - 4) + chunk + struct.pack('>I', zlib.crc32(chunk)) + png[-12:]
    monkeypatch.setattr(notes, 'PNG', base64.b64encode(png).decode())

    @contextmanager
    def serving(routes):
        with running(None, routes=routes) as server:
            yield 'http://127.0.0.1:' + str(server.socket.getsockname()[1])

    monkeypatch.setattr(notes, 'serving', serving)
    notes.test_note_http_save_retry_read_delete_and_current_source_revocation(
        system.__wrapped__(tmp_path), monkeypatch)


def test_nonreading_client_releases_stream_worker_at_real_timeout(tmp_path):
    app, _ = system.__wrapped__(tmp_path)
    finished = threading.Event()
    observed = {}

    class Stream(service.handler(app)):
        def do_GET(self):
            if self.path != '/stream':
                return super().do_GET()
            start = time.monotonic()
            observed['written'] = 0
            try:
                self.send_response(200)
                self.send_header('Content-Length', str(16 * 1024**2))
                self.end_headers()
                chunk = b'x' * 65536
                for _ in range(256):
                    self.wfile.write(chunk)
                    observed['written'] += len(chunk)
            finally:
                observed['elapsed'] = time.monotonic() - start
                finished.set()

    with running(None, routes=Stream) as server:
        with closing(socket.socket()) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            client.settimeout(3)
            client.connect(('127.0.0.1', server.socket.getsockname()[1]))
            client.sendall(b'GET /stream HTTP/1.1\r\nHost: one.example.test\r\n\r\n')
            # No response reads: once the small TCP receive window fills,
            # streaming must stop waiting without requiring client closure.
            assert finished.wait(36)
            assert observed['written'] < 16 * 1024**2
            assert 28 <= observed['elapsed'] < 36
            assert server.timeout == 30
            with closing(HTTPConnection('127.0.0.1', server.socket.getsockname()[1], timeout=3)) as conn:
                conn.request('GET', '/catalog.json', headers={'Host': 'one.example.test'})
                response = conn.getresponse()
                assert response.status == 200
                response.read()


@pytest.mark.parametrize('underscore_first', [False, True])
def test_client_underscore_headers_cannot_replace_proxy_context(tmp_path, underscore_first):
    app, _ = system.__wrapped__(tmp_path)

    class Probe(service.handler(app)):
        def do_GET(self):
            self.respond(200, {'home': self.headers.get('X-Daimon-Home'),
                               'vpn': self.headers.get('X-Daimon-Vpn')})

    canonical = [('X-Daimon-Home', 'one'), ('X-Daimon-Vpn', '0')]
    forged = [('X_Daimon_Home', 'two'), ('X_Daimon_Vpn', '1')]
    with running(None, routes=Probe) as server:
        with closing(HTTPConnection('127.0.0.1', server.socket.getsockname()[1], timeout=3)) as conn:
            conn.putrequest('GET', '/', skip_host=True)
            conn.putheader('Host', 'one.example.test')
            for key, value in (forged + canonical if underscore_first else canonical + forged):
                conn.putheader(key, value)
            conn.endheaders()
            response = conn.getresponse()
            assert response.status == 200
            assert json.loads(response.read()) == {'home': 'one', 'vpn': '0'}
