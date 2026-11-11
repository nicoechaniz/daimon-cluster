import socket
import stat
import threading
from types import SimpleNamespace

import pytest

from clusterctl.homes import service_socket as transport


def test_socket_half_close_delivers_exact_envelope_and_finite_result(tmp_path, monkeypatch):
    path = tmp_path / 'fixed.sock'
    original = type(path).lstat
    monkeypatch.setattr(type(path), 'lstat', lambda p: SimpleNamespace(
        st_uid=0, st_mode=original(p).st_mode & ~0o022))
    received = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        path.chmod(0o660)
        server.listen(1)

        def worker():
            with server.accept()[0] as client:
                received.append(client.makefile('rb').read())
                client.sendall(b'{"state":"ready"}')

        thread = threading.Thread(target=worker)
        thread.start()
        assert transport.exchange(path, b'{"action":"observe"}', seconds=2) == b'{"state":"ready"}'
        thread.join(2)
        assert not thread.is_alive()
    assert received == [b'{"action":"observe"}']


def test_socket_rejects_untrusted_operator_directory_before_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(type(tmp_path), 'lstat', lambda _: SimpleNamespace(
        st_uid=0, st_mode=stat.S_IFDIR | 0o777))
    with pytest.raises(ValueError, match='service_socket_operator_required'):
        transport.exchange(tmp_path / 'fixed.sock', b'{}')


def test_socket_rejects_oversized_envelope_before_opening_path(tmp_path, monkeypatch):
    monkeypatch.setattr(transport, 'MAX_INPUT', 2)
    with pytest.raises(ValueError, match='service_socket_input_capacity'):
        transport.exchange(tmp_path / 'absent.sock', b'123')
