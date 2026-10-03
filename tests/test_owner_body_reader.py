"""Owner boundary exercised through real Unix sockets and native Cluster stores."""
from contextlib import closing
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import socket
import sqlite3
import struct
import tempfile
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from clusterctl.embodiments import Registry
from clusterctl.matrix_fencing.fences import Ed25519Signer, ResourceFenceStore
from clusterctl import owner_body_reader as body

ORIGIN = {
    "body_ref": "codex:fixture:compaii",
    "embodiment_id": "embodiment:11111111-1111-4111-8111-111111111111",
    "incarnation_id": "incarnation:22222222-2222-4222-8222-222222222222",
}
REQUEST = {"schema": body.REQUEST_SCHEMA, **ORIGIN, "evaluated_at_ms": 1000}


@pytest.fixture
def fixture():
    # Keep Linux AF_UNIX paths short; all private fixture custody is disposable.
    with tempfile.TemporaryDirectory(prefix="dm-body-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        state = root / "state"
        state.mkdir(mode=0o700)
        key = state / "fixture-key.pem"
        key.write_bytes(Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        key.chmod(0o600)
        signer = Ed25519Signer(key, "private-fixture")
        ResourceFenceStore(state, signer=signer, key_id=signer.key_id, clock=lambda: 1000)
        registry = Registry(state)
        registry.register(body_ref=ORIGIN["body_ref"], embodiment_id=ORIGIN["embodiment_id"])
        registry.start(ORIGIN["embodiment_id"], incarnation_id=ORIGIN["incarnation_id"], started_at_ms=900)
        profile = {
            "schema": body.PROFILE_SCHEMA, "socket_path": str(root / "reader.sock"),
            "socket_mode": "0600", "caller_uid": os.geteuid(), "origin": dict(ORIGIN),
        }
        yield root, state, registry, profile


def history(state):
    path = state / "resource-fences.sqlite3"
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        assert all(t.replace("_", "").isalnum() for t in tables)
        return {t: hashlib.sha256(repr(sorted(connection.execute("SELECT * FROM " + t).fetchall(), key=repr)).encode()).hexdigest() for t in tables}


def serve(state, profile):
    reader = body.OwnerBodyReader(state, profile)
    stop = threading.Event()
    thread = threading.Thread(target=reader.serve, args=(stop,))
    thread.start()
    return reader, stop, thread


def shutdown(reader, stop, thread):
    stop.set()
    thread.join(6)
    assert not thread.is_alive()
    reader.close()


def query(profile, value=REQUEST, raw=None, declared_size=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(profile["socket_path"])
        assert body.peer_uid(connection) == os.geteuid()
        if raw is not None or declared_size is not None:
            raw = raw or b""
            connection.sendall(struct.pack("!I", declared_size if declared_size is not None else len(raw)) + raw)
        else:
            body.send(connection, value)
        try:
            return body.receive(connection)
        except OSError:
            # An unauthorized peer can be closed before it sends its frame.
            return {"ok": False, "error": "cluster_body_read_refused"}


def test_real_socket_uses_native_authenticated_reader_without_writes(fixture):
    _, state, _, profile = fixture
    before = (state / "embodiments.json").read_bytes(), history(state)
    reader, stop, thread = serve(state, profile)
    try:
        response = query(profile)
        expected = reader.adapter.body_snapshot(**{k: v for k, v in REQUEST.items() if k != "schema"})
        assert response == {"ok": True, "snapshot": expected}
        assert ((state / "embodiments.json").read_bytes(), history(state)) == before
    finally:
        shutdown(reader, stop, thread)
    assert not Path(profile["socket_path"]).exists()


@pytest.mark.parametrize("change", [
    {"body_ref": "codex:other:compaii"}, {"incarnation_id": "incarnation:other"},
    {"embodiment_id": "embodiment:other"}, {"evaluated_at_ms": True},
    {"evaluated_at_ms": -1}, {"extra": "refused"},
])
def test_invalid_or_unlisted_request_refuses_before_callback(fixture, change):
    _, state, _, profile = fixture
    reader, stop, thread = serve(state, profile)
    calls = []
    reader.adapter.body_snapshot = lambda **kw: calls.append(kw)
    try:
        assert query(profile, dict(REQUEST, **change)) == {"ok": False, "error": "cluster_body_read_refused"}
        assert calls == []
    finally:
        shutdown(reader, stop, thread)


def test_real_peer_uid_refuses_wrong_caller_before_callback(fixture):
    _, state, _, profile = fixture
    profile["caller_uid"] = os.geteuid() + 1
    reader, stop, thread = serve(state, profile)
    calls = []
    reader.adapter.body_snapshot = lambda **kw: calls.append(kw)
    try:
        assert query(profile) == {"ok": False, "error": "cluster_body_read_refused"}
        assert calls == []
    finally:
        shutdown(reader, stop, thread)


@pytest.mark.parametrize("raw,size", [
    (b'{"schema":"x","schema":"x"}', None),
    (b"{}", body.MAX_BYTES + 1), (b"{}", 0), (b'{"value":NaN}', None),
])
def test_bounded_frames_refuse_before_callback(fixture, raw, size):
    _, state, _, profile = fixture
    reader, stop, thread = serve(state, profile)
    calls = []
    reader.adapter.body_snapshot = lambda **kw: calls.append(kw)
    try:
        assert query(profile, raw=raw, declared_size=size) == {"ok": False, "error": "cluster_body_read_refused"}
        assert calls == []
    finally:
        shutdown(reader, stop, thread)


def test_stopped_native_registry_refuses_without_state_change(fixture):
    _, state, registry, profile = fixture
    registry.stop(ORIGIN["embodiment_id"])
    before = (state / "embodiments.json").read_bytes(), history(state)
    reader, stop, thread = serve(state, profile)
    try:
        assert query(profile) == {"ok": False, "error": "cluster_body_read_refused"}
        assert ((state / "embodiments.json").read_bytes(), history(state)) == before
    finally:
        shutdown(reader, stop, thread)


@pytest.mark.parametrize("kind", ["file", "alias", "socket"])
def test_occupied_socket_path_never_removed(fixture, kind):
    root, state, _, profile = fixture
    path = Path(profile["socket_path"])
    occupied = None
    if kind == "alias":
        target = root / "keep"
        target.write_text("keep")
        path.symlink_to(target)
    elif kind == "socket":
        occupied = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        occupied.bind(str(path))
    else:
        path.write_text("keep")
    before = path.lstat()
    try:
        with pytest.raises(OSError):
            body.OwnerBodyReader(state, profile)
        after = path.lstat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    finally:
        if occupied:
            occupied.close()


def test_shutdown_preserves_replaced_path(fixture):
    _, state, _, profile = fixture
    reader = body.OwnerBodyReader(state, profile)
    path = Path(profile["socket_path"])
    path.unlink()
    path.write_text("replacement")
    reader.close()
    assert path.read_text() == "replacement"


def test_profile_is_validated_and_copied_before_socket_publication(fixture):
    root, state, _, profile = fixture
    path = root / "profile.json"
    path.write_text(json.dumps(profile))
    path.chmod(0o600)
    assert body.load_profile(path) == profile
    reader = body.OwnerBodyReader(state, profile)
    profile["origin"]["body_ref"] = "changed"
    assert reader.profile["origin"] == ORIGIN
    reader.close()
    path.chmod(0o660)
    with pytest.raises(body.ReaderError):
        body.load_profile(path)
    path.unlink()
    path.symlink_to(root / "unused")
    with pytest.raises((body.ReaderError, OSError)):
        body.load_profile(path)


def test_genuine_pinned_entrypoint_query_and_sigterm_cleanup(fixture):
    root, state, _, profile = fixture
    path = root / "profile.json"
    path.write_text(json.dumps(profile))
    path.chmod(0o600)
    process = subprocess.Popen(
        [sys.executable, "-m", "clusterctl.owner_body_reader", "--state-root", str(state), "--profile", str(path)],
        cwd=Path(__file__).resolve().parents[1], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"HOME": str(root), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1"},
    )
    try:
        deadline = time.monotonic() + 10
        while not Path(profile["socket_path"]).exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError("pinned reader did not start")
            time.sleep(0.02)
        assert query(profile)["ok"] is True
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0 and stdout == b"" and stderr == b""
        assert not Path(profile["socket_path"]).exists()
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


def test_uncontrolled_ancestor_refuses_profile_and_socket(fixture):
    root, state, _, profile = fixture
    path = root / "profile.json"
    path.write_text(json.dumps(profile))
    path.chmod(0o600)
    root.chmod(0o770)
    try:
        with pytest.raises(body.ReaderError):
            body.load_profile(path)
        with pytest.raises(body.ReaderError):
            body.OwnerBodyReader(state, profile)
        assert not Path(profile["socket_path"]).exists()
    finally:
        root.chmod(0o700)
