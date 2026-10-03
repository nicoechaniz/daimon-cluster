"""Opt-in Cluster-owned, read-only body observations over authenticated local IPC."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import threading
import time
from typing import Any

from daimon_matrix.cluster import validate_body_snapshot

from .matrix_host import MatrixHostAdapter, _matrix_api

PROFILE_SCHEMA = "dm.cluster-owner-body-reader-profile/v1"
REQUEST_SCHEMA = "dm.cluster-owner-body-read/v1"
MAX_BYTES = 65536
TIMEOUT_SECONDS = 5


class ReaderError(ValueError):
    """Disclosure-safe refusal at the local metadata boundary."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ReaderError("body_reader_json_rejected")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReaderError("body_reader_json_rejected")


def _decode(raw: bytes) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (UnicodeError, ValueError) as error:
        raise ReaderError("body_reader_json_rejected") from error


def _uid(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise ReaderError("body_reader_uid_rejected")
    return value


def _origin(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "body_ref", "embodiment_id", "incarnation_id"
    }:
        raise ReaderError("body_reader_origin_rejected")
    if any(not isinstance(v, str) or not 0 < len(v.encode()) <= 256 for v in value.values()):
        raise ReaderError("body_reader_origin_rejected")
    return dict(value)


def _path(value: Any) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ReaderError("body_reader_path_rejected")
    if any(part in (".", "..") for part in value.split("/")):
        raise ReaderError("body_reader_path_rejected")
    result = Path(value)
    for parent in result.parents:
        info = parent.lstat()
        root_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, os.geteuid()}
            or (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not root_sticky)
        ):
            raise ReaderError("body_reader_path_rejected")
    return result


def load_profile(path: Path) -> dict[str, Any]:
    """Consume only an existing, owner-controlled public selector profile."""
    path = _path(str(path))
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid not in {0, os.geteuid()}
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ReaderError("body_reader_profile_rejected")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid not in {0, os.geteuid()}
            or after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ReaderError("body_reader_profile_rejected")
        if not 0 < after.st_size <= MAX_BYTES:
            raise ReaderError("body_reader_profile_rejected")
        raw = os.read(descriptor, MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    return validate_profile(_decode(raw))


def validate_profile(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "socket_path", "socket_mode", "caller_uid", "origin"
    } or value["schema"] != PROFILE_SCHEMA:
        raise ReaderError("body_reader_profile_rejected")
    _uid(value["caller_uid"])
    _origin(value["origin"])
    _path(value["socket_path"])
    if not isinstance(value["socket_mode"], str) or value["socket_mode"] not in {"0600", "0666"}:
        raise ReaderError("body_reader_profile_rejected")
    return dict(value, origin=_origin(value["origin"]))


def peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ReaderError("body_reader_peer_credentials_unavailable")
    return struct.unpack("3I", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


def _exact(connection: socket.socket, length: int, deadline: float | None = None) -> bytes:
    chunks = []
    while length:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReaderError("body_reader_deadline_rejected")
            connection.settimeout(remaining)
        chunk = connection.recv(length)
        if not chunk:
            raise ReaderError("body_reader_incomplete")
        chunks.append(chunk)
        length -= len(chunk)
    return b"".join(chunks)


def receive(connection: socket.socket, *, deadline: float | None = None) -> Any:
    size = struct.unpack("!I", _exact(connection, 4, deadline))[0]
    if not 0 < size <= MAX_BYTES:
        raise ReaderError("body_reader_size_rejected")
    return _decode(_exact(connection, size, deadline))


def send(connection: socket.socket, value: Any) -> None:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if not 0 < len(raw) <= MAX_BYTES:
        raise ReaderError("body_reader_size_rejected")
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def handle(connection: socket.socket, profile: dict[str, Any], reader: Any) -> None:
    connection.settimeout(TIMEOUT_SECONDS)
    try:
        if peer_uid(connection) != profile["caller_uid"]:
            raise ReaderError("body_reader_caller_rejected")
        request = receive(connection, deadline=time.monotonic() + TIMEOUT_SECONDS)
        if not isinstance(request, dict) or set(request) != {
            "schema", "body_ref", "embodiment_id", "incarnation_id", "evaluated_at_ms"
        } or request["schema"] != REQUEST_SCHEMA:
            raise ReaderError("body_reader_request_rejected")
        origin = _origin({key: request[key] for key in profile["origin"]})
        if origin != profile["origin"]:
            raise ReaderError("body_reader_origin_rejected")
        instant = request["evaluated_at_ms"]
        if isinstance(instant, bool) or not isinstance(instant, int) or not 0 <= instant < 2**63:
            raise ReaderError("body_reader_request_rejected")
        arguments = dict(origin, evaluated_at_ms=instant)
        observation = reader(**arguments)
        validate_body_snapshot(observation, **arguments)
        connection.settimeout(TIMEOUT_SECONDS)
        send(connection, {"ok": True, "snapshot": observation})
    except Exception:
        try:
            connection.settimeout(TIMEOUT_SECONDS)
            send(connection, {"ok": False, "error": "cluster_body_read_refused"})
        except (OSError, ValueError):
            pass
    finally:
        connection.close()


class OwnerBodyReader:
    """A passive query process: registers, starts and signs nothing."""

    def __init__(self, state_root: Path, profile: dict[str, Any]):
        # Always select the native authenticated verifier, never a fixture store.
        self.profile = validate_profile(profile)
        state_root = _path(str(state_root))
        self.adapter = MatrixHostAdapter(state_root, self.profile["origin"]["embodiment_id"])
        self.path = _path(self.profile["socket_path"])
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid not in {0, os.geteuid()}
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ReaderError("body_reader_socket_parent_rejected")
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.identity: tuple[int, int] | None = None
        try:
            # bind never removes an existing artifact, including stale sockets.
            self.socket.bind(str(self.path))
            info = self.path.lstat()
            self.identity = (info.st_dev, info.st_ino)
            self.path.chmod(int(self.profile["socket_mode"], 8))
            self.socket.listen(8)
            self.socket.settimeout(0.5)
        except BaseException:
            self.close()
            raise

    def serve(self, stop: threading.Event) -> None:
        try:
            while not stop.is_set():
                try:
                    connection, _ = self.socket.accept()
                except socket.timeout:
                    continue
                handle(connection, self.profile, self.adapter.body_snapshot)
        finally:
            self.close()

    def close(self) -> None:
        self.socket.close()
        if self.identity is not None:
            try:
                info = self.path.lstat()
            except FileNotFoundError:
                return
            if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self.identity:
                self.path.unlink()
            self.identity = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    args = parser.parse_args(argv)
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda _signum, _frame: stop.set())
    try:
        profile = load_profile(args.profile)
        _matrix_api()  # Retain the installed host's genuine dependency admission.
        reader = OwnerBodyReader(args.state_root, profile)
        reader.serve(stop)
        return 0
    except Exception:
        print('{"schema":"dm.cluster-owner-body-reader-diagnostic/v1","code":"body_reader_refused"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
