"""Bounded client for one operator-selected systemd Accept=yes Unix socket.

The root-owned socket unit fixes the entire executor command and configuration;
stdin remains the closed existing deployment envelope, never an executable argv.
This transport works from the Home gateway with NoNewPrivileges retained.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import socket
import stat
import sys

MAX_INPUT = 32 * 1024**2 * 2 + 65536
MAX_OUTPUT = 16384


def exchange(path: Path, raw: bytes, *, seconds=185):
    if len(raw) > MAX_INPUT or not path.is_absolute():
        raise ValueError('service_socket_input_capacity')
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('service_socket_operator_required')
    info = path.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o007):
        raise ValueError('service_socket_operator_required')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(seconds)
        channel.connect(str(path))
        channel.sendall(raw)
        channel.shutdown(socket.SHUT_WR)
        result = bytearray()
        while True:
            chunk = channel.recv(min(4096, MAX_OUTPUT + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > MAX_OUTPUT:
                raise ValueError('service_socket_output_capacity')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        result = exchange(args.socket, raw)
        sys.stdout.buffer.write(result)
    except (OSError, ValueError):
        # No replay: the socket may already have dispatched its fixed worker.
        print('{"state":"unconfirmed"}')
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
