#!/usr/bin/env python3
"""Finite owner-invoked upload; resume the longest verified private partial."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import socket
import stat
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


class UploadError(ValueError):
    pass


def private_token(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > 4096):
            raise UploadError("existing_private_token_file_required")
        return stream.read(4097).decode().strip()


def ipv4_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None,
                    **kwargs):
    last = None
    for family, kind, protocol, _, target in socket.getaddrinfo(
            address[0], address[1], socket.AF_INET, socket.SOCK_STREAM):
        connection = socket.socket(family, kind, protocol)
        try:
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                connection.settimeout(timeout)
            if source_address:
                connection.bind(source_address)
            connection.connect(target)
            return connection
        except OSError as error:
            last = error
            connection.close()
    raise last or OSError("ipv4_destination_unavailable")


def response(connection: http.client.HTTPConnection) -> dict:
    reply = connection.getresponse()
    raw = reply.read(65537)
    if len(raw) > 65536:
        raise UploadError("bounded_upload_response_required")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise UploadError("upload_response_invalid") from error
    if not isinstance(value, dict):
        raise UploadError("upload_response_invalid")
    if reply.status != 200:
        code = value.get("error", "upload_request_refused")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,100}", code):
            code = "upload_request_refused"
        raise UploadError(f"HTTP {reply.status}: {code}")
    return value


def upload(url: str, seed: str, archive: Path, sha256: str, token: str, *,
           timeout: int = 14400) -> dict:
    origin = urlsplit(url)
    if (origin.scheme != "https" or not origin.hostname or origin.username
            or origin.password or origin.path not in {"", "/"}
            or origin.query or origin.fragment or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", seed)
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            or not token or any(c.isspace() for c in token)
            or not 1 <= timeout <= 86400):
        raise UploadError("valid_https_origin_seed_checksum_and_private_access_required")
    deadline = time.monotonic() + timeout
    path = "/v1/seeds/" + seed + "/archive"
    headers = {"Authorization": "Bearer " + token}
    connection = http.client.HTTPSConnection(origin.hostname, origin.port, timeout=min(60, timeout))
    try:
        connection.request("GET", path, headers=headers)
        progress = response(connection)
    finally:
        connection.close()
    if set(progress) != {"complete", "offset", "size", "sha256", "prefix_sha256"}:
        raise UploadError("upload_progress_invalid")
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        size, offset = info.st_size, progress["offset"]
        if (not stat.S_ISREG(info.st_mode) or not 0 < size <= 2 * 1024**3
                or type(offset) is not int or not 0 <= offset <= size
                or type(progress["complete"]) is not bool
                or progress["size"] is not None and progress["size"] != size
                or progress["sha256"] is not None and progress["sha256"] != sha256):
            raise UploadError("resume_requires_same_original_archive")
        digest = hashlib.sha256()
        remaining = offset
        while remaining:
            if time.monotonic() >= deadline:
                raise UploadError("upload_total_timeout")
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise UploadError("original_archive_changed")
            digest.update(chunk)
            remaining -= len(chunk)
        prefix = digest.hexdigest()
        if prefix != progress["prefix_sha256"]:
            raise UploadError("original_archive_prefix_disagrees_no_bytes_sent")
        if progress["complete"]:
            if offset != size or prefix != sha256:
                raise UploadError("upload_progress_invalid")
            print("Archive already verified; continue to selection.", flush=True)
            return progress
        print(f"Continuing from {offset} of {size} bytes ({offset/size:.1%}).", flush=True)
        headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(size-offset),
                        "X-Archive-SHA256": sha256, "X-Archive-Offset": str(offset),
                        "X-Archive-Size": str(size), "X-Archive-Prefix-SHA256": prefix})
        connection = http.client.HTTPSConnection(origin.hostname, origin.port, timeout=min(60, timeout))
        try:
            connection.putrequest("POST", path)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            sent, report_at = offset, time.monotonic()
            while chunk := stream.read(min(size-sent, 1024 * 1024)):
                left = deadline-time.monotonic()
                if left <= 0:
                    raise UploadError("upload_total_timeout")
                if connection.sock is not None:
                    connection.sock.settimeout(min(60, left))
                connection.send(chunk)
                sent += len(chunk)
                if time.monotonic()-report_at >= 15:
                    print(f"Sent {sent} of {size} bytes ({sent/size:.1%}).", flush=True)
                    report_at = time.monotonic()
            if sent != size:
                raise UploadError("original_archive_changed")
            left = deadline-time.monotonic()
            if left <= 0:
                raise UploadError("upload_total_timeout")
            if connection.sock is not None:
                connection.sock.settimeout(min(60, left))
            value = response(connection)
        finally:
            connection.close()
    if value.get("phase") not in {"uploaded", "prepared"} or value.get("archive_sha256") != sha256:
        raise UploadError("upload_verification_not_observed")
    print("Complete archive checksum verified; continue to selection.", flush=True)
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("url", "seed", "archive", "sha256"):
        parser.add_argument("--" + name, required=True)
    access = parser.add_mutually_exclusive_group(required=True)
    access.add_argument("--token-file", type=Path)
    access.add_argument("--token-fd", type=int)
    parser.add_argument("--timeout", type=int, default=14400)
    parser.add_argument("--ipv4", action="store_true")
    args = parser.parse_args(argv)
    original_connection = socket.create_connection
    try:
        if args.ipv4:
            socket.create_connection = ipv4_connection
        token = (private_token(args.token_file) if args.token_file else
                 os.read(args.token_fd, 4097).decode().strip())
        if len(token) > 4096:
            raise UploadError("bounded_private_access_required")
        upload(args.url, args.seed, Path(args.archive), args.sha256, token, timeout=args.timeout)
        return 0
    except (OSError, http.client.HTTPException, UnicodeError, ValueError) as error:
        message = str(error) if isinstance(error, UploadError) else "upload_connection_interrupted"
        print(message + ". Received bytes stay preserved; rerun the same command to resume.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Stopped. Received bytes stay preserved; rerun the same command to resume.", file=sys.stderr)
        return 130
    finally:
        socket.create_connection = original_connection


if __name__ == "__main__":
    raise SystemExit(main())
