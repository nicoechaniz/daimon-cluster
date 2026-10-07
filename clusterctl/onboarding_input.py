"""Freeze already-prepared receiving context without changing the intake/source.

The digest covers the entire preserved input, not just the archive or its label.
It contains no bot/account credential; those use separate host-owned profiles.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory

SCHEMA = "cluster-onboarding-input/v1"
MAX_BYTES = 15 * 1024**3
MAX_FILES = 50000
MAX_MANIFEST = 16 * 1024**2


def relative(value: object) -> str:
    if not isinstance(value, str):
        raise OnboardingError("invalid_onboarding_input")
    path = PurePosixPath(value)
    if (path.is_absolute() or not path.parts or any(part in {".", ".."} for part in value.split("/"))
            or path.as_posix() != value or "\x00" in value or "\\" in value):
        raise OnboardingError("invalid_onboarding_input")
    return value


def owned_digest(path: Path, *, uid: int, copy: Path | None = None) -> tuple[str, int]:
    being_seed._path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    checksum = hashlib.sha256()
    size = 0
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid
                or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > MAX_BYTES):
            raise OnboardingError("private_onboarding_input_required")
        output = None
        try:
            if copy:
                copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                output = os.fdopen(os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
            while chunk := source.read(1024 * 1024):
                checksum.update(chunk)
                size += len(chunk)
                if size > MAX_BYTES:
                    raise OnboardingError("onboarding_input_too_large")
                if output:
                    output.write(chunk)
            after = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise OnboardingError("onboarding_input_changed")
            if output:
                output.flush()
                os.fsync(output.fileno())
        finally:
            if output:
                output.close()
    return checksum.hexdigest(), size


def inventory(root: Path, *, uid: int) -> list[dict]:
    being_seed._path(root)
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise OnboardingError("private_onboarding_input_required")
    rows, total = [], 0
    for path in sorted(root.rglob("*")):
        being_seed._path(path)
        if path.is_dir():
            info = path.stat()
            if info.st_uid != uid or info.st_mode & 0o077:
                raise OnboardingError("private_onboarding_input_required")
            continue
        checksum, size = owned_digest(path, uid=uid)
        rows.append(dict(path=relative(path.relative_to(root).as_posix()), sha256=checksum, size=size))
        total += size
        if total > MAX_BYTES or len(rows) > MAX_FILES:
            raise OnboardingError("onboarding_input_too_large")
    return rows


def capture(received: Path, destination: Path, *, source_uid: int) -> dict:
    """Preserve partial captures on failure. Only a final marker makes one usable."""
    before = inventory(received, uid=source_uid)
    if destination.exists() or destination.is_symlink():
        raise OnboardingError("onboarding_input_destination_exists")
    private_directory(destination.parent)
    destination.mkdir(mode=0o700)
    target = destination / "received"
    target.mkdir(mode=0o700)
    for directory in sorted(path for path in received.rglob("*") if path.is_dir()):
        (target / directory.relative_to(received)).mkdir(mode=0o700)
    for row in before:
        checksum, size = owned_digest(received / row["path"], uid=source_uid, copy=target / row["path"])
        if (checksum, size) != (row["sha256"], row["size"]):
            raise OnboardingError("onboarding_input_changed")
    if inventory(received, uid=source_uid) != before:
        raise OnboardingError("onboarding_input_changed")
    report = being_seed._read(target / "preparation.json")
    if (report.get("schema") != "dm.being-receiving-preparation/v1"
            or report.get("ready_for_context_install") is not True):
        raise OnboardingError("prepared_onboarding_input_required")
    # The frozen original archive is checked using the maintained verifier.
    being_seed.tool("export_being", ["verify", "--archive", str(target / "source.archive"),
                                      "--sha256", report["archive_sha256"]])
    value = dict(schema=SCHEMA, files=before, archive_sha256=report["archive_sha256"])
    raw = json.dumps(value, sort_keys=True).encode()
    if len(raw) > MAX_MANIFEST:
        raise OnboardingError("onboarding_input_too_large")
    descriptor = os.open(destination / "manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"seed_digest": digest(value), "files": len(before)}


def verify(root: Path, expected: str) -> dict:
    private_directory(root)
    manifest_path = being_seed._path(root / "manifest.json")
    descriptor = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_MANIFEST):
            raise OnboardingError("private_onboarding_input_required")
        manifest = json.load(stream)
    if (set(manifest) != {"schema", "files", "archive_sha256"} or manifest.get("schema") != SCHEMA
            or digest(manifest) != expected or not isinstance(manifest["files"], list)
            or inventory(root / "received", uid=os.geteuid()) != manifest["files"]):
        raise OnboardingError("onboarding_input_digest_mismatch")
    return manifest
