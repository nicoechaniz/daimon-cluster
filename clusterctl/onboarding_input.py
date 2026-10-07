"""Freeze already-prepared receiving context without changing the intake/source.

The digest covers the entire preserved input, not just the archive or its label.
It contains no bot/account credential; those use separate host-owned profiles.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
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


def capture(received: Path, destination: Path, *, source_uid: int, resume: bool = False) -> dict:
    """Freeze immutable prepared bytes; optional recovery never replaces files."""
    before = inventory(received, uid=source_uid)
    report_raw = (received / "preparation.json").read_bytes()
    report = json.loads(report_raw)
    if (report.get("schema") != "dm.being-receiving-preparation/v1"
            or report.get("ready_for_context_install") is not True):
        raise OnboardingError("prepared_onboarding_input_required")
    value = dict(schema=SCHEMA, files=before, archive_sha256=report["archive_sha256"])
    raw = json.dumps(value, sort_keys=True).encode()
    if len(raw) > MAX_MANIFEST:
        raise OnboardingError("onboarding_input_too_large")
    if destination.exists() or destination.is_symlink():
        if not resume:
            raise OnboardingError("onboarding_input_destination_exists")
        private_directory(destination)
    else:
        private_directory(destination.parent)
        destination.mkdir(mode=0o700)
    from .onboarding_guest import new_bytes
    from .matrix_host import _publish_directory_noreplace
    with being_seed._locked(destination):
        intent = destination / 'capture-intent.json'
        # A crash before this publication cannot have copied any input.
        if not intent.exists() and any(p.name != 'lock' for p in destination.iterdir()):
            raise OnboardingError('existing_onboarding_input_preserved')
        new_bytes(intent, raw)
        target = destination / 'received'
        private_directory(target, create=True)
        staging = destination / '.capture-staging'
        private_directory(staging, create=True)
        for directory in sorted(path for path in received.rglob('*') if path.is_dir()):
            private_directory(target / directory.relative_to(received), create=True)
        for row in before:
            copied = target / row['path']
            if copied.exists():
                if owned_digest(copied, uid=os.geteuid()) != (row['sha256'], row['size']):
                    raise OnboardingError('existing_onboarding_input_preserved')
                continue
            temporary = staging / uuid.uuid4().hex
            checksum, size = owned_digest(received / row['path'], uid=source_uid, copy=temporary)
            if (checksum, size) != (row['sha256'], row['size']):
                raise OnboardingError('onboarding_input_changed')
            descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _publish_directory_noreplace(descriptor, str(temporary.relative_to(destination)),
                    str(copied.relative_to(destination)), exists_code='existing_onboarding_input_preserved')
                parent = os.open(copied.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            finally:
                os.close(descriptor)
        if inventory(received, uid=source_uid) != before or inventory(target, uid=os.geteuid()) != before:
            raise OnboardingError('onboarding_input_changed')
        being_seed.tool('export_being', ['verify', '--archive', str(target / 'source.archive'),
                                       '--sha256', report['archive_sha256']])
        new_bytes(destination / 'manifest.json', raw)
        descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return dict(seed_digest=digest(value), files=len(before))


def verify(root: Path, expected: str, *, uid: int | None = None) -> dict:
    uid = os.geteuid() if uid is None else uid
    being_seed._path(root)
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise OnboardingError("private_onboarding_input_required")
    manifest_path = being_seed._path(root / "manifest.json")
    descriptor = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_MANIFEST):
            raise OnboardingError("private_onboarding_input_required")
        manifest = json.load(stream)
    if (set(manifest) != {"schema", "files", "archive_sha256"} or manifest.get("schema") != SCHEMA
            or digest(manifest) != expected or not isinstance(manifest["files"], list)
            or inventory(root / "received", uid=uid) != manifest["files"]):
        raise OnboardingError("onboarding_input_digest_mismatch")
    return manifest
