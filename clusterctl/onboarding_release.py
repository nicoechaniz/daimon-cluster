"""Content-addressed receiving code and consciously selected transferable context."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from . import being_seed
from .onboarding import OnboardingError, digest
from .onboarding_input import MAX_MANIFEST, relative

SCHEMA = "cluster-onboarding-code/v1"
PROFILE = "cluster-onboarding-context-profile/v1"


def regular(path: Path, *, uid: int, limit: int = 32 * 1024**2) -> bytes:
    being_seed._path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_mode & 0o022 or info.st_size > limit):
            raise OnboardingError("trusted_receiving_code_required")
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise OnboardingError("trusted_receiving_code_required")
        return raw


def profile(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {
        "schema", "model", "reasoning", "approval", "sandbox", "skills", "primary_store",
    } or value.get("schema") != PROFILE
            or not isinstance(value["model"], str) or not 1 <= len(value["model"]) <= 100
            or value["reasoning"] not in {"low", "medium", "high", "xhigh"}
            or value["approval"] not in {"never", "on-request"}
            or value["sandbox"] not in {"read-only", "workspace-write", "danger-full-access"}
            or not isinstance(value["skills"], list) or len(value["skills"]) > 50
            or any(not isinstance(name, str) or not being_seed.NAME.fullmatch(name) for name in value["skills"])
            or len(set(value["skills"])) != len(value["skills"])
            or value["primary_store"] is not None and (
                not isinstance(value["primary_store"], str) or not being_seed.NAME.fullmatch(value["primary_store"]))):
        raise OnboardingError("invalid_receiving_context_profile")
    return value


def inventory(root: Path, *, uid: int) -> list[dict]:
    being_seed._path(root)
    info = root.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise OnboardingError("trusted_receiving_code_required")
    rows = []
    for path in sorted(root.rglob("*")):
        being_seed._path(path)
        info = path.stat()
        if info.st_uid != uid or info.st_mode & 0o022:
            raise OnboardingError("trusted_receiving_code_required")
        if path.is_dir():
            continue
        name = relative(path.relative_to(root).as_posix())
        if name == "release.json":
            continue
        raw = regular(path, uid=uid)
        rows.append(dict(path=name, sha256=hashlib.sha256(raw).hexdigest()))
        if len(rows) > 10000:
            raise OnboardingError("receiving_code_too_large")
    return rows


def seal(root: Path, selected_profile: dict) -> str:
    if (root / "release.json").exists():
        raise OnboardingError("receiving_release_already_sealed")
    value = dict(schema=SCHEMA, profile=profile(selected_profile), files=inventory(root, uid=os.geteuid()))
    raw = json.dumps(value, sort_keys=True).encode()
    if len(raw) > MAX_MANIFEST:
        raise OnboardingError("receiving_code_too_large")
    descriptor = os.open(root / "release.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return digest(value)


def verify(root: Path, expected: str, *, uid: int) -> dict:
    value = json.loads(regular(root / "release.json", uid=uid, limit=MAX_MANIFEST))
    if (not isinstance(value, dict) or set(value) != {"schema", "profile", "files"}
            or value["schema"] != SCHEMA or digest(value) != expected
            or value["files"] != inventory(root, uid=uid)):
        raise OnboardingError("receiving_release_digest_mismatch")
    profile(value["profile"])
    paths = {row["path"] for row in value["files"]}
    required = {"inheritance.md", "hmk/scripts/memoryctl.py", "hmk/scripts/native_records.py"}
    required.update("skills/" + name + "/SKILL.md" for name in value["profile"]["skills"])
    # Qualified older contexts retain their captured ordinary archive tools.
    # The current host's tool table must not invalidate their frozen digest.
    required.update("support/being-seed-tools/tools/" + name for name in (
        "export_being.py", "receive_being.py", "install_codex_identity.py"))
    if "clusterctl/onboarding_transfer.py" in paths:
        required.add("support/being-seed-tools/tools/protected_being.py")
    if not required <= paths:
        raise OnboardingError("receiving_release_incomplete")
    return value
