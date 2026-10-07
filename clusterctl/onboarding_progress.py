"""Closed worker-owned read model; intake access never grants host execution."""
from __future__ import annotations

import json
import os
import re
import stat
import uuid
from pathlib import Path

from . import being_seed
from .onboarding import REASONS, SCHEMA, STAGES, STATES, OnboardingError


def validate(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema", "name", "owner", "plan_digest", "state", "stage", "reason",
        "completed_steps", "active", "updated_ms",
    }:
        raise OnboardingError("invalid_onboarding_progress")
    if (value["schema"] != SCHEMA
            or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                   for key in ("name", "owner"))
            or not isinstance(value["plan_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["plan_digest"])
            or not isinstance(value["state"], str) or value["state"] not in STATES
            or value["reason"] is not None and (not isinstance(value["reason"], str) or value["reason"] not in REASONS)
            or type(value["updated_ms"]) is not int or value["updated_ms"] < 0
            or type(value["active"]) is not bool
            or not isinstance(value["completed_steps"], list)):
        raise OnboardingError("invalid_onboarding_progress")
    count = len(value["completed_steps"])
    if value["completed_steps"] != list(STAGES[:count]) or count > len(STAGES):
        raise OnboardingError("invalid_onboarding_progress")
    complete = count == len(STAGES)
    if (value["active"] != complete or (value["state"] == "complete") != complete
            or value["stage"] != (None if complete else STAGES[count])):
        raise OnboardingError("invalid_onboarding_progress")
    return value


class Progress:
    suffix = ".json"
    validate = staticmethod(validate)

    def __init__(self, root: str | Path, *, worker_uid: int = 0):
        self.root = being_seed._path(Path(root))
        self.worker_uid = worker_uid

    def _directory(self) -> None:
        info = self.root.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.worker_uid
                or info.st_mode & 0o027):
            raise OnboardingError("trusted_onboarding_progress_required")

    def _file(self, name: str) -> Path:
        if not isinstance(name, str) or not being_seed.NAME.fullmatch(name):
            raise OnboardingError("invalid_onboarding_name")
        return being_seed._path(self.root / (name + self.suffix))

    def read(self, name: str, *, owner: str) -> dict:
        self._directory()
        path = self._file(name)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.worker_uid
                    or info.st_nlink != 1 or info.st_mode & 0o037 or info.st_size > 65536):
                raise OnboardingError("trusted_onboarding_progress_required")
            value = self.validate(json.load(stream))
        if value["name"] != name or owner != "*" and value["owner"] != owner:
            raise OnboardingError("onboarding_job_not_found")
        return value

    def publish(self, value: dict) -> None:
        value = self.validate(value)
        self._directory()
        if os.geteuid() != self.worker_uid:
            raise OnboardingError("trusted_onboarding_progress_required")
        path = self._file(value["name"])
        temporary = path.with_name("." + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                # Retain the read-only portal group from the trusted directory.
                os.fchown(stream.fileno(), self.worker_uid, self.root.stat().st_gid)
                os.fchmod(stream.fileno(), 0o640)
                stream.write(json.dumps(value, sort_keys=True).encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)
