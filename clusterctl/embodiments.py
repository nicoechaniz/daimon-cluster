"""Cluster-owned body, embodiment, and incarnation registry."""

from __future__ import annotations

import copy
import contextlib
import fcntl
import functools
import json
import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

REGISTRY_SCHEMA = "embodiment-registry/v1"
MUTATION_LOCK_TIMEOUT_SECONDS = 5


class RegistryError(RuntimeError):
    pass


def new_id(kind: str) -> str:
    return f"{kind}:{uuid.uuid4()}"


def _serialized(method):
    @functools.wraps(method)
    def mutate(self, *args, **kwargs):
        with self._mutation_lock():
            return method(self, *args, **kwargs)
    return mutate


class Registry:
    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "embodiments.json"

    @contextlib.contextmanager
    def _mutation_lock(self):
        """Serialize all bodies' load/modify/replace operations, including threads.

        Keep the inode in place: unlinking a flock file lets another caller lock
        a different inode. Kernel locks disappear when a process exits; elapsed
        time never grants permission to break a live holder's lock.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
        ):
            raise RegistryError("embodiment registry parent is unsafe")
        self.path.parent.chmod(0o700)
        lock_path = self.path.parent / "embodiments.lock"
        try:
            descriptor = os.open(
                lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
            )
        except OSError as exc:
            raise RegistryError("cannot open embodiment registry lock") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_nlink != 1
            ):
                raise RegistryError("embodiment registry lock is unsafe")
            deadline = time.monotonic() + MUTATION_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RegistryError("embodiment registry mutation is busy")
                    time.sleep(0.01)
            linked = lock_path.lstat()
            if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                raise RegistryError("embodiment registry lock changed")
            yield
        finally:
            os.close(descriptor)

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"schema": REGISTRY_SCHEMA, "embodiments": {}}
        info = self.path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RegistryError("embodiment registry is not owner-only")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError("cannot read embodiment registry") from exc
        if (
            not isinstance(value, dict)
            or value.get("schema") != REGISTRY_SCHEMA
            or not isinstance(value.get("embodiments"), dict)
        ):
            raise RegistryError("invalid embodiment registry")
        return copy.deepcopy(value)

    def _save(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent = self.path.parent.lstat()
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
        ):
            raise RegistryError("embodiment registry parent is unsafe")
        self.path.parent.chmod(0o700)
        if self.path.is_symlink():
            raise RegistryError("embodiment registry symlink is forbidden")
        temporary = self.path.with_suffix(".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
            written = 0
            while written < len(raw):
                written += os.write(descriptor, raw[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path)
        directory = os.open(
            self.path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @_serialized
    def register(
        self, *, body_ref: str, embodiment_id: str | None = None
    ) -> dict[str, Any]:
        state = self.load()
        for record in state["embodiments"].values():
            if record["body_ref"] == body_ref and record["status"] != "retired":
                raise RegistryError(f"body already registered: {body_ref}")
        now = int(time.time() * 1000)
        identifier = embodiment_id or new_id("embodiment")
        if identifier in state["embodiments"]:
            raise RegistryError("embodiment already registered")
        record = {
            "embodiment_id": identifier,
            "body_ref": body_ref,
            "status": "stopped",
            "created_at_ms": now,
            "current_incarnation_id": None,
            "incarnations": [],
        }
        state["embodiments"][identifier] = record
        self._save(state)
        return dict(record)

    @_serialized
    def adopt_running(
        self, *, body_ref: str, embodiment_id: str, incarnation_id: str
    ) -> dict[str, Any]:
        """Enroll an explicitly admitted existing process without minting IDs.

        The caller supplies physical admission; this atomic registry operation
        grants neither Matrix identity nor a resource fence. Exact active replay
        preserves history; an ended incarnation can never be reopened.
        """
        if (
            not isinstance(body_ref, str) or not body_ref
            or not isinstance(embodiment_id, str)
            or not embodiment_id.startswith("embodiment:")
            or not isinstance(incarnation_id, str)
            or not incarnation_id.startswith("incarnation:")
        ):
            raise RegistryError("invalid existing owner origin")
        state = self.load()
        current = state["embodiments"].get(embodiment_id)
        if current is not None:
            if (
                current.get("body_ref") == body_ref
                and current.get("hosting") == "external-owner"
                and current.get("status") == "running"
                and current.get("current_incarnation_id") == incarnation_id
                and sum(
                    item.get("incarnation_id") == incarnation_id
                    and item.get("stopped_at_ms") is None
                    for item in current.get("incarnations", [])
                ) == 1
            ):
                return copy.deepcopy(current)
            raise RegistryError("existing owner origin conflicts with registry")
        for record in state["embodiments"].values():
            if record.get("body_ref") == body_ref:
                raise RegistryError("existing owner body already registered")
            if any(
                item.get("incarnation_id") == incarnation_id
                for item in record.get("incarnations", [])
            ):
                raise RegistryError("incarnation already registered")
        now = int(time.time() * 1000)
        record = {
            "embodiment_id": embodiment_id,
            "body_ref": body_ref,
            "hosting": "external-owner",
            "status": "running",
            "created_at_ms": now,
            "current_incarnation_id": incarnation_id,
            "incarnations": [{
                "incarnation_id": incarnation_id,
                "started_at_ms": now,
                "stopped_at_ms": None,
            }],
        }
        state["embodiments"][embodiment_id] = record
        self._save(state)
        return copy.deepcopy(record)

    @_serialized
    def start(
        self,
        embodiment_id: str,
        *,
        incarnation_id: str | None = None,
        started_at_ms: int | None = None,
    ) -> dict[str, Any]:
        state = self.load()
        try:
            record = state["embodiments"][embodiment_id]
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc
        if record["status"] == "retired":
            raise RegistryError("cannot start retired embodiment")
        if record["status"] == "running":
            raise RegistryError("embodiment already running")
        identifier = incarnation_id or new_id("incarnation")
        if not isinstance(identifier, str) or not identifier.startswith("incarnation:"):
            raise RegistryError("invalid incarnation id")
        if any(
            item.get("incarnation_id") == identifier
            for candidate in state["embodiments"].values()
            for item in candidate.get("incarnations", [])
        ):
            raise RegistryError("incarnation already registered")
        started = int(time.time() * 1000) if started_at_ms is None else started_at_ms
        if isinstance(started, bool) or not isinstance(started, int) or started < 0:
            raise RegistryError("invalid incarnation start time")
        incarnation = {
            "incarnation_id": identifier,
            "started_at_ms": started,
            "stopped_at_ms": None,
        }
        record["incarnations"].append(incarnation)
        record["current_incarnation_id"] = identifier
        record["status"] = "running"
        self._save(state)
        return copy.deepcopy(incarnation)

    @_serialized
    def stop(self, embodiment_id: str) -> dict[str, Any]:
        state = self.load()
        try:
            record = state["embodiments"][embodiment_id]
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc
        if record["status"] == "retired":
            raise RegistryError("cannot stop retired embodiment")
        current = record.get("current_incarnation_id")
        if current is not None:
            for incarnation in record["incarnations"]:
                if (
                    incarnation["incarnation_id"] == current
                    and incarnation["stopped_at_ms"] is None
                ):
                    incarnation["stopped_at_ms"] = int(time.time() * 1000)
                    break
        record["current_incarnation_id"] = None
        record["status"] = "stopped"
        self._save(state)
        return dict(record)

    @_serialized
    def rollback_start(self, embodiment_id: str, *, incarnation_id: str) -> dict[str, Any]:
        """Compensate an unlaunched incarnation after admission is lost.

        This is deliberately narrower than ``stop``: it only removes the exact
        current incarnation and therefore cannot erase a body that reached the
        runtime boundary or a later incarnation created by another operation.
        """

        state = self.load()
        try:
            record = state["embodiments"][embodiment_id]
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc
        if (
            record.get("status") != "running"
            or record.get("current_incarnation_id") != incarnation_id
            or not record.get("incarnations")
            or record["incarnations"][-1].get("incarnation_id") != incarnation_id
            or record["incarnations"][-1].get("stopped_at_ms") is not None
        ):
            raise RegistryError("registry start compensation precondition failed")
        record["incarnations"].pop()
        record["current_incarnation_id"] = None
        record["status"] = "stopped"
        self._save(state)
        return dict(record)

    def status(self, embodiment_id: str) -> dict[str, Any]:
        state = self.load()
        try:
            return copy.deepcopy(state["embodiments"][embodiment_id])
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc

    def list_all(self) -> list[dict[str, Any]]:
        """Return the registry in stable embodiment-id order."""
        state = self.load()
        return [
            copy.deepcopy(state["embodiments"][key])
            for key in sorted(state["embodiments"])
        ]
