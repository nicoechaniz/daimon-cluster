"""Idempotency store for clusterctl mutations (issue #11).

``<state_dir>/idempotency.json`` maps an idempotency key (uuid) to::

    {"operation": str, "name": str, "result": dict, "created_ms": int}

Semantics:

- Same key + same operation + same name is only a replay candidate. The caller
  MUST also observe that the cached postcondition and current resource fence
  still match. Drift turns the retry into a successor execution.
- Same key + different operation (or different name) -> conflict
  (exit 6).

Entries are recorded only on success, so a failed mutation may be
retried with the same key.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path


class IdempotencyError(RuntimeError):
    pass


def store_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "idempotency.json"


def load_store(state_dir: str | Path) -> dict:
    path = store_path(state_dir)
    if path.is_symlink():
        raise IdempotencyError("idempotency store symlink is forbidden")
    if not path.is_file():
        return {}
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise IdempotencyError("idempotency store is not owner-only")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IdempotencyError("cannot read idempotency store") from exc
    if not isinstance(data, dict):
        raise IdempotencyError("invalid idempotency store")
    return data


def save_store(state_dir: str | Path, store: dict) -> None:
    path = store_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
    ):
        raise IdempotencyError("idempotency store parent is unsafe")
    path.parent.chmod(0o700)
    temporary = path.with_suffix(".tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        raw = (json.dumps(store, indent=2, sort_keys=True) + "\n").encode()
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def check(store: dict, key: str | None, operation: str, name: str):
    """Classify a key against the store.

    Returns ``("replay", entry)``, ``("conflict", entry)``, or
    ``("new", None)``. No key -> always ``("new", None)``.
    """
    if not key:
        return "new", None
    entry = store.get(key)
    if entry is None:
        return "new", None
    if entry.get("operation") == operation and entry.get("name") == name:
        return "replay", entry
    return "conflict", entry


def record(store: dict, key: str, operation: str, name: str, result: dict) -> None:
    store[key] = {
        "operation": operation,
        "name": name,
        "result": result,
        "created_ms": int(time.time() * 1000),
        "effect": {
            "expected_state": result.get("state"),
            "resource_fence": result.get("resource_fence"),
        },
    }
