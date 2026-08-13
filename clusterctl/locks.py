"""Per-instance mutation locks (issue #11).

A mutation on instance ``<name>`` must hold
``<state_dir>/locks/<name>.lock`` for its whole duration. The lock file
is created atomically (``O_CREAT|O_EXCL``) and contains JSON:
``{"operation", "pid", "ts_ms"}``.

- Concurrent mutation on the same name -> ``LockConflict`` (CLI: exit 6,
  holder info in the error JSON).
- A lock older than ``STALE_MS`` (10 min) is considered abandoned: it is
  broken and the operation proceeds; the previous holder is reported so
  the caller can note the break in the audit event.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from pathlib import Path

STALE_MS = 10 * 60 * 1000  # 10 minutes


class LockConflict(Exception):
    """Raised when another operation holds the instance lock."""

    def __init__(self, name: str, holder: dict):
        self.name = name
        self.holder = holder or {}
        op = self.holder.get("operation", "unknown")
        pid = self.holder.get("pid", "?")
        super().__init__(f"instance {name!r} is locked by {op} (pid {pid})")


class AcquiredLock:
    """Handle yielded by ``acquire``; ``stale_holder`` is set when a stale
    lock was broken to obtain this one."""

    def __init__(self, path: Path, stale_holder: dict | None):
        self.path = path
        self.stale_holder = stale_holder


def _locks_dir(state_dir: str | Path) -> Path:
    return Path(state_dir) / "locks"


def _read_holder(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


@contextlib.contextmanager
def acquire(state_dir: str | Path, name: str, operation: str, stale_ms: int = STALE_MS):
    """Acquire the per-instance lock; yields an ``AcquiredLock``.

    Raises ``LockConflict`` when a fresh lock is held by another operation.
    """
    locks_dir = _locks_dir(state_dir)
    locks_dir.mkdir(parents=True, exist_ok=True)
    path = locks_dir / f"{name}.lock"
    stale_holder = None
    payload = json.dumps(
        {"operation": operation, "pid": os.getpid(), "ts_ms": int(time.time() * 1000)}
    )
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            holder = _read_holder(path)
            ts_ms = (holder or {}).get("ts_ms")
            if ts_ms is not None and int(time.time() * 1000) - int(ts_ms) > stale_ms:
                stale_holder = holder
                path.unlink(missing_ok=True)
                continue
            raise LockConflict(name, holder or {})
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
        break
    try:
        yield AcquiredLock(path=path, stale_holder=stale_holder)
    finally:
        path.unlink(missing_ok=True)


@contextlib.contextmanager
def acquire_many(
    state_dir: str | Path,
    requests: list[tuple[str, str]],
    stale_ms: int = STALE_MS,
):
    """Acquire distinct target locks in stable order or release them all."""
    names = [name for name, _operation in requests]
    if len(set(names)) != len(names):
        raise ValueError("multi-target lock names must be distinct")
    acquired = {}
    with contextlib.ExitStack() as stack:
        for name, operation in sorted(requests):
            acquired[name] = stack.enter_context(
                acquire(state_dir, name, operation, stale_ms=stale_ms)
            )
        yield acquired
