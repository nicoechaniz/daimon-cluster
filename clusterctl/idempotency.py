"""Idempotency store for clusterctl mutations (issue #11).

``<state_dir>/idempotency.json`` maps an idempotency key (uuid) to::

    {"operation": str, "name": str, "result": dict, "created_ms": int}

Semantics (mirrors the tribe-bridge v1 broker):

- Same key + same operation + same name -> replay the cached result
  (exit 0, ``"idempotent-replay": true`` in ``--json`` output); the
  mutation is NOT re-executed.
- Same key + different operation (or different name) -> conflict
  (exit 6).

Entries are recorded only on success, so a failed mutation may be
retried with the same key.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


def store_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "idempotency.json"


def load_store(state_dir: str | Path) -> dict:
    path = store_path(state_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def save_store(state_dir: str | Path, store: dict) -> None:
    path = store_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
    }
