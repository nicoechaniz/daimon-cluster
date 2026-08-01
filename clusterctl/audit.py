"""Audit log for clusterctl mutations (issue #11).

Every mutation — and every *rejected* mutation — appends one JSON line
to ``<state_dir>/audit.jsonl`` conforming to ``audit-event/v1``:

- ``schema``: ``"audit-event/v1"``
- ``event_id``: uuid4
- ``ts_ms``: epoch milliseconds UTC
- ``actor``: from ``--actor`` (default ``"clusterctl-cli"``)
- ``action``: operation name (create/start/stop/restart/logs/destroy-plan)
- ``target``: instance name
- ``result``: ``ok`` | ``denied`` | ``error``
- ``detail``: dict, redacted — never contains secrets
- ``idempotency_key``: uuid or None

The log is append-only; reads (``last_event_for``) are side-effect free.
Hash-chaining and git mirroring per ``cluster-audit-event/v1`` land with
issue #19; this v1 log is the CLI-local precursor.
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

AUDIT_SCHEMA = "audit-event/v1"


def audit_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "audit.jsonl"


def now_ms() -> int:
    return int(time.time() * 1000)


def append_event(
    state_dir: str | Path,
    *,
    actor: str,
    action: str,
    target: str,
    result: str,
    detail: dict | None = None,
    idempotency_key: str | None = None,
) -> dict:
    """Append one ``audit-event/v1`` line and return the event dict."""
    if result not in ("ok", "denied", "error"):
        raise ValueError(f"invalid audit result {result!r}")
    event = {
        "schema": AUDIT_SCHEMA,
        "event_id": str(uuid.uuid4()),
        "ts_ms": now_ms(),
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
        "detail": dict(detail or {}),
        "idempotency_key": idempotency_key,
    }
    path = audit_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")
    return event


def last_event_for(state_dir: str | Path, target: str) -> dict | None:
    """Return the most recent audit event for ``target`` (read-only)."""
    path = audit_path(state_dir)
    if not path.is_file():
        return None
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("target") == target:
            last = event
    return last
