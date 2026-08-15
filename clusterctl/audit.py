"""Tamper-evident audit log for clusterctl mutations (issues #11 + #19).

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
- ``request_id``: caller-provided request id (clusterd's X-Request-Id)
  or None — forward-compatible optional field (issue #19)
- ``action_digest``: caller-provided confirmation digest (clusterd
  ``cluster-confirmation/v1`` action digest) or None

Hash chain (issue #19, design ``docs/design/clusterd.md`` §4):

- ``seq``: monotonic integer from the ``<state_dir>/audit-seq`` counter
  (atomic increment under an flock). Genesis event: ``seq`` 0.
- ``prev_sha256``: sha256 of the *raw line bytes* of the previous event
  (exactly as stored). Genesis: ``"0" * 64``.
- ``event_sha256``: sha256 of the canonical JSON (sorted keys, compact
  separators) of THIS event with the ``event_sha256`` field removed.

``verify_chain`` recomputes both hashes and the seq progression and also
compares the last chained seq against the high-water mark in
``<state_dir>/audit-hwm`` — so tampering (hash mismatch), truncation
(last seq < HWM) and sequence gaps (seq jumps) are all detectable.

Migration: events appended before the chain existed carry no ``seq``.
On the first append after the upgrade, the previous pre-chain line is
hashed AS-IS into ``prev_sha256`` (chain anchoring) and the new event
continues at ``seq = <number of existing lines>``. Pre-chain events are
therefore chain-ANCHORED but not themselves verifiable — any edit to a
pre-chain line breaks the first chained event's ``prev_sha256``, but
there is no ``event_sha256`` proving the pre-chain content itself.

Mirror (design §4, off-host placeholder until issue #15 targets land):
when ``<state_dir>/mirror/`` exists, every appended line is ALSO
appended to ``<state_dir>/mirror/audit.jsonl`` on a best-effort basis.
A mirror failure NEVER fails the local append and never drops the local
event — it is recorded in ``<state_dir>/mirror-last-error`` so the
clusterd health probe can report ``mirror_state: "failing"`` and degrade
health to ``"degraded"`` while the local log stays intact.

The log is append-only; reads (``last_event_for``, ``verify_chain``)
are side-effect free.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

AUDIT_SCHEMA = "audit-event/v1"
GENESIS_PREV_SHA256 = "0" * 64

SEQ_FILE = "audit-seq"
SEQ_LOCK_FILE = "audit-seq.lock"
HWM_FILE = "audit-hwm"
MIRROR_DIR = "mirror"
MIRROR_ERROR_FILE = "mirror-last-error"


def audit_path(state_dir: str | Path) -> Path:
    return Path(state_dir) / "audit.jsonl"


def now_ms() -> int:
    return int(time.time() * 1000)


def _canonical(event: dict) -> bytes:
    """Canonical JSON bytes used for hashing (sorted keys, compact)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def event_hash(event: dict) -> str:
    """sha256 of the canonical JSON of ``event`` minus ``event_sha256``."""
    stripped = {k: v for k, v in event.items() if k != "event_sha256"}
    return _sha256(_canonical(stripped))


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        tmp,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        raw = text.encode()
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(tmp, path)
    directory = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _next_seq(state_dir: Path, lines: list[str]) -> tuple[int, str]:
    """Atomically claim the next seq; return (seq, prev_sha256).

    Counter (``audit-seq``) and chain tail are read under an exclusive
    flock on ``audit-seq.lock``; the caller appends the event while still
    holding that lock (see ``append_event``).
    """
    seq_path = state_dir / SEQ_FILE
    last_seq: int | None = None
    if seq_path.is_file():
        try:
            last_seq = int(seq_path.read_text(encoding="utf-8").strip())
        except ValueError:
            last_seq = None
    prev_sha256 = GENESIS_PREV_SHA256
    if lines:
        last_line = lines[-1].strip()
        prev_sha256 = _sha256(last_line.encode("utf-8"))
        if last_seq is None:
            # Migration / counter recovery: derive the next seq from the
            # log tail. A chained last event gives its own seq; a
            # pre-chain tail is assigned ``len(lines) - 1`` so the new
            # event continues at ``len(lines)`` (pre-chain events are
            # chain-anchored, not themselves verifiable — see docstring).
            try:
                tail = json.loads(last_line)
            except json.JSONDecodeError:
                tail = {}
            tail_seq = tail.get("seq")
            last_seq = tail_seq if isinstance(tail_seq, int) else len(lines) - 1
    new_seq = (last_seq if last_seq is not None else -1) + 1
    _atomic_write(seq_path, f"{new_seq}\n")
    _atomic_write(state_dir / HWM_FILE, f"{new_seq}\n")
    return new_seq, prev_sha256


def _mirror_append(state_dir: Path, line: str) -> None:
    """Best-effort mirror of one appended line (design §4 placeholder).

    NEVER raises: a mirror failure is recorded to ``mirror-last-error``
    and the local event stays intact. Issue #15 replaces the directory
    mirror with real off-host targets.
    """
    mirror_dir = state_dir / MIRROR_DIR
    if not mirror_dir.is_dir():
        return  # not configured
    try:
        with (mirror_dir / "audit.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        err = state_dir / MIRROR_ERROR_FILE
        if err.exists():
            err.unlink()
    except OSError as exc:
        try:
            _atomic_write(state_dir / MIRROR_ERROR_FILE,
                          f"{now_ms()} {exc}\n")
        except OSError:
            pass


def append_event(
    state_dir: str | Path,
    *,
    actor: str,
    action: str,
    target: str,
    result: str,
    detail: dict | None = None,
    idempotency_key: str | None = None,
    request_id: str | None = None,
    action_digest: str | None = None,
    event_id: str | None = None,
) -> dict:
    """Append one chained ``audit-event/v1`` line and return the event."""
    if result not in ("ok", "denied", "error"):
        raise ValueError(f"invalid audit result {result!r}")
    state_dir = Path(state_dir)
    path = audit_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_dir / SEQ_LOCK_FILE
    lock_path.touch(exist_ok=True)
    with lock_path.open("r+", encoding="utf-8") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        lines = _read_lines(path)
        identifier = event_id or str(uuid.uuid4())
        if event_id is not None:
            try:
                if str(uuid.UUID(event_id)) != event_id:
                    raise ValueError
            except ValueError as exc:
                raise ValueError("invalid audit event id") from exc
            for raw in lines:
                try:
                    existing = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if existing.get("event_id") != event_id:
                    continue
                binding = {
                    "actor": actor,
                    "action": action,
                    "target": target,
                    "result": result,
                    "idempotency_key": idempotency_key,
                    "request_id": request_id,
                    "action_digest": action_digest,
                    "detail": dict(detail or {}),
                }
                if any(existing.get(key) != value for key, value in binding.items()):
                    raise ValueError("audit event id is bound to different bytes")
                return existing
        seq, prev_sha256 = _next_seq(state_dir, lines)
        event = {
            "schema": AUDIT_SCHEMA,
            "event_id": identifier,
            "ts_ms": now_ms(),
            "seq": seq,
            "prev_sha256": prev_sha256,
            "actor": actor,
            "action": action,
            "target": target,
            "result": result,
            "detail": dict(detail or {}),
            "idempotency_key": idempotency_key,
            "request_id": request_id,
            "action_digest": action_digest,
        }
        event["event_sha256"] = event_hash(event)
        line = json.dumps(event, sort_keys=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
    _mirror_append(state_dir, line)
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


def read_events(state_dir: str | Path) -> list[dict]:
    """Parse every audit event (unparseable lines are skipped)."""
    events = []
    for line in _read_lines(audit_path(Path(state_dir))):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def verify_chain(state_dir: str | Path) -> dict:
    """Verify the hash chain, seq progression and high-water mark.

    Returns ``{ok, events, first_bad_seq, error}``:

    - ``ok``: False when any check fails.
    - ``events``: number of parsed event lines (pre-chain included).
    - ``first_bad_seq``: seq of the first chained event that fails
      verification, or None.
    - ``error``: None, or one of ``"hash-mismatch"`` (event content
      altered), ``"chain-broken"`` (prev_sha256 linkage altered),
      ``"sequence-gap"`` (seq jump/missing event), ``"truncation"``
      (last chained seq below the recorded high-water mark),
      ``"unparseable-line"``.

    An empty (or absent) log verifies clean. Pre-chain events (no
    ``seq``) are skipped for per-event checks but their raw bytes still
    anchor the first chained event's ``prev_sha256``.
    """
    state_dir = Path(state_dir)
    lines = _read_lines(audit_path(state_dir))
    result = {"ok": True, "events": 0, "first_bad_seq": None, "error": None}

    prev_line: str | None = None
    prev_seq: int | None = None
    last_chained_seq: int | None = None
    for raw in lines:
        line = raw.strip()
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            result.update(ok=False, error="unparseable-line",
                          first_bad_seq=prev_seq + 1 if prev_seq is not None else 0)
            return result
        result["events"] += 1
        seq = event.get("seq")
        if not isinstance(seq, int):
            prev_line = line  # pre-chain event: anchor only, unverifiable
            continue
        if event.get("event_sha256") != event_hash(event):
            result.update(ok=False, first_bad_seq=seq, error="hash-mismatch")
            return result
        expected_prev = GENESIS_PREV_SHA256 if prev_line is None else \
            _sha256(prev_line.encode("utf-8"))
        if event.get("prev_sha256") != expected_prev:
            result.update(ok=False, first_bad_seq=seq, error="chain-broken")
            return result
        if prev_seq is not None and seq != prev_seq + 1:
            result.update(ok=False, first_bad_seq=seq, error="sequence-gap")
            return result
        prev_line, prev_seq = line, seq
        last_chained_seq = seq

    hwm_path = state_dir / HWM_FILE
    if hwm_path.is_file():
        try:
            hwm = int(hwm_path.read_text(encoding="utf-8").strip())
        except ValueError:
            hwm = None
        if hwm is not None and (last_chained_seq is None or last_chained_seq < hwm):
            result.update(ok=False, error="truncation",
                          first_bad_seq=(last_chained_seq or -1) + 1)
    return result
