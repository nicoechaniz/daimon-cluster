"""Bounded, owner-bound snapshot pagination for clusterd read models.

The cursor is intentionally opaque.  A cursor never contains fleet data; it
identifies an immutable in-memory snapshot and its next offset.  Snapshots are
bound to the authenticated visibility scope and query filters, expire quickly,
and are evicted under a hard count/byte budget.  That gives callers stable
pages while the underlying inventory or append-only log changes, without
turning a cursor into a durable capability.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

PAGE_SCHEMA = "clusterd-page/v1"
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
MAX_SNAPSHOT_ITEMS = 5_000
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
SNAPSHOT_TTL_S = 300.0
MAX_SNAPSHOTS = 32


class CursorError(ValueError):
    """A cursor is invalid, stale, or used outside its original scope."""

    def __init__(self, reason: str, *, stale: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.stale = stale


@dataclass(frozen=True)
class _Snapshot:
    items: tuple[object, ...]
    binding: str
    observed_at_ms: int
    expires_at: float
    truncated: bool
    size_bytes: int


def parse_limit(query: dict | None, default: int = DEFAULT_LIMIT) -> int:
    raw = (query or {}).get("limit", [None])[0]
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise CursorError("invalid-limit") from exc
    if value < 1 or value > MAX_LIMIT:
        raise CursorError("invalid-limit")
    return value


def query_cursor(query: dict | None) -> str | None:
    raw = (query or {}).get("cursor", [None])[0]
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str) or len(raw) > 512:
        raise CursorError("invalid-cursor")
    return raw


class SnapshotPager:
    """Thread-safe immutable snapshot cache with signed opaque cursors."""

    def __init__(
        self,
        *,
        ttl_s: float = SNAPSHOT_TTL_S,
        max_snapshots: int = MAX_SNAPSHOTS,
        max_items: int = MAX_SNAPSHOT_ITEMS,
        max_bytes: int = MAX_SNAPSHOT_BYTES,
        secret: bytes | None = None,
        monotonic=time.monotonic,
    ):
        self._ttl_s = float(ttl_s)
        self._max_snapshots = int(max_snapshots)
        self._max_items = int(max_items)
        self._max_bytes = int(max_bytes)
        self._secret = secret or secrets.token_bytes(32)
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._snapshots: OrderedDict[str, _Snapshot] = OrderedDict()
        self._bytes = 0

    @staticmethod
    def binding(kind: str, owner: str, filters: dict | None = None) -> str:
        value = {
            "kind": kind,
            "owner": owner,
            "filters": filters or {},
        }
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def _signature(self, payload: bytes) -> bytes:
        return hmac.new(self._secret, payload, hashlib.sha256).digest()[:16]

    def _encode(self, snapshot_id: str, offset: int) -> str:
        payload = json.dumps(
            {"s": snapshot_id, "o": offset},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        token = payload + self._signature(payload)
        return base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")

    def _decode(self, cursor: str) -> tuple[str, int]:
        try:
            raw = cursor.encode("ascii")
            decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
            if len(decoded) < 17:
                raise ValueError
            payload, signature = decoded[:-16], decoded[-16:]
            if not hmac.compare_digest(signature, self._signature(payload)):
                raise ValueError
            value = json.loads(payload)
            snapshot_id = value["s"]
            offset = value["o"]
            if (
                not isinstance(snapshot_id, str)
                or len(snapshot_id) != 32
                or isinstance(offset, bool)
                or not isinstance(offset, int)
                or offset < 0
            ):
                raise ValueError
        except (UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise CursorError("invalid-cursor") from exc
        return snapshot_id, offset

    def _remove(self, snapshot_id: str) -> None:
        snapshot = self._snapshots.pop(snapshot_id, None)
        if snapshot is not None:
            self._bytes -= snapshot.size_bytes

    def _purge(self, now: float) -> None:
        for snapshot_id, snapshot in list(self._snapshots.items()):
            if snapshot.expires_at <= now:
                self._remove(snapshot_id)
        while (
            len(self._snapshots) > self._max_snapshots
            or self._bytes > self._max_bytes
        ):
            oldest = next(iter(self._snapshots))
            self._remove(oldest)

    def _page(
        self, snapshot_id: str, snapshot: _Snapshot, offset: int, limit: int
    ) -> dict:
        if offset > len(snapshot.items):
            raise CursorError("invalid-cursor")
        end = min(offset + limit, len(snapshot.items))
        has_more = end < len(snapshot.items)
        return {
            "schema": PAGE_SCHEMA,
            "items": copy.deepcopy(list(snapshot.items[offset:end])),
            "page": {
                "limit": limit,
                "count": end - offset,
                "has_more": has_more,
                "next_cursor": self._encode(snapshot_id, end) if has_more else None,
                "snapshot_id": snapshot_id,
                "observed_at_ms": snapshot.observed_at_ms,
                "expires_in_s": max(
                    0, int(snapshot.expires_at - self._monotonic())
                ),
                "truncated": snapshot.truncated,
            },
        }

    def first(
        self,
        items: list[object],
        *,
        binding: str,
        limit: int,
        observed_at_ms: int,
        truncated: bool = False,
    ) -> dict:
        # Canonical JSON both rejects non-JSON values and gives a defensible
        # byte budget.  Decode it back so callers cannot mutate the snapshot.
        admitted: list[object] = []
        size = 2
        was_truncated = bool(truncated)
        for item in items:
            encoded = json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
            increment = len(encoded) + (1 if admitted else 0)
            if len(admitted) >= self._max_items or size + increment > self._max_bytes:
                was_truncated = True
                break
            admitted.append(json.loads(encoded))
            size += increment
        now = self._monotonic()
        snapshot_id = secrets.token_hex(16)
        snapshot = _Snapshot(
            items=tuple(admitted),
            binding=binding,
            observed_at_ms=int(observed_at_ms),
            expires_at=now + self._ttl_s,
            truncated=was_truncated,
            size_bytes=size,
        )
        with self._lock:
            self._purge(now)
            self._snapshots[snapshot_id] = snapshot
            self._bytes += size
            self._purge(now)
            if snapshot_id not in self._snapshots:
                raise CursorError("snapshot-capacity-exceeded", stale=True)
            return self._page(snapshot_id, snapshot, 0, limit)

    def resume(self, cursor: str, *, binding: str, limit: int) -> dict:
        snapshot_id, offset = self._decode(cursor)
        now = self._monotonic()
        with self._lock:
            self._purge(now)
            snapshot = self._snapshots.get(snapshot_id)
            if snapshot is None:
                raise CursorError("stale-cursor", stale=True)
            if snapshot.binding != binding:
                raise CursorError("cursor-scope-mismatch")
            self._snapshots.move_to_end(snapshot_id)
            return self._page(snapshot_id, snapshot, offset, limit)
