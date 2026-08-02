"""Live `/we` request/response records and local deduplication."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .protocol import BeingManifest, ProtocolError


def request(
    manifest: BeingManifest,
    origin: dict[str, str],
    content: Any,
    *,
    timeout_ms: int = 30_000,
    now_ms: int | None = None,
) -> dict[str, Any]:
    manifest.origin_member(origin)
    if not 100 <= timeout_ms <= 300_000:
        raise ProtocolError("invalid_request_timeout")
    issued = int(time.time() * 1000) if now_ms is None else now_ms
    return {
        "schema": "dm.we.request/v1", "request_id": str(uuid.uuid4()),
        "being_ref": manifest.value["being_ref"], "manifest_hash": manifest.digest,
        "origin": dict(origin), "issued_at_ms": issued,
        "deadline_ms": issued + timeout_ms, "content": content,
    }


@dataclass
class RequestHandler:
    manifest: BeingManifest
    origin: dict[str, str]
    handled: dict[str, dict[str, Any]] = field(default_factory=dict)

    def handle(self, value: dict[str, Any], responder: Callable[[Any], Any], *, now_ms: int | None = None) -> dict[str, Any]:
        if value.get("schema") != "dm.we.request/v1" or value.get("being_ref") != self.manifest.value["being_ref"] or value.get("manifest_hash") != self.manifest.digest:
            raise ProtocolError("invalid_we_request")
        self.manifest.origin_member(value.get("origin") or {})
        try:
            uuid.UUID(value["request_id"])
        except (KeyError, ValueError) as exc:
            raise ProtocolError("invalid_request_id") from exc
        if value["request_id"] in self.handled:
            return self.handled[value["request_id"]]
        current = int(time.time() * 1000) if now_ms is None else now_ms
        if current > value.get("deadline_ms", -1):
            raise ProtocolError("request_expired")
        response = {
            "schema": "dm.we.response/v1", "request_id": value["request_id"],
            "being_ref": value["being_ref"], "manifest_hash": value["manifest_hash"],
            "origin": dict(self.origin), "completed_at_ms": current,
            "status": "ok", "content": responder(value.get("content")),
        }
        self.handled[value["request_id"]] = response
        return response
