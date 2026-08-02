"""Canonical ``dm.we.v1`` records and provisional being manifests."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL = "dm.we.v1"
EVENT_DOMAIN = b"daimon/weave/event/v1\x00"
MAX_EVENT_BYTES = 256 * 1024
MAX_PAGE_BYTES = 1024 * 1024
MAX_PAGE_EVENTS = 256
MAX_CAUSAL_PARENTS = 64
EVENT_KINDS = frozenset(
    {
        "experience.observed",
        "skill.proposed",
        "preference.proposed",
        "configuration.proposed",
        "adoption.decided",
        "projection.receipted",
        "lifecycle.announced",
    }
)
DECISIONS = frozenset({"adopt", "reject", "defer", "revert"})
SENSITIVITIES = frozenset({"personal", "private", "shareable"})
SECRET_NAMES = re.compile(
    r"(?:^|_)(?:password|passwd|token|secret|private_key|api_key|bearer)(?:$|_)",
    re.IGNORECASE,
)


class ProtocolError(ValueError):
    """Stable fail-closed protocol error."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ProtocolError("invalid_base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ProtocolError("invalid_base64url") from exc
    if b64url(decoded) != value or (size is not None and len(decoded) != size):
        raise ProtocolError("invalid_base64url")
    return decoded


def _uuid_ref(value: Any, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix + ":"):
        raise ProtocolError(f"invalid_{prefix}_id")
    try:
        uuid.UUID(value.split(":", 1)[1])
    except (ValueError, AttributeError) as exc:
        raise ProtocolError(f"invalid_{prefix}_id") from exc
    return value


def _plain_uuid(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"invalid_{field}")
    try:
        uuid.UUID(value)
    except ValueError as exc:
        raise ProtocolError(f"invalid_{field}") from exc
    return value


def _reject_secret_values(value: Any, path: str = "payload") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("invalid_payload_key")
            if SECRET_NAMES.search(key) and not key.endswith("_ref"):
                raise ProtocolError(f"secret_value_forbidden:{path}.{key}")
            _reject_secret_values(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_values(item, f"{path}[{index}]")


@dataclass(frozen=True)
class BeingManifest:
    value: dict[str, Any]
    digest: str

    @classmethod
    def from_value(cls, value: Any) -> BeingManifest:
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "being_ref",
            "revision",
            "embodiments",
        }:
            raise ProtocolError("invalid_manifest_fields")
        if value["schema"] != "being-manifest/v1":
            raise ProtocolError("unsupported_manifest")
        _uuid_ref(value["being_ref"], "being")
        revision = value["revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ProtocolError("invalid_manifest_revision")
        rows = value["embodiments"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
            raise ProtocolError("invalid_manifest_embodiments")
        normalized = []
        seen_ids: set[str] = set()
        seen_principals: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "embodiment_id",
                "principal_id",
                "body_ref",
                "status",
            }:
                raise ProtocolError("invalid_manifest_embodiment")
            embodiment_id = _uuid_ref(row["embodiment_id"], "embodiment")
            principal = row["principal_id"]
            body_ref = row["body_ref"]
            if (
                not isinstance(principal, str)
                or not 1 <= len(principal) <= 128
                or not isinstance(body_ref, str)
                or not 1 <= len(body_ref) <= 256
                or row["status"] not in {"active", "retired"}
            ):
                raise ProtocolError("invalid_manifest_embodiment")
            if embodiment_id in seen_ids or principal in seen_principals:
                raise ProtocolError("duplicate_manifest_member")
            seen_ids.add(embodiment_id)
            seen_principals.add(principal)
            normalized.append(dict(row))
        if normalized != sorted(normalized, key=lambda row: row["embodiment_id"]):
            raise ProtocolError("manifest_members_not_sorted")
        exact = {
            "schema": value["schema"],
            "being_ref": value["being_ref"],
            "revision": revision,
            "embodiments": normalized,
        }
        return cls(exact, sha256_hex(canonical_json(exact)))

    @classmethod
    def load(cls, path: str | Path) -> BeingManifest:
        try:
            raw = Path(path).read_bytes()
            value = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("cannot_read_manifest") from exc
        return cls.from_value(value)

    def member(self, embodiment_id: str) -> dict[str, Any]:
        for row in self.value["embodiments"]:
            if row["embodiment_id"] == embodiment_id and row["status"] == "active":
                return row
        raise ProtocolError("embodiment_not_active")

    def origin_member(self, origin: Mapping[str, Any]) -> dict[str, Any]:
        row = self.member(str(origin.get("embodiment_id")))
        if row["principal_id"] != origin.get("principal_id") or row["body_ref"] != origin.get("body_ref"):
            raise ProtocolError("origin_manifest_mismatch")
        return row


@dataclass(frozen=True)
class EventSigner:
    kid: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, kid: str) -> EventSigner:
        return cls(kid, Ed25519PrivateKey.generate())

    @property
    def public_key_text(self) -> str:
        return b64url(self.private_key.public_key().public_bytes_raw())

    def sign(self, content_hash: str) -> dict[str, str]:
        signature = self.private_key.sign(EVENT_DOMAIN + bytes.fromhex(content_hash))
        return {"alg": "Ed25519", "kid": self.kid, "value": b64url(signature)}


def event_core(
    *,
    event_id: str,
    manifest: BeingManifest,
    origin: Mapping[str, Any],
    sequence: int,
    previous_event_id: str | None,
    occurred_at_ms: int,
    causal_parents: list[str],
    kind: str,
    subject: str,
    payload: Mapping[str, Any],
    supersedes: str | None,
    sensitivity: str,
) -> dict[str, Any]:
    core = {
        "protocol": PROTOCOL,
        "event_id": event_id,
        "being_ref": manifest.value["being_ref"],
        "manifest_hash": manifest.digest,
        "origin": dict(origin),
        "sequence": sequence,
        "previous_event_id": previous_event_id,
        "occurred_at_ms": occurred_at_ms,
        "causal_parents": list(causal_parents),
        "kind": kind,
        "subject": subject,
        "payload": dict(payload),
        "supersedes": supersedes,
        "sensitivity": sensitivity,
    }
    validate_core(core, manifest)
    return core


def sign_event(core: Mapping[str, Any], signer: EventSigner) -> dict[str, Any]:
    digest = sha256_hex(canonical_json(core))
    return {**core, "content_hash": digest, "signature": signer.sign(digest)}


def validate_core(core: Any, manifest: BeingManifest) -> dict[str, Any]:
    fields = {
        "protocol", "event_id", "being_ref", "manifest_hash", "origin",
        "sequence", "previous_event_id", "occurred_at_ms", "causal_parents",
        "kind", "subject", "payload", "supersedes", "sensitivity",
    }
    if not isinstance(core, dict) or set(core) != fields:
        raise ProtocolError("invalid_event_fields")
    if core["protocol"] != PROTOCOL:
        raise ProtocolError("unsupported_event_protocol")
    _plain_uuid(core["event_id"], "event_id")
    if core["being_ref"] != manifest.value["being_ref"]:
        raise ProtocolError("wrong_being")
    if core["manifest_hash"] != manifest.digest:
        raise ProtocolError("manifest_hash_mismatch")
    origin = core["origin"]
    if not isinstance(origin, dict) or set(origin) != {
        "embodiment_id", "incarnation_id", "principal_id", "body_ref"
    }:
        raise ProtocolError("invalid_origin")
    _uuid_ref(origin["embodiment_id"], "embodiment")
    _uuid_ref(origin["incarnation_id"], "incarnation")
    manifest.origin_member(origin)
    sequence = core["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ProtocolError("invalid_sequence")
    previous = core["previous_event_id"]
    if sequence == 1:
        if previous is not None:
            raise ProtocolError("unexpected_predecessor")
    elif previous is None:
        raise ProtocolError("missing_predecessor")
    else:
        _plain_uuid(previous, "previous_event_id")
    if isinstance(core["occurred_at_ms"], bool) or not isinstance(core["occurred_at_ms"], int) or core["occurred_at_ms"] < 0:
        raise ProtocolError("invalid_occurred_at")
    parents = core["causal_parents"]
    if not isinstance(parents, list) or len(parents) > MAX_CAUSAL_PARENTS or parents != sorted(set(parents)):
        raise ProtocolError("invalid_causal_parents")
    for parent in parents:
        _plain_uuid(parent, "causal_parent")
    if core["kind"] not in EVENT_KINDS:
        raise ProtocolError("unsupported_event_kind")
    if not isinstance(core["subject"], str) or not 1 <= len(core["subject"]) <= 256:
        raise ProtocolError("invalid_subject")
    if not isinstance(core["payload"], dict) or len(core["payload"]) > 64:
        raise ProtocolError("invalid_payload")
    _reject_secret_values(core["payload"])
    if core["supersedes"] is not None:
        _plain_uuid(core["supersedes"], "supersedes")
    if core["sensitivity"] not in SENSITIVITIES:
        raise ProtocolError("invalid_sensitivity")
    if core["kind"] == "adoption.decided":
        if set(core["payload"]) != {"target_event_id", "decision", "reason"} or core["payload"]["decision"] not in DECISIONS:
            raise ProtocolError("invalid_adoption_decision")
        _plain_uuid(core["payload"]["target_event_id"], "target_event_id")
    return core


def validate_event(
    event: Any,
    manifest: BeingManifest,
    public_keys: Mapping[str, str],
) -> dict[str, Any]:
    if not isinstance(event, dict) or set(event) != {
        "protocol", "event_id", "being_ref", "manifest_hash", "origin",
        "sequence", "previous_event_id", "occurred_at_ms", "causal_parents",
        "kind", "subject", "payload", "supersedes", "sensitivity",
        "content_hash", "signature",
    }:
        raise ProtocolError("invalid_event_fields")
    if len(canonical_json(event)) > MAX_EVENT_BYTES:
        raise ProtocolError("event_too_large")
    core = {key: value for key, value in event.items() if key not in {"content_hash", "signature"}}
    validate_core(core, manifest)
    digest = sha256_hex(canonical_json(core))
    if event["content_hash"] != digest:
        raise ProtocolError("content_hash_mismatch")
    signature = event["signature"]
    if not isinstance(signature, dict) or set(signature) != {"alg", "kid", "value"} or signature["alg"] != "Ed25519":
        raise ProtocolError("invalid_signature")
    public_text = public_keys.get(signature["kid"])
    if public_text is None:
        raise ProtocolError("unknown_signing_key")
    try:
        Ed25519PublicKey.from_public_bytes(b64url_decode(public_text, 32)).verify(
            b64url_decode(signature["value"], 64),
            EVENT_DOMAIN + bytes.fromhex(digest),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ProtocolError("invalid_signature") from exc
    return event
