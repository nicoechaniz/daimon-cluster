"""One-shot human approvals for unattended steward mutations.

The clusterd process owns no human signing key.  It persists public authority
descriptors and content-addressed intents only.  A separate process signs one
exact intent; the server verifies and consumes that approval atomically.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

from clusterctl.fences import Ed25519Signer, FenceError
from clusterctl.production_fences import _verify_ed25519

INTENT_SCHEMA = "clusterd-human-approval-intent/v1"
APPROVAL_SCHEMA = "clusterd-human-approval/v1"
AUTHORITY_SCHEMA = "clusterd-human-authorities/v1"
DEFAULT_TTL_S = 300
MAX_TTL_S = 300
MAX_HEADER_BYTES = 16 * 1024


class ApprovalError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _approval_root(state_dir: str | Path) -> Path:
    return Path(state_dir) / "human-approvals"


def _authorities_path(state_dir: str | Path) -> Path:
    return _approval_root(state_dir) / "authorities.json"


def _intent_path(state_dir: str | Path, intent_id: str) -> Path:
    if not intent_id.startswith("clusterd:approval-intent:v1:"):
        raise ApprovalError("approval-intent-id-invalid")
    digest = intent_id.rsplit(":", 1)[-1]
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ApprovalError("approval-intent-id-invalid")
    return _approval_root(state_dir) / "intents" / f"{digest}.json"


def _write_owner_file(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(_canonical_json(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_owner_json(path: Path) -> dict[str, Any]:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise ApprovalError("approval-state-symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ApprovalError("approval-state-replaced")
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > 256 * 1024
        ):
            raise ApprovalError("approval-state-not-owner-only")
        raw = b""
        while chunk := os.read(descriptor, 16 * 1024):
            raw += chunk
            if len(raw) > 256 * 1024:
                raise ApprovalError("approval-state-too-large")
        value = json.loads(raw)
    except FileNotFoundError as exc:
        raise ApprovalError("approval-state-missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ApprovalError("approval-state-invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise ApprovalError("approval-state-invalid")
    return value


def register_authority(
    state_dir: str | Path, *, key_id: str, public_key: str
) -> dict[str, Any]:
    """Provision one public authority descriptor; no private key is accepted."""

    if not key_id or not public_key.startswith("ssh-ed25519 "):
        raise ApprovalError("approval-authority-invalid")
    path = _authorities_path(state_dir)
    if path.exists():
        value = _read_owner_json(path)
    else:
        value = {"schema": AUTHORITY_SCHEMA, "authorities": {}}
    if value.get("schema") != AUTHORITY_SCHEMA or not isinstance(
        value.get("authorities"), dict
    ):
        raise ApprovalError("approval-authorities-invalid")
    existing = value["authorities"].get(key_id)
    record = {"public_key": public_key, "state": "active"}
    if existing is not None and existing != record:
        raise ApprovalError("approval-authority-conflict")
    value["authorities"][key_id] = record
    _write_owner_file(path, value)
    return {"key_id": key_id, **record}


def revoke_authority(state_dir: str | Path, key_id: str) -> None:
    value = _read_owner_json(_authorities_path(state_dir))
    record = value.get("authorities", {}).get(key_id)
    if not isinstance(record, dict):
        raise ApprovalError("approval-authority-unknown")
    record["state"] = "revoked"
    _write_owner_file(_authorities_path(state_dir), value)


def target_state_hash(state_dir: str | Path, target: str | None) -> str:
    if target is None:
        return _digest({"target": None})
    path = Path(state_dir) / "instances" / f"{target}.yaml"
    try:
        raw = path.read_bytes()
    except OSError:
        raw = b"<absent>"
    return hashlib.sha256(raw).hexdigest()


def issue_intent(
    state_dir: str | Path,
    *,
    token_id: str,
    actor: str,
    operation: str,
    method: str,
    path: str,
    target: str | None,
    args: dict[str, Any],
    now_ms: int | None = None,
    ttl_s: int = DEFAULT_TTL_S,
) -> dict[str, Any]:
    if not 1 <= ttl_s <= MAX_TTL_S:
        raise ApprovalError("approval-intent-ttl-invalid")
    created_ms = int(time.time() * 1000) if now_ms is None else now_ms
    body: dict[str, Any] = {
        "schema": INTENT_SCHEMA,
        "token_id": token_id,
        "actor": actor,
        "operation": operation,
        "method": method,
        "path": path,
        "target": target,
        "args_hash": _digest(args),
        "target_state_hash": target_state_hash(state_dir, target),
        "created_ms": created_ms,
        "expires_at_ms": created_ms + ttl_s * 1000,
        "nonce": base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("="),
    }
    digest = _digest(body)
    body["intent_id"] = f"clusterd:approval-intent:v1:{digest}"
    persisted = {**body, "used": False}
    _write_owner_file(_intent_path(state_dir, body["intent_id"]), persisted)
    return body


def sign_intent(signer: Ed25519Signer, intent: dict[str, Any]) -> dict[str, Any]:
    if intent.get("schema") != INTENT_SCHEMA:
        raise ApprovalError("approval-intent-invalid")
    return {
        "schema": APPROVAL_SCHEMA,
        "authority_key_id": signer.key_id,
        "intent": intent,
        "signature": signer.sign(_canonical_json(intent)),
    }


def encode_approval(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(_canonical_json(value)).decode().rstrip("=")


def decode_approval(value: str | None) -> dict[str, Any]:
    if not value or len(value) > MAX_HEADER_BYTES:
        raise ApprovalError("human-approval-required")
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
        decoded = json.loads(raw)
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise ApprovalError("human-approval-invalid") from exc
    if not isinstance(decoded, dict):
        raise ApprovalError("human-approval-invalid")
    return decoded


def consume_approval(
    state_dir: str | Path,
    encoded: str | None,
    *,
    token_id: str,
    actor: str,
    operation: str,
    method: str,
    path: str,
    target: str | None,
    args: dict[str, Any],
    now_ms: int | None = None,
) -> dict[str, Any]:
    approval = decode_approval(encoded)
    if set(approval) != {"schema", "authority_key_id", "intent", "signature"}:
        raise ApprovalError("human-approval-invalid")
    if approval["schema"] != APPROVAL_SCHEMA or not isinstance(
        approval.get("intent"), dict
    ):
        raise ApprovalError("human-approval-invalid")
    intent = approval["intent"]
    intent_id = intent.get("intent_id")
    if not isinstance(intent_id, str):
        raise ApprovalError("human-approval-invalid")
    expected = {
        "token_id": token_id,
        "actor": actor,
        "operation": operation,
        "method": method,
        "path": path,
        "target": target,
        "args_hash": _digest(args),
        "target_state_hash": target_state_hash(state_dir, target),
    }
    if intent.get("schema") != INTENT_SCHEMA or any(
        intent.get(key) != value for key, value in expected.items()
    ):
        raise ApprovalError("human-approval-binding-mismatch")
    unsigned = {key: value for key, value in intent.items() if key != "intent_id"}
    if intent_id != f"clusterd:approval-intent:v1:{_digest(unsigned)}":
        raise ApprovalError("human-approval-intent-id-mismatch")
    observed_ms = int(time.time() * 1000) if now_ms is None else now_ms
    created_ms = intent.get("created_ms")
    expires_at_ms = intent.get("expires_at_ms")
    if (
        isinstance(created_ms, bool)
        or not isinstance(created_ms, int)
        or isinstance(expires_at_ms, bool)
        or not isinstance(expires_at_ms, int)
        or created_ms > observed_ms + 5_000
        or expires_at_ms <= observed_ms
        or expires_at_ms <= created_ms
        or expires_at_ms - created_ms > MAX_TTL_S * 1000
    ):
        raise ApprovalError("human-approval-expired")
    authorities = _read_owner_json(_authorities_path(state_dir))
    key_id = approval.get("authority_key_id")
    authority = authorities.get("authorities", {}).get(key_id)
    if not isinstance(authority, dict) or authority.get("state") != "active":
        raise ApprovalError("human-approval-authority-unknown")
    signature = approval.get("signature")
    if not isinstance(signature, str) or not _verify_ed25519(
        _canonical_json(intent), signature, authority.get("public_key", "")
    ):
        raise ApprovalError("human-approval-signature-invalid")

    intent_path = _intent_path(state_dir, intent_id)
    lock_path = _approval_root(state_dir) / ".consume.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        persisted = _read_owner_json(intent_path)
        if persisted.get("used") is True:
            raise ApprovalError("human-approval-replayed")
        if {key: value for key, value in persisted.items() if key != "used"} != intent:
            raise ApprovalError("human-approval-intent-mismatch")
        persisted["used"] = True
        persisted["used_at_ms"] = observed_ms
        _write_owner_file(intent_path, persisted)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
    return approval


def signer_from_path(path: str | Path, key_id: str) -> Ed25519Signer:
    try:
        return Ed25519Signer(path, key_id)
    except FenceError as exc:
        raise ApprovalError("human-approval-signing-key-invalid") from exc


def main(argv: list[str] | None = None) -> int:
    """Offline signer utility. It has no state-dir/server access."""

    parser = argparse.ArgumentParser(description="sign one clusterd approval intent")
    parser.add_argument("--intent", required=True, help="approval intent JSON")
    parser.add_argument("--key", required=True, help="owner-only Ed25519 private key")
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args(argv)
    try:
        intent = json.loads(Path(args.intent).read_text(encoding="utf-8"))
        if not isinstance(intent, dict):
            raise ApprovalError("approval-intent-invalid")
        signer = signer_from_path(args.key, args.key_id)
        print(encode_approval(sign_intent(signer, intent)))
    except (OSError, json.JSONDecodeError, ApprovalError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
