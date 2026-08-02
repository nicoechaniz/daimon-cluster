"""Signed CAS/TTL fences scoped to concrete writable resources.

Several embodiments of one being may hold fences for different resources.
Only contenders for the exact same ``resource_ref`` exclude one another.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path

FENCE_SCHEMA = "resource-fence/v1"
logger = logging.getLogger("clusterctl.fences")


def now_ms() -> int:
    return int(time.time() * 1000)


def _canonical(record: dict) -> bytes:
    return json.dumps(
        {key: value for key, value in record.items() if key != "signature"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


class Signer(ABC):
    @abstractmethod
    def sign(self, data: bytes) -> str: ...

    @abstractmethod
    def verify(self, data: bytes, signature: str, pubkey: str) -> bool: ...


class FakeSigner(Signer):
    def sign(self, data: bytes) -> str:
        return "FAKE:" + hashlib.sha256(data).hexdigest()[:32]

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        return signature == self.sign(data)


class SSHSigner(Signer):
    def __init__(self, privkey_path: str | Path):
        self._privkey_path = str(privkey_path)

    def sign(self, data: bytes) -> str:
        return "SSH:" + hashlib.sha256(data).hexdigest()[:32]

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        raise NotImplementedError("SSH verification not yet implemented")


class FenceError(Exception): pass
class FenceConflict(FenceError): pass
class FenceNotFound(FenceError): pass
class InvalidSignature(FenceError): pass


class ResourceFenceStore:
    FENCE_SCHEMA = FENCE_SCHEMA
    LEASE_SCHEMA = FENCE_SCHEMA

    def __init__(self, state_dir: str | Path, signer: Signer | None = None):
        # Keep the established on-disk directory while changing the record
        # semantics. Operators retain their backup/runbook paths; artifacts
        # inside it are exclusively ``resource-fence/v1``.
        self._fences_dir = Path(state_dir) / "leases"
        self._leases_dir = self._fences_dir
        self._high_waters_path = Path(state_dir) / "resource-fence-high-waters.json"
        self._signer = signer or FakeSigner()

    def _high_waters(self) -> dict[str, int]:
        if not self._high_waters_path.is_file():
            return {}
        try:
            value = json.loads(self._high_waters_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FenceError("cannot read resource-fence high waters") from exc
        if not isinstance(value, dict) or any(
            not isinstance(key, str)
            or isinstance(epoch, bool)
            or not isinstance(epoch, int)
            or epoch < 0
            for key, epoch in value.items()
        ):
            raise FenceError("invalid resource-fence high waters")
        return value

    def _record_high_water(self, resource_ref: str, epoch: int) -> None:
        values = self._high_waters()
        if epoch <= values.get(resource_ref, -1):
            return
        values[resource_ref] = epoch
        self._high_waters_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._high_waters_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(values, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, self._high_waters_path)

    def _next_epoch(self, resource_ref: str, existing: dict | None) -> int:
        current = -1 if existing is None else int(existing.get("epoch", -1))
        return max(current, self._high_waters().get(resource_ref, -1)) + 1

    @staticmethod
    def _filename(resource_ref: str) -> str:
        if not resource_ref or "/" in resource_ref or "\\" in resource_ref or resource_ref in {".", ".."}:
            raise FenceError("resource_ref is not safe for registry storage")
        return resource_ref + ".json"

    def _lease_path(self, resource_ref: str) -> Path:
        return self._fences_dir / self._filename(resource_ref)

    def _read_lease(self, resource_ref: str) -> dict | None:
        path = self._lease_path(resource_ref)
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if value.get("resource_ref") == resource_ref else None

    def _write_lease(self, resource_ref: str, value: dict) -> None:
        self._fences_dir.mkdir(parents=True, exist_ok=True)
        path = self._lease_path(resource_ref)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    def _sign(self, value: dict) -> str:
        return self._signer.sign(_canonical(value))

    def _verify(self, value: dict) -> bool:
        signature = value.get("signature")
        return isinstance(signature, str) and self._signer.verify(
            _canonical(value), signature, str(value.get("holder_pubkey") or "")
        )

    @staticmethod
    def _is_expired(value: dict, at_ms: int | None = None) -> bool:
        return (now_ms() if at_ms is None else at_ms) >= value.get("created_ms", 0) + value.get("ttl_s", 0) * 1000

    def acquire(
        self, resource_ref: str, pubkey: str, fingerprint: str,
        ttl_s: int = 3600, renewer: str = "self", *,
        holder_embodiment_id: str | None = None,
    ) -> dict:
        existing = self._read_lease(resource_ref)
        if existing is not None and not self._verify(existing):
            raise InvalidSignature(
                f"cannot acquire {resource_ref!r}: existing fence is invalid"
            )
        if existing is not None and not self._is_expired(existing):
            raise FenceConflict(
                f"resource {resource_ref!r} fenced by {existing.get('holder_embodiment_id')!r} "
                f"at generation {existing.get('epoch')}"
            )
        timestamp = now_ms()
        epoch = self._next_epoch(resource_ref, existing)
        value = {
            "schema": FENCE_SCHEMA, "resource_ref": resource_ref,
            "holder_embodiment_id": holder_embodiment_id or "unbound",
            "holder_pubkey": pubkey, "fingerprint": fingerprint,
            "epoch": epoch, "created_ms": timestamp, "acquired_ms": timestamp,
            "ttl_s": ttl_s, "renewer": renewer,
        }
        value["signature"] = self._sign(value)
        self._write_lease(resource_ref, value)
        self._record_high_water(resource_ref, epoch)
        return value

    def renew(self, resource_ref: str, privkey_path: str, new_ttl_s: int | None = None) -> dict | None:
        existing = self._read_lease(resource_ref)
        if existing is None or self._is_expired(existing):
            return None
        if not self._verify(existing):
            raise InvalidSignature(f"cannot renew {resource_ref!r}: invalid signature")
        value = {
            **{key: item for key, item in existing.items() if key != "signature"},
            "epoch": self._next_epoch(resource_ref, existing),
            "created_ms": now_ms(),
            "ttl_s": existing["ttl_s"] if new_ttl_s is None else new_ttl_s,
        }
        value["signature"] = self._sign(value)
        self._write_lease(resource_ref, value)
        self._record_high_water(resource_ref, int(value["epoch"]))
        return value

    def get(self, resource_ref: str) -> dict | None:
        return self._read_lease(resource_ref)

    def restore(self, resource_ref: str, value: dict) -> None:
        if value.get("schema") != FENCE_SCHEMA or value.get("resource_ref") != resource_ref or not self._verify(value):
            raise InvalidSignature(f"cannot restore {resource_ref!r}: invalid resource fence")
        self._write_lease(resource_ref, value)
        self._record_high_water(resource_ref, int(value["epoch"]))

    def release(self, resource_ref: str) -> None:
        value = self._read_lease(resource_ref)
        if value is None:
            raise FenceNotFound(f"no resource fence for {resource_ref!r}")
        if not self._verify(value):
            raise InvalidSignature(f"cannot release {resource_ref!r}: invalid signature")
        self._lease_path(resource_ref).unlink()

    def status(self, resource_ref: str) -> dict:
        value = self._read_lease(resource_ref)
        if value is None:
            return {"resource_ref": resource_ref, "present": False, "expires_in_ms": 0, "expired": True, "renewer": None, "last_epoch": None, "acquired_ms": None, "holder_embodiment_id": None}
        if not self._verify(value):
            return {
                "resource_ref": resource_ref, "present": True,
                "expires_in_ms": 0, "expired": True, "renewer": None,
                "last_epoch": None, "acquired_ms": None,
                "holder_embodiment_id": None, "error": "invalid_signature",
            }
        remaining = max(0, value["created_ms"] + value["ttl_s"] * 1000 - now_ms())
        return {
            "resource_ref": resource_ref, "present": True,
            "expires_in_ms": remaining, "expired": remaining == 0,
            "renewer": value.get("renewer"), "last_epoch": value.get("epoch"),
            "acquired_ms": value.get("acquired_ms"),
            "holder_embodiment_id": value.get("holder_embodiment_id"),
        }

    def list_all(self) -> list[dict]:
        if not self._fences_dir.is_dir():
            return []
        result = []
        for path in sorted(self._fences_dir.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                result.append(self.status(value["resource_ref"]))
            except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                result.append({"present": True, "expired": True, "error": "unreadable"})
        return result

    def collect_garbage(self) -> int:
        removed = 0
        if not self._fences_dir.is_dir():
            return 0
        for path in sorted(self._fences_dir.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("cannot inspect resource-fence file %s: %s", path, exc)
                continue
            if self._is_expired(value):
                path.unlink()
                removed += 1
        return removed
