"""Signed CAS/TTL fences scoped to concrete writable resources.

Several embodiments of one being may hold fences for different resources.
Only contenders for the exact same ``resource_ref`` exclude one another.
"""

from __future__ import annotations

import copy
import base64
import hashlib
import json
import logging
import os
import stat
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any

FENCE_SCHEMA = "resource-fence/v1"
logger = logging.getLogger("clusterctl.fences")


def now_ms() -> int:
    return int(time.time() * 1000)


def _canonical(record: dict) -> bytes:
    return json.dumps(
        {key: value for key, value in record.items() if key != "signature"},
        sort_keys=True,
        separators=(",", ":"),
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


class Ed25519Signer(Signer):
    """Real Ed25519 signer backed by one owner-only private key file."""

    PREFIX = "ED25519:"

    def __init__(self, privkey_path: str | Path, key_id: str):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        if not key_id or any(character.isspace() for character in key_id):
            raise FenceError("invalid production signing key id")
        path = Path(os.path.abspath(privkey_path))
        descriptor: int | None = None
        try:
            before = path.lstat()
            if stat.S_ISLNK(before.st_mode):
                raise FenceError("production signing key cannot be a symlink")
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise FenceError("production signing key was replaced")
            if metadata.st_size <= 0 or metadata.st_size > 64 * 1024:
                raise FenceError("production signing key size is invalid")
            chunks: list[bytes] = []
            size = 0
            while chunk := os.read(descriptor, 16 * 1024):
                size += len(chunk)
                if size > 64 * 1024:
                    raise FenceError("production signing key size is invalid")
                chunks.append(chunk)
            raw = b"".join(chunks)
        except OSError as exc:
            raise FenceError("cannot read production signing key") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise FenceError("production signing key is not a regular file")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise FenceError("production signing key must be owner-only")
        try:
            if raw.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
                private_key = serialization.load_ssh_private_key(raw, password=None)
            else:
                private_key = serialization.load_pem_private_key(raw, password=None)
        except (TypeError, ValueError) as exc:
            raise FenceError("invalid production signing key") from exc
        if not isinstance(private_key, Ed25519PrivateKey):
            raise FenceError("production signing key must be Ed25519")
        self._private_key = private_key
        self.key_id = key_id
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        )
        self.public_key = public_bytes.decode("ascii")

    def sign(self, data: bytes) -> str:
        return self.PREFIX + base64.b64encode(self._private_key.sign(data)).decode(
            "ascii"
        )

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not signature.startswith(self.PREFIX):
            return False
        try:
            decoded = base64.b64decode(
                signature[len(self.PREFIX) :], validate=True
            )
            verifier = serialization.load_ssh_public_key(pubkey.encode("ascii"))
            if not isinstance(verifier, Ed25519PublicKey):
                return False
            verifier.verify(decoded, data)
        except (ValueError, TypeError, CryptoInvalidSignature, UnicodeError):
            return False
        return True


class FenceError(Exception):
    pass


class FenceConflict(FenceError):
    pass


class FenceNotFound(FenceError):
    pass


class InvalidSignature(FenceError):
    pass


class _LegacyFileFenceStore:
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
        if (
            not resource_ref
            or "/" in resource_ref
            or "\\" in resource_ref
            or resource_ref in {".", ".."}
        ):
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
        temporary.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
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
        return (now_ms() if at_ms is None else at_ms) >= value.get(
            "created_ms", 0
        ) + value.get("ttl_s", 0) * 1000

    def acquire(
        self,
        resource_ref: str,
        pubkey: str,
        fingerprint: str,
        ttl_s: int = 3600,
        renewer: str = "self",
        *,
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
            "schema": FENCE_SCHEMA,
            "resource_ref": resource_ref,
            "holder_embodiment_id": holder_embodiment_id or "unbound",
            "holder_pubkey": pubkey,
            "fingerprint": fingerprint,
            "epoch": epoch,
            "created_ms": timestamp,
            "acquired_ms": timestamp,
            "ttl_s": ttl_s,
            "renewer": renewer,
        }
        value["signature"] = self._sign(value)
        self._write_lease(resource_ref, value)
        self._record_high_water(resource_ref, epoch)
        return value

    def renew(
        self, resource_ref: str, privkey_path: str, new_ttl_s: int | None = None
    ) -> dict | None:
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

    @staticmethod
    def proof_ref(value: dict) -> str:
        """Return an opaque reference bound to the complete signed record."""
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return "cluster:fence-proof:v1:" + hashlib.sha256(raw).hexdigest()

    def verify_current(
        self, resource_ref: str, *, at_ms: int | None = None
    ) -> dict | None:
        """Return one signed, unexpired, non-regressed fence or fail closed."""
        value = self._read_lease(resource_ref)
        if value is None:
            return None
        if value.get("schema") != FENCE_SCHEMA or not self._verify(value):
            raise InvalidSignature(
                f"cannot verify {resource_ref!r}: invalid resource fence"
            )
        observed_at_ms = now_ms() if at_ms is None else at_ms
        created_ms = value.get("created_ms")
        ttl_s = value.get("ttl_s")
        if (
            isinstance(observed_at_ms, bool)
            or not isinstance(observed_at_ms, int)
            or observed_at_ms < 0
            or isinstance(created_ms, bool)
            or not isinstance(created_ms, int)
            or created_ms < 0
            or isinstance(ttl_s, bool)
            or not isinstance(ttl_s, int)
            or ttl_s <= 0
        ):
            raise FenceError("invalid resource-fence time boundary")
        if created_ms > observed_at_ms:
            return None
        if observed_at_ms >= created_ms + ttl_s * 1000:
            return None
        epoch = value.get("epoch")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise FenceError("invalid resource-fence epoch")
        high_water = self._high_waters().get(resource_ref)
        if high_water is None or epoch != high_water:
            raise FenceError("resource-fence high-water regression")
        return copy.deepcopy(value)

    def current_for_holder(
        self, holder_embodiment_id: str, *, at_ms: int | None = None
    ) -> list[dict]:
        """Return verified current fences for a holder in resource order."""
        if not self._fences_dir.is_dir():
            return []
        result = []
        for path in sorted(self._fences_dir.glob("*.json")):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                resource_ref = raw["resource_ref"]
            except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                raise FenceError("unreadable resource-fence registry") from exc
            current = self.verify_current(resource_ref, at_ms=at_ms)
            if (
                current is not None
                and current.get("holder_embodiment_id") == holder_embodiment_id
            ):
                result.append(current)
        return result

    def support_status(self) -> dict:
        """Expose honest hardening support without leaking key material."""
        if isinstance(self._signer, FakeSigner):
            mode = "synthetic-fake-signer"
        elif isinstance(self._signer, SSHSigner):
            mode = "ssh-sign-only-verification-unimplemented"
        else:
            mode = "injected-signer"
        return {
            "schema": "resource-fence-support/v1",
            "mode": mode,
            "production_ready": False,
            "interprocess_cas": False,
        }

    def restore(self, resource_ref: str, value: dict) -> None:
        if (
            value.get("schema") != FENCE_SCHEMA
            or value.get("resource_ref") != resource_ref
            or not self._verify(value)
        ):
            raise InvalidSignature(
                f"cannot restore {resource_ref!r}: invalid resource fence"
            )
        self._write_lease(resource_ref, value)
        self._record_high_water(resource_ref, int(value["epoch"]))

    def release(self, resource_ref: str) -> None:
        value = self._read_lease(resource_ref)
        if value is None:
            raise FenceNotFound(f"no resource fence for {resource_ref!r}")
        if not self._verify(value):
            raise InvalidSignature(
                f"cannot release {resource_ref!r}: invalid signature"
            )
        self._lease_path(resource_ref).unlink()

    def status(self, resource_ref: str) -> dict:
        value = self._read_lease(resource_ref)
        if value is None:
            return {
                "resource_ref": resource_ref,
                "present": False,
                "expires_in_ms": 0,
                "expired": True,
                "renewer": None,
                "last_epoch": None,
                "acquired_ms": None,
                "holder_embodiment_id": None,
            }
        if not self._verify(value):
            return {
                "resource_ref": resource_ref,
                "present": True,
                "expires_in_ms": 0,
                "expired": True,
                "renewer": None,
                "last_epoch": None,
                "acquired_ms": None,
                "holder_embodiment_id": None,
                "error": "invalid_signature",
            }
        remaining = max(0, value["created_ms"] + value["ttl_s"] * 1000 - now_ms())
        return {
            "resource_ref": resource_ref,
            "present": True,
            "expires_in_ms": remaining,
            "expired": remaining == 0,
            "renewer": value.get("renewer"),
            "last_epoch": value.get("epoch"),
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


class SyntheticResourceFenceStore(_LegacyFileFenceStore):
    """Explicit test fixture; never selected by runtime code."""


class ResourceFenceStore:
    """Authenticated SQLite fence authority, or query-only verifier."""

    FENCE_SCHEMA = "resource-fence/v2"
    LEASE_SCHEMA = "resource-fence/v2"

    def __init__(
        self,
        state_dir: str | Path,
        signer: Signer | None = None,
        *,
        key_id: str | None = None,
        database_path: str | Path | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ):
        from .production_fences import ProductionFenceStore

        if isinstance(signer, FakeSigner):
            raise FenceError("synthetic signer is restricted to explicit fixtures")
        verifier_only = signer is None
        if signer is not None and key_id is None:
            key_id = getattr(signer, "key_id", None)
        self._backend: Any = ProductionFenceStore(
            state_dir,
            signer=signer,
            key_id=key_id,
            database_path=database_path,
            fault_hook=fault_hook,
            verifier_only=verifier_only,
        )

    @classmethod
    def production(
        cls,
        state_dir: str | Path,
        *,
        signer: Signer,
        key_id: str,
        database_path: str | Path | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> ResourceFenceStore:
        return cls(
            state_dir,
            signer,
            key_id=key_id,
            database_path=database_path,
            fault_hook=fault_hook,
        )

    @classmethod
    def production_verifier(
        cls,
        state_dir: str | Path,
        *,
        database_path: str | Path | None = None,
    ) -> ResourceFenceStore:
        from .production_fences import ProductionFenceStore

        value = cls.__new__(cls)
        value._backend = ProductionFenceStore(
            state_dir,
            signer=None,
            key_id=None,
            database_path=database_path,
            verifier_only=True,
        )
        return value

    def __getattr__(self, name: str):
        return getattr(self._backend, name)
