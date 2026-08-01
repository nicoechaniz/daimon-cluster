"""Signed daimon-presence lease records with CAS fencing + TTL (issue #27).

One file per daimon identity under ``<state_dir>/leases/<daimon_id>.json``,
conforming to ``lease/v1``:

- ``daimon_id``: global identity (e.g. ``eko@daimonmatrix``)
- ``identity_pubkey``: SSH public key of the identity
- ``fingerprint``: SHA256 fingerprint of the pubkey
- ``epoch``: monotonic unsigned integer (0 on acquire, increments on renew)
- ``created_ms``: epoch milliseconds UTC of the most recent mutation
- ``ttl_s``: lease duration in seconds
- ``signature``: canonical(lease minus signature) signed by the identity key
- ``renewer``: ``"self"`` | ``"steward"`` | ``"human"``

CAS fencing:

- ``acquire`` refuses if an unexpired lease already exists (``LeaseConflict``).
- ``renew`` increments epoch and re-signs; returns ``None`` if no lease
  or the lease is expired.
- ``release`` deletes the lease file (only if the existing lease signature
  is valid — corrupted/forged files are refused).

Garbage collection (housekeeping, never audits): ``collect_garbage`` drops
expired lease files with an info log.

Signers:

- ``FakeSigner``: deterministic fake signatures for tests.
- ``SSHSigner``: uses ``ssh-keygen -Y sign`` (production; placeholder
  until container identity provisioning lands — issue #12).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from pathlib import Path

LEASE_SCHEMA = "lease/v1"

logger = logging.getLogger("clusterctl.leases")


def now_ms() -> int:
    return int(time.time() * 1000)


def _canonical(record: dict) -> bytes:
    """Canonical JSON bytes for signing: sorted keys, compact separators,
    ``signature`` field removed."""
    stripped = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Signer interface
# ---------------------------------------------------------------------------


class Signer(ABC):
    """Abstract signer: produce and verify signatures over canonical lease bytes."""

    @abstractmethod
    def sign(self, data: bytes) -> str:
        ...

    @abstractmethod
    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        """Return True when ``signature`` is a valid signature of ``data``
        by the private key corresponding to ``pubkey``."""
        ...


class FakeSigner(Signer):
    """Deterministic fake signer for tests.

    Produces signatures of the form ``"FAKE:<hex>"`` where ``<hex>`` is
    ``sha256(data)[:32]``. Verification checks that the produced signature
    matches — any other string is rejected.
    """

    def sign(self, data: bytes) -> str:
        return "FAKE:" + _sha256_hex(data)[:32]

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        # pubkey is ignored in fake mode (trust the store's own record)
        expected = self.sign(data)
        return signature == expected


class SSHSigner(Signer):
    """Production signer using ``ssh-keygen -Y sign``.

    Placeholder until container identity provisioning (#12) — the daimon's
    private key must be available at ``privkey_path`` in its container.

    The ``sign`` method shells out to ``ssh-keygen -Y sign`` with
    ``-n file`` namespace; the signature is captured from stdout.
    """

    def __init__(self, privkey_path: str | Path):
        self._privkey_path = str(privkey_path)

    def sign(self, data: bytes) -> str:
        # Placeholder — real implementation will shell out to ssh-keygen.
        # For now, produce a distinguishable marker so tests don't
        # accidentally pass with the wrong signer.
        return f"SSH:{_sha256_hex(data)[:32]}"

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        # Placeholder — real implementation will use ssh-keygen -Y verify.
        raise NotImplementedError("SSH verification not yet implemented")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LeaseError(Exception):
    """Base for lease-operation errors."""


class LeaseConflict(LeaseError):
    """An unexpired lease already exists for this identity (CAS fencing)."""


class LeaseNotFound(LeaseError):
    """No lease found for this identity."""


class InvalidSignature(LeaseError):
    """The stored lease carries an invalid or forged signature."""


# ---------------------------------------------------------------------------
# LeaseStore
# ---------------------------------------------------------------------------


class LeaseStore:
    """Manage signed presence-lease files under ``state_dir/leases/``.

    Every write is atomic (temp file + ``os.replace``). Reads are direct
    from the JSON file. No file-level locking — contention is per-daimon
    and the CAS semantics prevent stale writers from overwriting a valid
    lease (acquire refuses existing leases; renew uses atomic replace).
    """

    LEASE_SCHEMA = LEASE_SCHEMA

    def __init__(self, state_dir: str | Path, signer: Signer | None = None):
        self._leases_dir = Path(state_dir) / "leases"
        self._signer: Signer = signer or FakeSigner()

    # -- helpers ---------------------------------------------------------

    def _lease_path(self, daimon_id: str) -> Path:
        return self._leases_dir / f"{daimon_id}.json"

    def _read_lease(self, daimon_id: str) -> dict | None:
        """Read and parse a lease file; return None if absent or unparseable."""
        path = self._lease_path(daimon_id)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _write_lease(self, daimon_id: str, lease: dict) -> None:
        """Atomically write a lease file (temp + os.replace)."""
        self._leases_dir.mkdir(parents=True, exist_ok=True)
        path = self._lease_path(daimon_id)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps(lease, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, path)

    def _sign(self, lease: dict) -> str:
        return self._signer.sign(_canonical(lease))

    def _verify(self, lease: dict) -> bool:
        """Verify that ``lease["signature"]`` is valid for the canonical
        record body and that the signer matches ``lease["identity_pubkey"]``."""
        sig = lease.get("signature")
        if not sig or not isinstance(sig, str):
            return False
        pubkey = lease.get("identity_pubkey") or ""
        return self._signer.verify(_canonical(lease), sig, pubkey)

    @staticmethod
    def _is_expired(lease: dict, at_ms: int | None = None) -> bool:
        created = lease.get("created_ms", 0)
        ttl_s = lease.get("ttl_s", 0)
        deadline = created + ttl_s * 1000
        return (at_ms or now_ms()) >= deadline

    # -- public API ------------------------------------------------------

    def acquire(
        self,
        daimon_id: str,
        pubkey: str,
        fingerprint: str,
        ttl_s: int = 3600,
        renewer: str = "self",
    ) -> dict:
        """Create a new lease (epoch=0).

        Raises ``LeaseConflict`` when an unexpired lease already exists
        for ``daimon_id`` (CAS fencing). An *expired* lease is silently
        overwritten — no conflict.

        Returns the full lease dict (schema ``lease/v1``).
        """
        # enforce_fencing check
        existing = self._read_lease(daimon_id)
        if existing is not None and not self._is_expired(existing):
            raise LeaseConflict(
                f"lease for {daimon_id!r} is held (epoch={existing.get('epoch')}, "
                f"renewer={existing.get('renewer')}); release or wait for expiry"
            )
        lease = {
            "schema": self.LEASE_SCHEMA,
            "daimon_id": daimon_id,
            "identity_pubkey": pubkey,
            "fingerprint": fingerprint,
            "epoch": 0,
            "created_ms": now_ms(),
            "ttl_s": ttl_s,
            "renewer": renewer,
        }
        lease["signature"] = self._sign(lease)
        self._write_lease(daimon_id, lease)
        logger.info("lease acquired: %s epoch=0 ttl=%ds renewer=%s",
                     daimon_id, ttl_s, renewer)
        return lease

    def renew(
        self,
        daimon_id: str,
        privkey_path: str,
        new_ttl_s: int | None = None,
    ) -> dict | None:
        """Renew an existing lease: epoch ↦ epoch+1, re-sign.

        ``privkey_path`` is passed to the signer; in v1 (FakeSigner or
        the placeholder SSHSigner) it is advisory — the real verification
        will require the daimon's private key in its container.

        Returns the updated lease, or ``None`` when there is no existing
        lease or it is already expired (CAS fencing — a stale writer
        cannot renew a lease that has lapsed).
        """
        existing = self._read_lease(daimon_id)
        if existing is None:
            return None
        if self._is_expired(existing):
            return None
        # Verify the existing lease signature before proceeding.
        if not self._verify(existing):
            raise InvalidSignature(
                f"cannot renew {daimon_id!r}: existing lease carries an "
                f"invalid signature"
            )
        epoch = existing["epoch"] + 1
        ttl = new_ttl_s if new_ttl_s is not None else existing["ttl_s"]
        lease = {
            "schema": self.LEASE_SCHEMA,
            "daimon_id": daimon_id,
            "identity_pubkey": existing["identity_pubkey"],
            "fingerprint": existing["fingerprint"],
            "epoch": epoch,
            "created_ms": now_ms(),
            "ttl_s": ttl,
            "renewer": existing["renewer"],
        }
        lease["signature"] = self._sign(lease)
        self._write_lease(daimon_id, lease)
        logger.info("lease renewed: %s epoch=%d ttl=%ds",
                     daimon_id, epoch, ttl)
        return lease

    def release(self, daimon_id: str) -> None:
        """Destroy the lease file for ``daimon_id``.

        Only succeeds when the lease exists AND carries a valid signature
        (prevents deletion of forged/manually edited files). Raises
        ``LeaseNotFound`` when no lease file exists; ``InvalidSignature``
        when the stored signature is invalid.
        """
        existing = self._read_lease(daimon_id)
        if existing is None:
            raise LeaseNotFound(f"no lease for {daimon_id!r}")
        if not self._verify(existing):
            raise InvalidSignature(
                f"cannot release {daimon_id!r}: stored lease carries an "
                f"invalid signature"
            )
        path = self._lease_path(daimon_id)
        path.unlink()
        logger.info("lease released: %s", daimon_id)

    def status(self, daimon_id: str) -> dict:
        """Return a lightweight status dict for ``daimon_id``.

        Keys: ``daimon_id``, ``expires_in_ms`` (0 when expired or absent),
        ``expired`` (bool), ``renewer``, ``last_epoch``, ``present`` (bool).
        """
        lease = self._read_lease(daimon_id)
        if lease is None:
            return {
                "daimon_id": daimon_id,
                "present": False,
                "expires_in_ms": 0,
                "expired": True,
                "renewer": None,
                "last_epoch": None,
            }
        created = lease.get("created_ms", 0)
        ttl_s = lease.get("ttl_s", 0)
        deadline = created + ttl_s * 1000
        remaining = max(0, deadline - now_ms())
        expired = remaining == 0
        return {
            "daimon_id": daimon_id,
            "present": True,
            "expires_in_ms": remaining,
            "expired": expired,
            "renewer": lease.get("renewer"),
            "last_epoch": lease.get("epoch"),
        }

    def list_all(self) -> list[dict]:
        """Return a status dict for every lease file found on disk."""
        result = []
        if not self._leases_dir.is_dir():
            return result
        for path in sorted(self._leases_dir.glob("*.json")):
            daimon_id = path.stem
            try:
                st = self.status(daimon_id)
            except Exception:
                st = {
                    "daimon_id": daimon_id,
                    "present": True,
                    "expires_in_ms": 0,
                    "expired": True,
                    "renewer": None,
                    "last_epoch": None,
                    "error": "unreadable",
                }
            result.append(st)
        return result

    def collect_garbage(self) -> int:
        """Drop expired lease files (housekeeping — never audits).

        Returns the number of leases removed.
        """
        removed = 0
        if not self._leases_dir.is_dir():
            return 0
        for path in sorted(self._leases_dir.glob("*.json")):
            daimon_id = path.stem
            lease = self._read_lease(daimon_id)
            if lease is None:
                continue
            if not self._is_expired(lease):
                continue
            path.unlink()
            removed += 1
            logger.info("lease garbage-collected: %s (expired)", daimon_id)
        return removed
