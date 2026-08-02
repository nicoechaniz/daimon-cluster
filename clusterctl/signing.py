"""Signing primitives for clusterctl records (extracted from leases.py, M10-R2).

Canonical-JSON signing shared by checkpoint manifests, embodiment-registry
records and (R3) chain-of-existence segments. No identity semantics live
here — this module only signs and verifies bytes.

Signers:

- ``FakeSigner``: deterministic fake signatures for tests.
- ``SSHSigner``: uses ``ssh-keygen -Y sign`` (production; placeholder
  until container identity provisioning lands — issue #12).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger("clusterctl.signing")


def now_ms() -> int:
    return int(time.time() * 1000)


def _canonical(record: dict) -> bytes:
    """Canonical JSON bytes for signing: sorted keys, compact separators,
    ``signature`` field removed."""
    stripped = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class InvalidSignature(Exception):
    """A signed record is unsigned, malformed or tampered."""


class Signer(ABC):
    @abstractmethod
    def sign(self, data: bytes) -> str:  # pragma: no cover - interface
        ...

    @abstractmethod
    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:  # pragma: no cover
        ...


class FakeSigner(Signer):
    """Deterministic test signer: signature = sha256(data) (NOT secure)."""

    def sign(self, data: bytes) -> str:
        return _sha256_hex(data)

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:
        return signature == _sha256_hex(data)


class SSHSigner(Signer):
    """Sign via ``ssh-keygen -Y`` with a local private key (production)."""

    def __init__(self, privkey_path: str | Path):
        self.privkey_path = Path(privkey_path)

    def sign(self, data: bytes) -> str:  # pragma: no cover - requires keys
        import subprocess

        proc = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.privkey_path), "-n", "daimon-cluster"],
            input=data, capture_output=True, timeout=10,
        )
        if proc.returncode != 0:
            raise InvalidSignature(f"ssh-keygen sign failed: {proc.stderr.decode(errors='replace')[:200]}")
        return proc.stdout.decode("utf-8", errors="replace")

    def verify(self, data: bytes, signature: str, pubkey: str) -> bool:  # pragma: no cover
        raise NotImplementedError("SSHSigner.verify lands with issue #12 identity provisioning")
