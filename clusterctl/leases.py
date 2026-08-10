"""Compatibility import name for resource-scoped fencing.

Callers still importing ``clusterctl.leases`` receive resource fences. The
store never fences a being or Daimon identity.
"""

from .fences import (
    FENCE_SCHEMA as LEASE_SCHEMA,
    Ed25519Signer,
    FakeSigner,
    FenceConflict as LeaseConflict,
    FenceError as LeaseError,
    FenceNotFound as LeaseNotFound,
    InvalidSignature,
    ResourceFenceStore as LeaseStore,
    SSHSigner,
    Signer,
    _canonical,
    now_ms,
)

__all__ = [
    "Ed25519Signer", "FakeSigner", "InvalidSignature", "LEASE_SCHEMA", "LeaseConflict",
    "LeaseError", "LeaseNotFound", "LeaseStore", "SSHSigner", "Signer",
    "_canonical", "now_ms",
]
