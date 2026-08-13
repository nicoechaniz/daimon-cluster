"""Synthetic resource-fence fixtures for isolated legacy test scenarios.

Runtime code must import :mod:`clusterctl.fences` and receives only the
authenticated SQLite authority or its query-only verifier.
"""

from .fences import (
    FENCE_SCHEMA as LEASE_SCHEMA,
    Ed25519Signer,
    FakeSigner,
    FenceConflict as LeaseConflict,
    FenceError as LeaseError,
    FenceNotFound as LeaseNotFound,
    InvalidSignature,
    SyntheticResourceFenceStore as LeaseStore,
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
