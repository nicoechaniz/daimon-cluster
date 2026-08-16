"""Fail-closed production credentials for park/wake/transfer handoffs."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .admission import AdmissionEndpoint, FenceMutationClient
from .fences import Ed25519Signer, FenceError

CLIENT_SCHEMA = "dm.cluster.admission-client/v1"
_IDENTITY_FIELDS = (
    "being_ref",
    "body_ref",
    "embodiment_id",
    "incarnation_id",
    "activation_id",
    "credential_id",
    "manifest_hash",
)


class HandoffAuthorizationError(RuntimeError):
    pass


def holder_identity(spec: Mapping[str, Any], manifest: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Return only explicitly declared/enrolled identity; never synthesize it."""

    candidate: Any = None
    if manifest is not None:
        candidate = manifest.get("fence_holder")
    if not isinstance(candidate, dict):
        candidate = spec.get("fence_holder")
    if not isinstance(candidate, dict) and spec.get("instance_kind") == "matrix-embodiment":
        candidate = {
            "being_ref": spec.get("being_ref"),
            "body_ref": spec.get("body_ref"),
            "embodiment_id": spec.get("embodiment_id"),
            "incarnation_id": spec.get("current_incarnation_id"),
            "activation_id": spec.get("activation_id"),
            "credential_id": spec.get("credential_id"),
            "manifest_hash": spec.get("manifest_hash"),
        }
    if not isinstance(candidate, dict) or set(candidate) != set(_IDENTITY_FIELDS):
        raise HandoffAuthorizationError("exact enrolled fence holder identity is missing")
    if not all(isinstance(candidate.get(key), str) and candidate[key] for key in _IDENTITY_FIELDS):
        raise HandoffAuthorizationError("exact enrolled fence holder identity is invalid")
    return {key: candidate[key] for key in _IDENTITY_FIELDS}


def _owner_json(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise HandoffAuthorizationError("handoff authority config is not owner-only")
        value = json.loads(path.read_text(encoding="utf-8"))
    except HandoffAuthorizationError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise HandoffAuthorizationError("handoff authority config is unavailable") from exc
    if not isinstance(value, dict):
        raise HandoffAuthorizationError("handoff authority config is invalid")
    return value


def configured_client(
    state_dir: str | Path,
    spec: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any] | None = None,
) -> FenceMutationClient:
    identity = holder_identity(spec, manifest)
    config = _owner_json(Path(state_dir) / "admission-client.json")
    required = {
        "schema", "endpoint", "holder_key_path", "holder_key_id",
        "authority_key_id", "authority_public_key", "lease_ttl_s",
    }
    if set(config) != required or config.get("schema") != CLIENT_SCHEMA:
        raise HandoffAuthorizationError("handoff authority config is invalid")
    endpoint_config = config.get("endpoint")
    try:
        if (
            isinstance(endpoint_config, dict)
            and set(endpoint_config) == {"transport", "path"}
            and endpoint_config.get("transport") == "unix-local-fixture"
        ):
            endpoint = AdmissionEndpoint.local_fixture(endpoint_config["path"])
        elif (
            isinstance(endpoint_config, dict)
            and set(endpoint_config) == {"transport", "host", "port"}
            and endpoint_config.get("transport") == "tcp-authenticated"
        ):
            endpoint = AdmissionEndpoint.network(
                endpoint_config["host"], endpoint_config["port"]
            )
        else:
            raise ValueError
        signer = Ed25519Signer(config["holder_key_path"], config["holder_key_id"])
        return FenceMutationClient(
            endpoint,
            holder_signer=signer,
            authority_key_id=config["authority_key_id"],
            authority_public_key=config["authority_public_key"],
            lease_ttl_s=config["lease_ttl_s"],
            being_ref=identity["being_ref"],
            body_ref=identity["body_ref"],
            embodiment_id=identity["embodiment_id"],
            incarnation_id=identity["incarnation_id"],
            activation_id=identity["activation_id"],
            credential_id=identity["credential_id"],
            manifest_hash=identity["manifest_hash"],
        )
    except (KeyError, TypeError, ValueError, FenceError) as exc:
        raise HandoffAuthorizationError("handoff authority config is invalid") from exc


__all__ = [
    "CLIENT_SCHEMA", "HandoffAuthorizationError", "configured_client",
    "holder_identity",
]
