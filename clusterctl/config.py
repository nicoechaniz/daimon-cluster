"""clusterctl configuration loading.

Versioned YAML config (schema ``clusterctl-config/v1``), normally at
``configs/clusterctl.yaml`` in the repository. Tests point ``state_dir``
at a temporary directory.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import yaml

CONFIG_SCHEMA = "clusterctl-config/v1"
DEFAULT_STATE_DIR = "/var/lib/daimon-cluster"


class ConfigError(Exception):
    """Raised when the clusterctl config is missing or invalid."""


@dataclasses.dataclass(frozen=True)
class Config:
    host_id: str
    incus_project: str
    managed_prefix: str
    profile: str
    state_dir: str = DEFAULT_STATE_DIR

    @property
    def instances_dir(self) -> Path:
        return Path(self.state_dir) / "instances"


def load_config(path: str | Path) -> Config:
    """Load and validate a ``clusterctl-config/v1`` YAML config file."""
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {p}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in config {p}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"config {p} must be a YAML mapping")
    schema = raw.get("schema")
    if schema != CONFIG_SCHEMA:
        raise ConfigError(
            f"config {p}: schema must be {CONFIG_SCHEMA!r}, got {schema!r}"
        )

    missing = [
        f
        for f in ("host_id", "incus_project", "managed_prefix", "profile")
        if f not in raw
    ]
    if missing:
        raise ConfigError(f"config {p}: missing required fields: {', '.join(missing)}")

    return Config(
        host_id=str(raw["host_id"]),
        incus_project=str(raw["incus_project"]),
        managed_prefix=str(raw["managed_prefix"]),
        profile=str(raw["profile"]),
        state_dir=str(raw.get("state_dir") or DEFAULT_STATE_DIR),
    )
