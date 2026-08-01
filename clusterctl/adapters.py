"""Adapters that report *actual* instance state.

The abstract ``Adapter`` protocol has a single read method,
``list_instances() -> list[dict]``. Implementations must be read-only:
no incus mutations, no writes.

Normalized instance dict keys (adapters may add more; consumers ignore
unknown fields per the forward-compatibility rule):

- ``name``: str
- ``state``: lowercased incus status, e.g. ``"running"`` / ``"stopped"``
- ``image_version``: str | None (incus ``image.name`` config value)
- ``budgets``: ``{"cpu": int|None, "memory_mib": int|None, "disk_gib": int|None}``
- ``uptime_s``: int | None (None when not running or unknown)
"""

from __future__ import annotations

import abc
import json
import os
import re
import subprocess
from datetime import datetime, timezone

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([A-Za-z]+)?\s*$")
_SIZE_UNITS_BYTES = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
}


def _parse_size_bytes(value: str | None) -> int | None:
    """Parse an incus size string like ``"1536MiB"`` into bytes."""
    if not value:
        return None
    m = _SIZE_RE.match(str(value))
    if not m:
        return None
    num = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    factor = _SIZE_UNITS_BYTES.get(unit)
    if factor is None:
        return None
    return int(num * factor)


def _parse_cpu(value: str | None) -> int | None:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None  # e.g. a pinning range like "0-3" — not a fixed budget


def _root_disk_gib(expanded_devices: dict) -> int | None:
    """Extract the root disk size (GiB) from incus expanded_devices."""
    for dev in (expanded_devices or {}).values():
        if not isinstance(dev, dict):
            continue
        if dev.get("type") == "disk" and dev.get("path") == "/":
            size = _parse_size_bytes(dev.get("size"))
            if size is not None:
                return size // (1024**3)
            return None
    return None


def _parse_info_timestamp(text: str, label: str) -> datetime | None:
    """Parse e.g. ``Created: 2026/08/01 06:23 UTC`` from ``incus info`` output."""
    m = re.search(rf"^{re.escape(label)}:\s*(\d{{4}}/\d{{2}}/\d{{2}}\s+\d{{2}}:\d{{2}})\s+UTC\s*$",
                  text, re.MULTILINE)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M").replace(tzinfo=timezone.utc)


class Adapter(abc.ABC):
    """Abstract read-only source of actual instance state."""

    @abc.abstractmethod
    def list_instances(self) -> list[dict]:
        """Return normalized actual-state dicts for managed instances."""
        raise NotImplementedError


class FakeAdapter(Adapter):
    """In-memory adapter driven by test fixtures."""

    def __init__(self, instances: list[dict] | None = None):
        self._instances = list(instances or [])

    def list_instances(self) -> list[dict]:
        # Defensive copy so callers can mutate freely.
        return [dict(inst, budgets=dict(inst.get("budgets") or {})) for inst in self._instances]


class IncusError(Exception):
    """Raised when an incus invocation fails."""


class IncusAdapter(Adapter):
    """Adapter backed by the live incus daemon.

    Shells out (read-only) to:

    - ``incus list --format json`` (instance set, expanded config/devices)
    - ``incus config show <name>`` (per-instance config + profiles)
    - ``incus info <name>`` (state + started/created timestamps)

    Only instances using the configured profile (and, if set, matching
    the managed name prefix) are returned.
    """

    def __init__(
        self,
        profile: str = "tribe-agent",
        managed_prefix: str = "",
        project: str = "default",
        runner=None,
    ):
        self.profile = profile
        self.managed_prefix = managed_prefix or ""
        self.project = project
        # runner(argv: list[str]) -> str (stdout). Injectable for tests.
        self._runner = runner or self._sudo_runner

    @staticmethod
    def _sudo_runner(argv: list[str]) -> str:
        env = dict(os.environ)
        if "/usr/sbin" not in env.get("PATH", "").split(":"):
            env["PATH"] = env.get("PATH", "") + ":/usr/sbin"
        proc = subprocess.run(
            ["sudo", *argv],
            capture_output=True,
            text=True,
            env=env,
        )
        if proc.returncode != 0:
            raise IncusError(
                f"{' '.join(argv)} failed (rc={proc.returncode}): {proc.stderr.strip()}"
            )
        return proc.stdout

    def _incus(self, *args: str) -> str:
        argv = ["incus", *args]
        if self.project:
            argv += ["--project", self.project]
        return self._runner(argv)

    def list_instances(self) -> list[dict]:
        try:
            listing = json.loads(self._incus("list", "--format", "json"))
        except json.JSONDecodeError as exc:
            raise IncusError(f"cannot parse incus list JSON: {exc}") from exc

        instances = []
        aliases = self._image_aliases()
        for entry in listing:
            name = entry.get("name", "")
            profiles = entry.get("profiles") or []
            if self.profile not in profiles:
                continue
            if self.managed_prefix and not name.startswith(self.managed_prefix):
                continue
            instances.append(self._normalize(name, entry, aliases))
        return instances

    def _image_aliases(self) -> dict[str, str]:
        """Map image fingerprint -> shortest local alias (e.g. tribe-base/2026-08-01.1).

        Incus reports the upstream ``image.name`` for launched instances, which
        hides which tribe-base version (fingerprint/alias) actually backs the
        container. Aliases are the fleet's version handle, so resolve them.
        """
        try:
            images = json.loads(self._incus("image", "list", "--format", "json"))
        except Exception:
            return {}
        out: dict[str, str] = {}
        for img in images:
            fp = img.get("fingerprint") or ""
            aliases = [a.get("name", "") for a in (img.get("aliases") or [])]
            aliases = [a for a in aliases if a and a != "tribe-base/latest"]
            if fp and aliases:
                out[fp] = sorted(aliases, key=len)[0]
        return out

    def _normalize(self, name: str, entry: dict, image_aliases: dict[str, str] | None = None) -> dict:
        # `incus config show <name>` — per-instance (unexpanded) config.
        config_show = self._incus("config", "show", name)
        # `incus info <name>` — live state + timestamps.
        info = self._incus("info", name)

        expanded_config = entry.get("expanded_config") or {}
        config = entry.get("config") or {}

        state = str(entry.get("status") or "").strip().lower() or None
        m = re.search(r"^Status:\s*(\S+)", info, re.MULTILINE)
        if m:
            state = m.group(1).lower()

        uptime_s = None
        if state == "running":
            started = _parse_info_timestamp(info, "Started")
            if started is not None:
                uptime_s = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))

        memory_bytes = _parse_size_bytes(expanded_config.get("limits.memory"))
        base_image = expanded_config.get("volatile.base_image") or ""
        image_version = (image_aliases or {}).get(base_image) or (
            config.get("image.name") or expanded_config.get("image.name")
        )

        return {
            "name": name,
            "state": state,
            "image_version": image_version,
            "budgets": {
                "cpu": _parse_cpu(expanded_config.get("limits.cpu")),
                "memory_mib": (memory_bytes // (1024**2)) if memory_bytes is not None else None,
                "disk_gib": _root_disk_gib(entry.get("expanded_devices") or {}),
            },
            "uptime_s": uptime_s,
            "profiles": list(entry.get("profiles") or []),
            "config_show": config_show,
        }
