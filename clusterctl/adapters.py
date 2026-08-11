"""Adapters that report *actual* instance state and execute lifecycle mutations.

Read path: ``list_instances() -> list[dict]`` (strictly side-effect free).
Mutation path (issue #11): ``create_instance``, ``start``, ``stop``,
``restart``, ``delete``, ``logs`` — these change incus (or FakeAdapter
in-memory) state. All business rules (admission, idempotency, locking,
audit) live in ``clusterctl.lifecycle``; adapters only execute.

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
import hashlib
import json
import os
import re
import subprocess
import urllib.parse
from datetime import datetime, timezone

import yaml

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
    """Abstract source of actual instance state + lifecycle executor."""

    @abc.abstractmethod
    def list_instances(self) -> list[dict]:
        """Return normalized actual-state dicts for managed instances."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Lifecycle mutations (issue #11). Adapters only execute; all policy
    # (admission, idempotency, locking, audit) lives in clusterctl.lifecycle.
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def create_instance(self, name: str, image_alias: str, profile: str) -> None:
        """Create (but do not start) an instance from an image alias."""
        raise NotImplementedError

    @abc.abstractmethod
    def start(self, name: str) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def stop(self, name: str, timeout: int) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def restart(self, name: str) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, name: str) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def logs(self, name: str, max_lines: int) -> str:
        """Return up to ``max_lines`` most recent log lines."""
        raise NotImplementedError

    def list_volumes(self) -> list[str]:
        """Names of custom storage volumes in the default pool (read-only).

        Used by ``clusterctl reconcile`` (issue #19) to detect custom
        volumes without a matching spec. Default: unknown (empty list).
        """
        return []

    def resolve_image(self, image_alias: str) -> str:
        """Resolve a moving alias (e.g. tribe-base/latest) to a versioned one."""
        return image_alias

    def profile_budgets(self, profile: str) -> dict:
        """Budgets (cpu/memory_mib/disk_gib) granted by an incus profile."""
        return {}

    # ------------------------------------------------------------------
    # Provisioning primitives (issue #12)
    # ------------------------------------------------------------------

    def exec(self, name: str, argv: list[str]) -> str:
        """Run a command inside the instance; return stdout."""
        raise NotImplementedError

    def ensure_volume(self, name: str) -> None:
        """Create+attach the durable home volume ``<name>-home`` (idempotent)."""
        return None

    def delete_volume(self, name: str) -> None:
        """Best-effort removal of ``<name>-home`` (used during reversal)."""
        return None

    # ------------------------------------------------------------------
    # Durable-volume relocation primitives (issue #66)
    # ------------------------------------------------------------------

    def volume_observation(self, volume_name: str) -> dict:
        """Return exact custom-volume identity and instance attachments."""
        raise NotImplementedError

    def instance_volume_devices(self, instance: str) -> list[dict]:
        """Return unexpanded custom-volume devices attached to one instance."""
        raise NotImplementedError

    def attach_volume(
        self,
        volume_name: str,
        instance: str,
        *,
        device: str = "home",
        path: str = "/home/agent",
    ) -> dict:
        """Idempotently attach one existing volume and return observation."""
        raise NotImplementedError

    def detach_volume(
        self,
        volume_name: str,
        instance: str,
        *,
        device: str = "home",
    ) -> dict:
        """Idempotently detach one exact volume and return observation."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Quiesced snapshot primitives (issue #14)
    # ------------------------------------------------------------------

    def exec_quiesce_park(self, name: str, timeout_s: int) -> bool:
        """Park the daimon's writers (SIGSTOP hermes). True = parked."""
        raise NotImplementedError

    def exec_quiesce_verify(self, name: str) -> dict:
        """Checkpoint + integrity-check DBs in-container.

        Returns ``{"checkpoint_files": [paths], "sqlite_ok": bool}``.
        """
        raise NotImplementedError

    def exec_unpark(self, name: str) -> bool:
        """Resume the daimon (SIGCONT hermes). Best effort."""
        raise NotImplementedError

    def incus_snapshot_create(self, name: str, snap_name: str) -> None:
        raise NotImplementedError

    def incus_snapshot_verify(self, name: str, snap_name: str) -> bool:
        """True when the snapshot exists and is readable."""
        raise NotImplementedError

    def incus_snapshot_list(self, name: str) -> list[str]:
        raise NotImplementedError

    def incus_snapshot_delete(self, name: str, snap_name: str) -> None:
        raise NotImplementedError

    def manifest_written(self, name: str, manifest_path: str) -> None:
        """Hook called after a backup manifest is durably written (no-op)."""
        return None


DEFAULT_FAKE_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "fake@daimonmatrix"
)


class FakeAdapter(Adapter):
    """In-memory adapter driven by test fixtures.

    ``fail_create=True`` makes ``create_instance`` add the instance and
    then raise, simulating a mid-create failure so tests can exercise
    the reversal path. ``mutation_log`` records every mutation call.
    """

    def __init__(
        self,
        instances: list[dict] | None = None,
        profile_budgets_map: dict | None = None,
        image_aliases: dict | None = None,
        log_lines: dict | None = None,
        fail_create: bool = False,
        fail_volume: bool = False,
        exec_pubkey: str | None = None,
        fail_quiesce: bool = False,
        fail_verify: bool = False,
        fail_capture: bool = False,
        quiesce_files: list | None = None,
        volumes: list | None = None,
        volume_records: dict | None = None,
        exec_handler=None,
    ):
        self._instances = list(instances or [])
        self._volumes = set(volumes or [])
        self._volume_records: dict[str, dict] = {}
        for volume in self._volumes:
            self._volume_records[volume] = self._new_volume_record(volume)
        for volume, value in (volume_records or {}).items():
            record = self._new_volume_record(volume)
            record.update(dict(value))
            record["attachments"] = [dict(item) for item in value.get("attachments", [])]
            self._volume_records[volume] = record
            self._volumes.add(volume)
        self._profile_budgets = dict(profile_budgets_map or {})
        self._image_aliases = dict(image_aliases or {})
        self._log_lines = {k: list(v) for k, v in (log_lines or {}).items()}
        # Optional callable (name, argv) -> str | None. Returning a string
        # answers the exec; returning None falls through to the canned
        # defaults. Used by park tests to script in-container git/cat
        # behaviour (issue #28).
        self.exec_handler = exec_handler
        self.fail_create = fail_create
        self.fail_volume = fail_volume
        # Canned public material returned for `cat .../identity.pub`.
        self._exec_pubkey = exec_pubkey or DEFAULT_FAKE_PUBKEY
        # Quiesced-snapshot failure simulation (issue #14).
        self.fail_quiesce = fail_quiesce
        self.fail_verify = fail_verify
        self.fail_capture = fail_capture
        self._quiesce_files = list(quiesce_files) if quiesce_files is not None else [
            "/home/agent/.hermes/agent-memory/library.db",
        ]
        self.mutation_log: list[tuple] = []

    def list_instances(self) -> list[dict]:
        # Defensive copy so callers can mutate freely.
        return [dict(inst, budgets=dict(inst.get("budgets") or {})) for inst in self._instances]

    # -- mutations ------------------------------------------------------

    def _find(self, name: str) -> dict | None:
        for inst in self._instances:
            if inst["name"] == name:
                return inst
        return None

    def _require(self, name: str) -> dict:
        inst = self._find(name)
        if inst is None:
            raise ValueError(f"unknown instance {name!r}")
        return inst

    def create_instance(self, name: str, image_alias: str, profile: str) -> None:
        self.mutation_log.append(("create_instance", name))
        if self._find(name) is not None:
            raise ValueError(f"instance {name!r} already exists")
        self._instances.append(
            {
                "name": name,
                "state": "stopped",
                "image_version": image_alias,
                "budgets": dict(self._profile_budgets.get(profile) or {}),
                "uptime_s": None,
            }
        )
        if self.fail_create:
            raise RuntimeError(f"simulated mid-create failure for {name!r}")

    def start(self, name: str) -> None:
        self.mutation_log.append(("start", name))
        inst = self._require(name)
        inst["state"] = "running"
        inst["uptime_s"] = 0

    def stop(self, name: str, timeout: int = 30) -> None:
        self.mutation_log.append(("stop", name))
        inst = self._require(name)
        inst["state"] = "stopped"
        inst["uptime_s"] = None

    def restart(self, name: str) -> None:
        self.mutation_log.append(("restart", name))
        inst = self._require(name)
        if inst.get("state") != "running":
            raise ValueError(f"instance {name!r} is not running")
        inst["uptime_s"] = 0

    def delete(self, name: str) -> None:
        self.mutation_log.append(("delete", name))
        inst = self._require(name)
        self._instances.remove(inst)
        for volume in self._volume_records.values():
            volume["attachments"] = [
                item for item in volume["attachments"] if item["instance"] != name
            ]

    def logs(self, name: str, max_lines: int) -> str:
        self.mutation_log.append(("logs", name))
        self._require(name)
        lines = self._log_lines.get(name, [])
        return "\n".join(lines[-max_lines:]) if max_lines else ""

    def resolve_image(self, image_alias: str) -> str:
        return self._image_aliases.get(image_alias, image_alias)

    def profile_budgets(self, profile: str) -> dict:
        return dict(self._profile_budgets.get(profile) or {})

    # -- provisioning (issue #12) ----------------------------------------

    def exec(self, name: str, argv: list[str]) -> str:
        self.mutation_log.append(("exec", name, list(argv)))
        self._require(name)
        if self.exec_handler is not None:
            answered = self.exec_handler(name, list(argv))
            if answered is not None:
                return answered
        # Only the public-material read-back is answered; everything else
        # is recorded as a no-op (key generation, seed staging, etc.).
        if len(argv) == 2 and argv[0] == "cat" and argv[1].endswith("identity.pub"):
            return self._exec_pubkey + "\n"
        return ""

    def ensure_volume(self, name: str) -> None:
        self.mutation_log.append(("ensure_volume", name))
        self._require(name)
        if self.fail_volume:
            raise RuntimeError(f"simulated volume attach failure for {name!r}")
        volume = f"{name}-home"
        self._volumes.add(volume)
        self._volume_records.setdefault(volume, self._new_volume_record(volume))
        self.attach_volume(volume, name)

    def delete_volume(self, name: str) -> None:
        self.mutation_log.append(("delete_volume", name))
        volume = f"{name}-home"
        self._volumes.discard(volume)
        self._volume_records.pop(volume, None)

    def list_volumes(self) -> list[str]:
        return sorted(self._volumes)

    @staticmethod
    def _new_volume_record(volume_name: str) -> dict:
        return {
            "identity": "volume:" + hashlib.sha256(volume_name.encode()).hexdigest(),
            "content_type": "filesystem",
            "created_at": "fake",
            "attachments": [],
            "content_sha256": hashlib.sha256(
                f"fake-content:{volume_name}".encode()
            ).hexdigest(),
        }

    def volume_observation(self, volume_name: str) -> dict:
        record = self._volume_records.get(volume_name)
        if record is None:
            return {
                "schema": "cluster-volume-observation/v1",
                "present": False,
                "pool": "default",
                "project": "default",
                "name": volume_name,
                "identity": None,
                "attachments": [],
            }
        return {
            "schema": "cluster-volume-observation/v1",
            "present": True,
            "pool": "default",
            "project": "default",
            "name": volume_name,
            "identity": record["identity"],
            "content_type": record["content_type"],
            "created_at": record["created_at"],
            "attachments": sorted(
                [dict(item) for item in record["attachments"]],
                key=lambda item: (item["instance"], item["device"]),
            ),
            "content_sha256": record["content_sha256"],
        }

    def instance_volume_devices(self, instance: str) -> list[dict]:
        self._require(instance)
        result = []
        for volume_name, record in self._volume_records.items():
            for attachment in record["attachments"]:
                if attachment["instance"] == instance:
                    result.append(
                        {
                            "device": attachment["device"],
                            "pool": "default",
                            "source": volume_name,
                            "path": attachment["path"],
                            "writable": attachment["writable"],
                        }
                    )
        return sorted(result, key=lambda item: (item["device"], item["source"]))

    def attach_volume(
        self,
        volume_name: str,
        instance: str,
        *,
        device: str = "home",
        path: str = "/home/agent",
    ) -> dict:
        self.mutation_log.append(("attach_volume", volume_name, instance, device, path))
        self._require(instance)
        record = self._volume_records.get(volume_name)
        if record is None:
            raise ValueError(f"unknown volume {volume_name!r}")
        exact = {
            "instance": instance,
            "device": device,
            "path": path,
            "writable": True,
        }
        same_instance = [
            item for item in record["attachments"] if item["instance"] == instance
        ]
        if same_instance and same_instance != [exact]:
            raise ValueError("instance has a contradictory volume attachment")
        if not same_instance:
            record["attachments"].append(exact)
        return self.volume_observation(volume_name)

    def detach_volume(
        self,
        volume_name: str,
        instance: str,
        *,
        device: str = "home",
    ) -> dict:
        self.mutation_log.append(("detach_volume", volume_name, instance, device))
        record = self._volume_records.get(volume_name)
        if record is None:
            raise ValueError(f"unknown volume {volume_name!r}")
        contradictory = [
            item
            for item in record["attachments"]
            if item["instance"] == instance and item["device"] != device
        ]
        if contradictory:
            raise ValueError("volume is attached under a different device")
        record["attachments"] = [
            item
            for item in record["attachments"]
            if not (item["instance"] == instance and item["device"] == device)
        ]
        return self.volume_observation(volume_name)

    # -- quiesced snapshots (issue #14) ----------------------------------

    def _snapshots(self, name: str) -> list:
        inst = self._require(name)
        return inst.setdefault("snapshots", [])

    def exec_quiesce_park(self, name: str, timeout_s: int = 30) -> bool:
        self.mutation_log.append(("exec_quiesce_park", name, timeout_s))
        self._require(name)
        return not self.fail_quiesce

    def exec_quiesce_verify(self, name: str) -> dict:
        self.mutation_log.append(("exec_quiesce_verify", name))
        self._require(name)
        return {
            "checkpoint_files": list(self._quiesce_files),
            "sqlite_ok": not self.fail_verify,
        }

    def exec_unpark(self, name: str) -> bool:
        self.mutation_log.append(("exec_unpark", name))
        self._require(name)
        return True

    def incus_snapshot_create(self, name: str, snap_name: str) -> None:
        self.mutation_log.append(("incus_snapshot_create", name, snap_name))
        snaps = self._snapshots(name)
        if self.fail_capture:
            raise RuntimeError(f"simulated snapshot capture failure for {name!r}")
        if snap_name in snaps:
            raise ValueError(f"snapshot {snap_name!r} already exists on {name!r}")
        snaps.append(snap_name)

    def incus_snapshot_verify(self, name: str, snap_name: str) -> bool:
        self.mutation_log.append(("incus_snapshot_verify", name, snap_name))
        return snap_name in self._snapshots(name)

    def incus_snapshot_list(self, name: str) -> list:
        self.mutation_log.append(("incus_snapshot_list", name))
        return list(self._snapshots(name))

    def incus_snapshot_delete(self, name: str, snap_name: str) -> None:
        self.mutation_log.append(("incus_snapshot_delete", name, snap_name))
        snaps = self._snapshots(name)
        if snap_name in snaps:
            snaps.remove(snap_name)

    def manifest_written(self, name: str, manifest_path: str) -> None:
        self.mutation_log.append(("manifest_write", name, manifest_path))


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
        """Run an incus command, preferring direct socket access.

        Service accounts (e.g. the ``clusterd`` user, group incus-admin)
        reach the incus socket directly — no setuid sudo path, compatible
        with NoNewPrivileges=true. Accounts without the group fall back
        to sudo (interactive operator shells).
        """
        env = dict(os.environ)
        if "/usr/sbin" not in env.get("PATH", "").split(":"):
            env["PATH"] = env.get("PATH", "") + ":/usr/sbin"
        proc = subprocess.run(argv, capture_output=True, text=True, env=env)
        if proc.returncode != 0 and (
                "permissions" in proc.stderr or "unix.socket" in proc.stderr):
            proc = subprocess.run(
                ["sudo", *argv], capture_output=True, text=True, env=env)
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

    # ------------------------------------------------------------------
    # Lifecycle mutations (issue #11)
    # ------------------------------------------------------------------

    def create_instance(self, name: str, image_alias: str, profile: str) -> None:
        # `incus init` creates the container stopped; `clusterctl start`
        # performs the start transition explicitly.
        self._incus("init", image_alias, name, "--profile", profile)

    def start(self, name: str) -> None:
        self._incus("start", name)

    def stop(self, name: str, timeout: int = 30) -> None:
        self._incus("stop", name, "--timeout", str(timeout))

    def restart(self, name: str) -> None:
        self._incus("restart", name)

    def delete(self, name: str) -> None:
        self._incus("delete", name, "--force")

    def logs(self, name: str, max_lines: int) -> str:
        out = self._incus("console", name, "--show-log")
        lines = out.splitlines()
        return "\n".join(lines[-max_lines:]) if max_lines else ""

    def resolve_image(self, image_alias: str) -> str:
        """Resolve a moving alias to the versioned alias of the same image."""
        try:
            images = json.loads(self._incus("image", "list", "--format", "json"))
        except Exception:
            return image_alias
        for img in images:
            aliases = [a.get("name", "") for a in (img.get("aliases") or [])]
            if image_alias in aliases:
                versioned = [a for a in aliases if a and a != image_alias]
                return sorted(versioned, key=len)[0] if versioned else image_alias
        return image_alias

    def profile_budgets(self, profile: str) -> dict:
        """Budgets granted by an incus profile (limits + root disk size)."""
        raw = yaml.safe_load(self._incus("profile", "show", profile)) or {}
        config = raw.get("config") or {}
        memory_bytes = _parse_size_bytes(config.get("limits.memory"))
        return {
            "cpu": _parse_cpu(config.get("limits.cpu")),
            "memory_mib": (memory_bytes // (1024**2)) if memory_bytes is not None else None,
            "disk_gib": _root_disk_gib(raw.get("devices") or {}),
        }

    # ------------------------------------------------------------------
    # Provisioning primitives (issue #12)
    # ------------------------------------------------------------------

    def exec(self, name: str, argv: list[str]) -> str:
        """Run a command inside the instance; return stdout.

        Callers must treat any stdout as potentially sensitive: private
        key material must never be requested, logged, or audited.

        NOTE: cannot use ``_incus`` here — it appends ``--project`` at the
        END of the argv, which lands AFTER ``--`` and gets passed to the
        in-container command instead of to incus. Build the command with
        incus flags before the ``--`` separator.
        """
        cmd = ["incus", "exec"]
        if self.project:
            cmd += ["--project", self.project]
        cmd += [name, "--", *[str(a) for a in argv]]
        return self._runner(cmd)

    def ensure_volume(self, name: str) -> None:
        """Create + attach the durable home volume ``<name>-home`` at /home/agent.

        Idempotent: "already exists" on either step is fine.
        """
        volume = f"{name}-home"
        try:
            self._incus("storage", "volume", "create", "default", volume)
        except IncusError as exc:
            if "already exists" not in str(exc):
                raise
        self.attach_volume(volume, name)

    @staticmethod
    def _volume_instance(used_by: str) -> str | None:
        parsed = urllib.parse.urlsplit(used_by)
        marker = "/instances/"
        if marker not in parsed.path:
            return None
        value = parsed.path.split(marker, 1)[1]
        return urllib.parse.unquote(value) if value else None

    def volume_observation(self, volume_name: str) -> dict:
        try:
            raw = yaml.safe_load(
                self._incus("storage", "volume", "show", "default", volume_name)
            ) or {}
        except IncusError as exc:
            if "not found" in str(exc).lower():
                return {
                    "schema": "cluster-volume-observation/v1",
                    "present": False,
                    "pool": "default",
                    "project": self.project,
                    "name": volume_name,
                    "identity": None,
                    "attachments": [],
                }
            raise
        identity_record = {
            "pool": "default",
            "project": str(raw.get("project") or self.project),
            "name": str(raw.get("name") or volume_name),
            "type": str(raw.get("type") or "custom"),
            "content_type": str(raw.get("content_type") or "filesystem"),
            "created_at": str(raw.get("created_at") or "unknown"),
        }
        identity = "volume:" + hashlib.sha256(
            json.dumps(identity_record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        attachments = []
        for reference in raw.get("used_by") or []:
            instance = self._volume_instance(str(reference))
            if instance is None:
                continue
            devices = yaml.safe_load(
                self._incus("config", "device", "show", instance)
            ) or {}
            matched = False
            for device, config in devices.items():
                if (
                    isinstance(config, dict)
                    and config.get("type") == "disk"
                    and config.get("pool") == "default"
                    and config.get("source") == volume_name
                ):
                    attachments.append(
                        {
                            "instance": instance,
                            "device": str(device),
                            "path": config.get("path"),
                            "writable": str(
                                config.get("readonly") or "false"
                            ).lower() not in {"1", "true", "yes"},
                        }
                    )
                    matched = True
            if not matched:
                attachments.append(
                    {
                        "instance": instance,
                        "device": None,
                        "path": None,
                        "writable": None,
                    }
                )
        return {
            "schema": "cluster-volume-observation/v1",
            "present": True,
            **identity_record,
            "identity": identity,
            "attachments": sorted(
                attachments,
                key=lambda item: (item["instance"], str(item["device"])),
            ),
        }

    def instance_volume_devices(self, instance: str) -> list[dict]:
        devices = yaml.safe_load(
            self._incus("config", "device", "show", instance)
        ) or {}
        result = []
        for device, config in devices.items():
            if not isinstance(config, dict) or config.get("type") != "disk":
                continue
            if "source" not in config:
                continue
            result.append(
                {
                    "device": str(device),
                    "pool": config.get("pool"),
                    "source": config.get("source"),
                    "path": config.get("path"),
                    "writable": str(config.get("readonly") or "false").lower()
                    not in {"1", "true", "yes"},
                }
            )
        return sorted(result, key=lambda item: (item["device"], item["source"]))

    def attach_volume(
        self,
        volume_name: str,
        instance: str,
        *,
        device: str = "home",
        path: str = "/home/agent",
    ) -> dict:
        before = self.volume_observation(volume_name)
        exact = {
            "instance": instance,
            "device": device,
            "path": path,
            "writable": True,
        }
        current = [
            item for item in before.get("attachments", []) if item["instance"] == instance
        ]
        if current == [exact]:
            return before
        if current:
            raise IncusError("instance has a contradictory volume attachment")
        self._incus(
            "storage", "volume", "attach", "default", volume_name,
            instance, device, path,
        )
        return self.volume_observation(volume_name)

    def detach_volume(
        self,
        volume_name: str,
        instance: str,
        *,
        device: str = "home",
    ) -> dict:
        before = self.volume_observation(volume_name)
        current = [
            item for item in before.get("attachments", []) if item["instance"] == instance
        ]
        if not current:
            return before
        if len(current) != 1 or current[0].get("device") != device:
            raise IncusError("volume is attached under a different device")
        self._incus(
            "storage", "volume", "detach", "default", volume_name,
            instance, device,
        )
        return self.volume_observation(volume_name)

    # ------------------------------------------------------------------
    # Quiesced snapshot primitives (issue #14)
    # ------------------------------------------------------------------

    def _exec_rc(self, name: str, argv: list[str]) -> tuple[int, str]:
        """Run a command inside the instance; return (rc, stdout).

        Unlike ``exec`` this does not raise on non-zero rc — pkill uses
        rc 1 for "no processes matched", which is a valid quiesce state.
        """
        rc, out, _ = self._exec_rc_full(name, argv)
        return rc, out

    def _exec_rc_full(self, name: str,
                      argv: list[str]) -> tuple[int, str, str]:
        """Same as _exec_rc but also returns stderr — quiesce failures
        must be diagnosable from the audit trail (drill #26: the daemon
        path failed while every out-of-daemon replica passed, and the
        discarded stderr hid the cause)."""
        cmd = ["incus", "exec"]
        if self.project:
            cmd += ["--project", self.project]
        cmd += [name, "--", *[str(a) for a in argv]]
        env = dict(os.environ)
        if "/usr/sbin" not in env.get("PATH", "").split(":"):
            env["PATH"] = env.get("PATH", "") + ":/usr/sbin"
        # Direct first (incus-admin membership covers the daemon); sudo
        # only as fallback for interactive operator shells — and never
        # unconditionally: under systemd NoNewPrivileges sudo cannot
        # run at all, which silently broke every quiesce verify from
        # the daemon (drill #26, found via this very stderr capture).
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if proc.returncode != 0 and (
                "permissions" in proc.stderr or "unix.socket" in proc.stderr):
            proc = subprocess.run(
                ["sudo", *cmd], capture_output=True, text=True, env=env)
        return proc.returncode, proc.stdout, proc.stderr

    def exec_quiesce_park(self, name: str, timeout_s: int = 30) -> bool:
        """SIGSTOP all hermes processes. rc 0 = parked; rc 1 = no hermes
        processes = parked-clean (fresh daimon); other rc = failure."""
        rc, _ = self._exec_rc(name, ["pkill", "-STOP", "-f", "hermes"])
        return rc in (0, 1)

    def exec_quiesce_verify(self, name: str) -> dict:
        """Checkpoint + integrity-check every library.db in-container.

        Missing files = empty checkpoint list (valid: fresh daimon).
        """
        script = (
            "DIR=/home/agent/.hermes/agent-memory; "
            "FILES=$(find \"$DIR\" \\( -name '*.sqlite*' -o -name 'library.db*' \\) "
            "2>/dev/null || true); "
            "echo '__FILES__'; echo \"$FILES\"; echo '__CHECK__'; "
            "OK=ok; "
            "for db in $(find \"$DIR\" -name 'library.db' 2>/dev/null); do "
            # sqlite3 CLI is NOT in tribe-base; python3 is (hermes needs it).
            "OUT=$(python3 -c 'import sqlite3,sys; "
            "c=sqlite3.connect(sys.argv[1]); "
            "c.execute(\"PRAGMA wal_checkpoint(TRUNCATE)\"); "
            "ok=c.execute(\"PRAGMA integrity_check\").fetchone()[0]; "
            "print(ok); sys.exit(0 if ok==\"ok\" else 1)' \"$db\" 2>&1) || OK=fail; "
            "echo \"$OUT\" | grep -q '^ok$' || OK=fail; "
            "done; "
            "echo \"__RESULT__$OK\""
        )
        rc, out, stderr = self._exec_rc_full(name, ["sh", "-c", script])
        files: list[str] = []
        sqlite_ok = False
        section = None
        for line in out.splitlines():
            if line == "__FILES__":
                section = "files"
                continue
            if line == "__CHECK__":
                section = "check"
                continue
            if line.startswith("__RESULT__"):
                sqlite_ok = line.removeprefix("__RESULT__").strip() == "ok"
                continue
            if section == "files" and line.strip():
                files.append(line.strip())
        if rc != 0:
            sqlite_ok = False
        result = {"checkpoint_files": files, "sqlite_ok": sqlite_ok}
        if not sqlite_ok:
            result["rc"] = rc
            result["stderr_tail"] = stderr.strip()[-300:]
            result["stdout_tail"] = out.strip()[-300:]
        return result

    def exec_unpark(self, name: str) -> bool:
        """SIGCONT all hermes processes. Best effort; rc 0/1 both fine."""
        rc, _ = self._exec_rc(name, ["pkill", "-CONT", "-f", "hermes"])
        return rc in (0, 1)

    def incus_snapshot_create(self, name: str, snap_name: str) -> None:
        self._incus("snapshot", "create", name, snap_name)

    def incus_snapshot_list(self, name: str) -> list[str]:
        raw = json.loads(self._incus("snapshot", "list", name, "--format", "json"))
        return [e.get("name", "") for e in raw if e.get("name")]

    def incus_snapshot_verify(self, name: str, snap_name: str) -> bool:
        """Verified-readable = the snapshot exists in `incus snapshot list`."""
        return snap_name in self.incus_snapshot_list(name)

    def incus_snapshot_delete(self, name: str, snap_name: str) -> None:
        self._incus("snapshot", "delete", name, snap_name)

    def delete_volume(self, name: str) -> None:
        try:
            self._incus("storage", "volume", "delete", "default", f"{name}-home")
        except IncusError:
            pass  # best-effort cleanup during reversal

    def list_volumes(self) -> list[str]:
        """Names of ``custom`` volumes in the ``default`` pool (read-only)."""
        raw = json.loads(self._incus(
            "storage", "volume", "list", "default", "--format", "json"))
        return sorted(
            e.get("name", "") for e in raw
            if e.get("type") == "custom" and e.get("name")
        )
