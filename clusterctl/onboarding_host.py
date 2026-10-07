"""Host-owned onboarding configuration and exact Incus body reconciliation.

Neither participant labels nor files writable by intake authorize execution.
Only an owner-local grant of the exact plan is accepted. Guest stages use the
maintained installer; no command from a source archive is executed.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import being_seed
from .onboarding import Observation, OnboardingError, digest, private_directory, validate_plan
from .onboarding_progress import Progress


def sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class HostConfig:
    jobs: Path
    grants: Path
    native_image: str
    browser_image: str
    release_digest: str
    pool: str
    profile: str
    concurrency: int
    progress: Path | None = None

    @classmethod
    def load(cls, path: Path) -> HostConfig:
        value = being_seed._read(path)
        if (set(value) != {"schema", "jobs", "grants", "progress", "native_image", "browser_image",
                           "release_digest", "pool", "profile", "concurrency"}
                or value.get("schema") != "cluster-onboarding-host/v1"
                or any(not sha(value[key]) for key in ("native_image", "browser_image", "release_digest"))
                or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                       for key in ("pool", "profile"))
                or type(value["concurrency"]) is not int or not 1 <= value["concurrency"] <= 8):
            raise OnboardingError("invalid_onboarding_host_configuration")
        directories = {}
        for key in ("jobs", "grants"):
            if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                raise OnboardingError("invalid_onboarding_host_configuration")
            directories[key] = private_directory(Path(value[key]))
        if directories["jobs"] == directories["grants"]:
            raise OnboardingError("invalid_onboarding_host_configuration")
        if not isinstance(value["progress"], str) or not Path(value["progress"]).is_absolute():
            raise OnboardingError("invalid_onboarding_host_configuration")
        progress = Path(value["progress"])
        Progress(progress, worker_uid=progress.stat().st_uid)._directory()
        if progress.stat().st_uid != path.stat().st_uid or progress in directories.values():
            raise OnboardingError("invalid_onboarding_host_configuration")
        return cls(directories["jobs"], directories["grants"], value["native_image"],
                   value["browser_image"], value["release_digest"], value["pool"],
                   value["profile"], value["concurrency"], progress)

    def approved_plans(self) -> list[dict]:
        private_directory(self.grants)
        plans = []
        for path in sorted(self.grants.iterdir()):
            if path.suffix != ".json" or not being_seed.NAME.fullmatch(path.stem):
                continue
            try:
                grant = being_seed._read(path)
                plan = validate_plan(grant["plan"])
                if plan["name"] == path.stem and HostBackend(self).authorize(plan, digest(plan)):
                    plans.append(plan)
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return plans


class HostBackend:
    def __init__(self, config: HostConfig, *, run: Callable | None = None):
        self.config = config
        self.run = run or self._run

    @staticmethod
    def _run(argv: list[str]) -> str:
        # No shell, no source-supplied program, and never leak captured stderr.
        try:
            result = subprocess.run(["incus", *argv], capture_output=True, text=True,
                                    timeout=1800, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError("onboarding_host_operation_failed") from None
        if result.returncode:
            raise OnboardingError("onboarding_host_operation_failed")
        return result.stdout

    def authorize(self, plan: dict, plan_digest: str) -> bool:
        if digest(validate_plan(plan)) != plan_digest or plan["release_digest"] != self.config.release_digest:
            return False
        try:
            private_directory(self.config.grants)
            grant = being_seed._read(self.config.grants / (plan["name"] + ".json"))
        except (OSError, ValueError):
            return False
        return (set(grant) == {"schema", "plan", "revoked"}
                and grant.get("schema") == "cluster-onboarding-host-grant/v1"
                and grant.get("plan") == plan and grant.get("revoked") is False)

    @staticmethod
    def instance(plan: dict) -> str:
        # This namespace cannot name an existing administrative account/body.
        return "dm-" + plan["name"]

    def _inventory(self) -> tuple[list, list]:
        instances = json.loads(self.run(["list", "--format=json"]))
        volumes = json.loads(self.run(["storage", "volume", "list", self.config.pool, "--format=json"]))
        if not isinstance(instances, list) or not isinstance(volumes, list):
            raise OnboardingError("invalid_onboarding_environment_observation")
        return instances, volumes

    def _environment(self, plan: dict) -> Observation:
        instances, volumes = self._inventory()
        name, fingerprint = self.instance(plan), digest(plan)
        rows = [row for row in instances if row.get("name") == name]
        homes = [row for row in volumes if row.get("name") == name + "-home" and row.get("type") == "custom"]
        if len(rows) > 1 or len(homes) > 1:
            return Observation("conflict", reason="observed_state_conflict")
        if homes:
            home = json.loads(self.run(["query", "/1.0/storage-pools/" + self.config.pool
                                        + "/volumes/custom/" + name + "-home"]))
            if (home.get("config", {}).get("user.dm.onboarding-plan") != fingerprint
                    or home.get("config", {}).get("size") != "22GiB"):
                return Observation("conflict", reason="observed_state_conflict")
        if not rows:
            return Observation("absent", safe_to_execute=True)
        row = rows[0]
        config = row.get("config", {})
        expected_image = self.config.browser_image if plan["browser"] else self.config.native_image
        if (config.get("user.dm.onboarding-plan") != fingerprint
                or config.get("volatile.base_image") != expected_image):
            return Observation("conflict", reason="observed_state_conflict")
        devices = row.get("expanded_devices", {})
        root = devices.get("root", {})
        if root != {"type": "disk", "path": "/", "pool": self.config.pool, "size": "8GiB"}:
            return Observation("conflict", reason="observed_state_conflict")
        attached = devices.get("home")
        expected_home = {"type": "disk", "path": "/home/agent", "pool": self.config.pool, "source": name + "-home"}
        if attached is not None and attached != expected_home:
            return Observation("conflict", reason="observed_state_conflict")
        if not homes or attached is None or row.get("status") == "Stopped":
            return Observation("absent", safe_to_execute=True)
        if row.get("status") != "Running":
            return Observation("uncertain", reason="uncertain_external_effect")
        return Observation("complete", {"verified": True, "root_gib": 8, "home_gib": 22})

    def observe(self, plan: dict, stage: str, operation_id: str) -> Observation:
        if not self.authorize(plan, digest(plan)):
            return Observation("waiting", reason="host_authorization_required")
        if stage == "environment":
            return self._environment(plan)
        # Do not invent success for native enrollment or receiving acceptance.
        # The remaining typed stage adapters are added with their actual tests.
        reason = {"matrix": "identity_authorization_required", "access": "account_authorization_required",
                  "acceptance": "human_contact_required"}.get(stage, "backend_unavailable")
        return Observation("waiting", reason=reason)

    def execute(self, plan: dict, stage: str, operation_id: str) -> None:
        if not self.authorize(plan, digest(plan)):
            raise OnboardingError("host_authorization_required")
        if stage != "environment":
            raise OnboardingError("unsupported_onboarding_host_stage")
        observed = self._environment(plan)
        if observed.state == "complete":
            return
        if observed.state != "absent" or not observed.safe_to_execute:
            raise OnboardingError("onboarding_environment_conflict")
        instances, volumes = self._inventory()
        name, fingerprint = self.instance(plan), digest(plan)
        if not any(row.get("name") == name for row in instances):
            image = self.config.browser_image if plan["browser"] else self.config.native_image
            self._dispatch(plan, ["init", image, name, "--profile", self.config.profile,
                      "--storage", self.config.pool, "--device", "root,size=8GiB",
                      "--config", "user.dm.onboarding-plan=" + fingerprint])
        if not any(row.get("name") == name + "-home" and row.get("type") == "custom" for row in volumes):
            self._dispatch(plan, ["storage", "volume", "create", self.config.pool, name + "-home",
                      "size=22GiB", "user.dm.onboarding-plan=" + fingerprint])
        instances, _ = self._inventory()
        row = next(row for row in instances if row.get("name") == name)
        if "home" not in row.get("expanded_devices", {}):
            self._dispatch(plan, ["config", "device", "add", name, "home", "disk", "pool=" + self.config.pool,
                      "source=" + name + "-home", "path=/home/agent"])
        if row.get("status") == "Stopped":
            self._dispatch(plan, ["start", name])

    def _dispatch(self, plan: dict, argv: list[str]) -> str:
        # A revoked plan stops before the next concrete effect, including
        # revocation while an earlier long Incus operation was in flight.
        if not self.authorize(plan, digest(plan)):
            raise OnboardingError("host_authorization_required")
        return self.run(argv)
