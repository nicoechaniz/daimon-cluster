"""Host-owned onboarding configuration and exact Incus body reconciliation.

Neither participant labels nor files writable by intake authorize execution.
Only an owner-local grant of the exact plan is accepted. Guest stages use the
maintained installer; no command from a source archive is executed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import being_seed, onboarding_consent, onboarding_input, onboarding_mounts, onboarding_release
from .onboarding_custody import FirstCustody
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
    inputs: Path | None = None
    code: Path | None = None
    views: Path | None = None
    consent_state: Path | None = None
    consent_uid: int | None = None
    qualification: bool = False
    custody: Path | None = None
    custody_grants: Path | None = None

    @classmethod
    def load(cls, path: Path) -> HostConfig:
        value = being_seed._read(path)
        consent_keys = {"consent_state", "consent_uid"}
        custody_keys = {"custody", "custody_grants"}
        if (set(value) - consent_keys - custody_keys - {"qualification"} != {"schema", "jobs", "grants", "progress", "native_image", "browser_image",
                           "release_digest", "pool", "profile", "concurrency", "inputs", "code", "views"}
                or value.get("schema") != "cluster-onboarding-host/v1"
                or any(not sha(value[key]) for key in ("native_image", "browser_image", "release_digest"))
                or any(not isinstance(value[key], str) or not being_seed.NAME.fullmatch(value[key])
                       for key in ("pool", "profile"))
                or type(value["concurrency"]) is not int or not 1 <= value["concurrency"] <= 8
                or type(value.get("qualification", False)) is not bool):
            raise OnboardingError("invalid_onboarding_host_configuration")
        directories = {}
        for key in ("jobs", "grants", "inputs", "views"):
            if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                raise OnboardingError("invalid_onboarding_host_configuration")
            directories[key] = private_directory(Path(value[key]))
        if len(set(directories.values())) != len(directories):
            raise OnboardingError("invalid_onboarding_host_configuration")
        if not isinstance(value["progress"], str) or not Path(value["progress"]).is_absolute():
            raise OnboardingError("invalid_onboarding_host_configuration")
        progress = Path(value["progress"])
        Progress(progress, worker_uid=progress.stat().st_uid)._directory()
        if progress.stat().st_uid != path.stat().st_uid or progress in directories.values():
            raise OnboardingError("invalid_onboarding_host_configuration")
        if not isinstance(value["code"], str) or not Path(value["code"]).is_absolute():
            raise OnboardingError("invalid_onboarding_host_configuration")
        code = Path(value["code"])
        onboarding_release.verify(code, value["release_digest"], uid=path.stat().st_uid)
        consent_state, consent_uid = None, None
        if consent_keys & set(value):
            if (not consent_keys <= set(value) or not isinstance(value["consent_state"], str)
                    or not Path(value["consent_state"]).is_absolute()
                    or type(value["consent_uid"]) is not int or value["consent_uid"] < 0):
                raise OnboardingError("invalid_onboarding_host_configuration")
            consent_state, consent_uid = being_seed._path(Path(value["consent_state"])), value["consent_uid"]
            info = consent_state.stat()
            if info.st_uid != consent_uid or info.st_mode & 0o077 or not consent_state.is_dir():
                raise OnboardingError("invalid_onboarding_host_configuration")
        custody, custody_grants = None, None
        if custody_keys & set(value):
            if not custody_keys <= set(value) or consent_state is None:
                raise OnboardingError("invalid_onboarding_host_configuration")
            for key in custody_keys:
                if not isinstance(value[key], str) or not Path(value[key]).is_absolute():
                    raise OnboardingError("invalid_onboarding_host_configuration")
                private_directory(Path(value[key]))
            custody, custody_grants = Path(value["custody"]), Path(value["custody_grants"])
            boundaries = set(directories.values()) | {progress, consent_state, code}
            if (any(path == other or path.is_relative_to(other) or other.is_relative_to(path)
                    for path in (custody, custody_grants) for other in boundaries)
                    or custody == custody_grants or custody.is_relative_to(custody_grants)
                    or custody_grants.is_relative_to(custody)):
                raise OnboardingError("separate_onboarding_custody_required")
        return cls(directories["jobs"], directories["grants"], value["native_image"],
                   value["browser_image"], value["release_digest"], value["pool"],
                   value["profile"], value["concurrency"], progress, directories["inputs"], code, directories["views"],
                   consent_state, consent_uid, value.get("qualification", False), custody, custody_grants)

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
        if stage in {"context", "matrix"} and not self._consented(plan, stage=stage):
            return Observation("waiting", reason="identity_authorization_required")
        if stage in {"context", "memory"} and self.config.code and self.config.inputs and self.config.views:
            return self._guest_observe(plan, stage)
        if stage == "matrix" and self.config.custody and self.config.custody_grants:
            ceremony = FirstCustody(self.config.custody, self.config.custody_grants)
            decision = self._decision(plan)
            if decision is None or decision["matrix_identity_mode"] != "first" or not ceremony.authorize(plan):
                return Observation("waiting", reason="identity_authorization_required")
            observed = ceremony.observe(plan)
            if observed is None or not observed["backup_restore_verified"]:
                return Observation("absent", safe_to_execute=True)
            # Genesis custody is not a body enrollment. Native target preparation,
            # restore and physical admission must finish before this stage does.
            return Observation("waiting", reason="backend_unavailable")
        # Do not invent success for native enrollment or receiving acceptance.
        # The remaining typed stage adapters are added with their actual tests.
        reason = {"matrix": "identity_authorization_required", "access": "account_authorization_required",
                  "acceptance": "human_contact_required"}.get(stage, "backend_unavailable")
        return Observation("waiting", reason=reason)

    def execute(self, plan: dict, stage: str, operation_id: str) -> None:
        if not self.authorize(plan, digest(plan)):
            raise OnboardingError("host_authorization_required")
        if stage in {"context", "matrix"} and not self._consented(plan, stage=stage):
            raise OnboardingError("identity_authorization_required")
        if stage in {"context", "memory"} and self.config.code and self.config.inputs and self.config.views:
            self._guest_execute(plan, stage)
            return
        if stage == "matrix" and self.config.custody and self.config.custody_grants:
            decision = self._decision(plan)
            if decision is None:
                raise OnboardingError("identity_authorization_required")
            FirstCustody(self.config.custody, self.config.custody_grants).prepare(
                plan, identity_mode=decision["matrix_identity_mode"])
            return
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

    def _consented(self, plan: dict, *, stage: str) -> bool:
        # Disposable context-only qualification has no participant decision.
        # A deployed host config supplies the private intake boundary.
        if self.config.consent_state is None:
            return stage == "context" and self.config.qualification and plan["name"].startswith("qualify-")
        return self._decision(plan) is not None

    def _decision(self, plan: dict) -> dict | None:
        if self.config.consent_uid is None or self.config.progress is None or self.config.code is None:
            raise OnboardingError("invalid_onboarding_host_configuration")
        onboarding_release.verify(self.config.code, plan["release_digest"], uid=os.geteuid())
        proposal = onboarding_consent.review(plan, (self.config.code / "inheritance.md").read_text())
        reviews = onboarding_consent.Reviews(self.config.progress, worker_uid=os.geteuid())
        try:
            existing = reviews.read(plan["name"], owner=plan["owner"])
        except FileNotFoundError:
            existing = None
        if existing != proposal:
            reviews.publish(proposal)
        if self.config.consent_state is None:
            raise OnboardingError("invalid_onboarding_host_configuration")
        return onboarding_consent.read(self.config.consent_state, proposal, intake_uid=self.config.consent_uid)

    def _guest_paths(self, plan: dict) -> tuple[Path, Path, dict]:
        if self.config.code is None or self.config.inputs is None or self.config.views is None:
            raise OnboardingError("receiving_code_configuration_required")
        onboarding_release.verify(self.config.code, plan["release_digest"], uid=os.geteuid())
        source = self.config.inputs / plan["name"]
        onboarding_input.verify(source, plan["seed_digest"])
        view = self.config.views / digest(plan) / "input"
        guest_code = Path("/opt/daimon-onboarding") / plan["release_digest"]
        mounts = {
            "onboarding-code": dict(type="disk", source=str(self.config.code), path=str(guest_code), readonly="true", shift="true"),
            "onboarding-input": dict(type="disk", source=str(view), path="/home/agent/.onboarding-input", readonly="true", shift="true"),
        }
        return source, guest_code, mounts

    def _mounted(self, plan: dict, mounts: dict) -> bool:
        instances, _ = self._inventory()
        row = next(row for row in instances if row.get("name") == self.instance(plan))
        devices = row.get("expanded_devices", {})
        for name, expected in mounts.items():
            if name in devices and devices[name] != expected:
                raise OnboardingError("foreign_receiving_mount_preserved")
        return all(name in devices for name in mounts)

    def _guest_command(self, plan: dict, action: str, stage: str, guest_code: Path) -> str:
        # Only qualified receiving code runs. No command from the seed or
        # inherited home, model output, or HTTP string reaches this argv.
        launcher = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                    "from clusterctl.onboarding_guest import main; raise SystemExit(main())")
        incoming = "/home/agent/.onboarding-input"
        return self._dispatch(plan, ["exec", self.instance(plan), "--user", "1000", "--group", "1000",
            "--env", "HOME=/home/agent", "--", "python3", "-B", "-I", "-c", launcher, str(guest_code),
            action, stage, "--home", "/home/agent", "--input", incoming,
            "--code", str(guest_code), "--plan", incoming + "/plan.json"])

    def _guest_observe(self, plan: dict, stage: str) -> Observation:
        if self._environment(plan).state != "complete":
            return Observation("waiting", reason="backend_unavailable")
        _, guest_code, mounts = self._guest_paths(plan)
        if not self._mounted(plan, mounts):
            return Observation("absent", safe_to_execute=True) if stage == "context" else Observation("waiting", reason="backend_unavailable")
        value = json.loads(self._guest_command(plan, "observe", stage, guest_code))
        if not isinstance(value, dict) or set(value) != {"state", "facts", "reason", "safe_to_execute"}:
            raise OnboardingError("invalid_onboarding_observation")
        observed = Observation(**value)
        observed.validate()
        return observed

    def _guest_execute(self, plan: dict, stage: str) -> None:
        if self._environment(plan).state != "complete":
            raise OnboardingError("qualified_guest_environment_required")
        source, guest_code, mounts = self._guest_paths(plan)
        if stage == "context":
            assert self.config.views is not None
            onboarding_mounts.prepare_view(source, self.config.views, plan)
            instances, _ = self._inventory()
            row = next(row for row in instances if row.get("name") == self.instance(plan))
            # Code first: its typed bootstrap owns just the new empty home.
            for name in ("onboarding-code", "onboarding-input"):
                if name == "onboarding-input":
                    launcher = ("import sys; sys.path.insert(0, sys.argv[1]); "
                                "from clusterctl.onboarding_mounts import bootstrap_home; bootstrap_home()")
                    self._dispatch(plan, ["exec", self.instance(plan), "--", "python3", "-B", "-I", "-c", launcher, str(guest_code)])
                current = row.get("expanded_devices", {}).get(name)
                if current is not None and current != mounts[name]:
                    raise OnboardingError("foreign_receiving_mount_preserved")
                if current is None:
                    device = mounts[name]
                    self._dispatch(plan, ["config", "device", "add", self.instance(plan), name, "disk",
                        *[key + "=" + value for key, value in device.items() if key != "type"]])
        self._guest_command(plan, "execute", stage, guest_code)

    def _dispatch(self, plan: dict, argv: list[str]) -> str:
        # A revoked plan stops before the next concrete effect, including
        # revocation while an earlier long Incus operation was in flight.
        if not self.authorize(plan, digest(plan)):
            raise OnboardingError("host_authorization_required")
        return self.run(argv)
