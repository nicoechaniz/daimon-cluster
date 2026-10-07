"""Resumable native first-genesis ceremony under a separate custody grant.

Holder commands run in separate native processes; aggregation opens no holder.
Participant consent and a resource grant do not issue this custody grant.
Existing being identities are handled by native enrollment, never this ceremony.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory, validate_plan

GRANT_SCHEMA = "cluster-onboarding-custody-grant/v1"
ROLES = ["root", "recovery", "backup", "restore"]


def document(path: Path) -> dict:
    being_seed._path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or not 0 < info.st_size <= 4 * 1024**2):
            raise OnboardingError("private_onboarding_custody_required")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise OnboardingError("invalid_onboarding_custody_document")
    return value


class FirstCustody:
    def __init__(self, root: Path, grants: Path, *, run: Callable | None = None):
        self.root = private_directory(root)
        self.grants = private_directory(grants)
        if (self.root == self.grants or self.root.is_relative_to(self.grants)
                or self.grants.is_relative_to(self.root)):
            raise OnboardingError("separate_onboarding_custody_required")
        self.run = run or self._run

    def authorize(self, plan: dict) -> bool:
        validate_plan(plan)
        try:
            grant = being_seed._read(self.grants / (plan["name"] + ".json"))
        except FileNotFoundError:
            return False
        fields = {"schema", "plan_digest", "ceremony", "execution_uid", "source_binding_digest",
                  "owner_instruction_digest", "roles", "revoked"}
        return (set(grant) == fields and grant["schema"] == GRANT_SCHEMA
                and grant["plan_digest"] == digest(plan)
                and grant["ceremony"] == "first-matrix-identity"
                and type(grant["execution_uid"]) is int and grant["execution_uid"] == os.geteuid()
                and all(isinstance(grant[key], str) and re.fullmatch(r"[0-9a-f]{64}", grant[key])
                        for key in ("source_binding_digest", "owner_instruction_digest"))
                and grant["roles"] == ROLES and grant["revoked"] is False)

    @staticmethod
    def _run(arguments: list[str], password: Path | None) -> None:
        # Exact installed SDK validation precedes any key command. Neither
        # password nor native output/diagnostics enters a public projection.
        from .matrix_host import _matrix_api

        _matrix_api()
        descriptor = -1
        try:
            command = [sys.executable, "-B", "-I", "-m", "daimon_matrix.operator_genesis", *arguments]
            if password is not None:
                descriptor = os.open(being_seed._path(password), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != 64):
                    raise OnboardingError("private_onboarding_custody_required")
                command += ["--password-fd", str(descriptor)]
            result = subprocess.run(command, pass_fds=(descriptor,) if descriptor >= 0 else (),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env={"PATH": os.defpath, "LANG": "C.UTF-8",
                                         "LD_LIBRARY_PATH": str(Path(sys.base_prefix) / "lib")},
                                    timeout=120, check=False)
            if result.returncode:
                raise OnboardingError("native_onboarding_custody_refused")
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError("native_onboarding_custody_refused") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _dispatch(self, plan: dict, arguments: list[str], password: Path | None = None) -> None:
        if not self.authorize(plan):
            raise OnboardingError("identity_authorization_required")
        self.run(arguments, password)

    def _path(self, plan: dict) -> Path:
        return self.root / digest(validate_plan(plan))

    @staticmethod
    def _unrecorded(root: Path) -> bool:
        # No holder operation runs before the fsynced plan. Preserve interrupted
        # plan temporaries; they do not name another identity or authorize keys.
        for path in root.iterdir():
            if path.name != "lock" and not re.fullmatch(r"plan\.json\.[0-9a-f]{32}", path.name):
                return False
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                return False
        return True

    @staticmethod
    def _reconcile_unlock(root: Path, role: str) -> None:
        password = root / (role + ".unlock")
        if not password.exists():
            return
        info = password.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise OnboardingError("private_onboarding_custody_required")
        if info.st_nlink == 1:
            return
        aliases = []
        for candidate in root.glob("." + role + ".unlock-*"):
            row = candidate.lstat()
            if ((row.st_dev, row.st_ino) == (info.st_dev, info.st_ino)
                    and re.fullmatch(r"\." + role + r"\.unlock-[0-9a-f]{16}", candidate.name)):
                aliases.append(candidate)
        if info.st_nlink != 2 or len(aliases) != 1:
            raise OnboardingError("private_onboarding_custody_required")
        aliases[0].unlink()
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_intent(root: Path) -> None:
        from daimon_matrix import canonical, operator_genesis

        intent = document(root / "intent.json")
        prepared = intent.get("prepared_genesis", {})
        try:
            body = prepared["body"]
            expected = operator_genesis.create_intent(
                [document(root / role / "descriptor.json") for role in ("root", "recovery")],
                root_threshold=1, recovery_threshold=1, created_at_ms=body["created_at_ms"],
                nonce=canonical.unb64url(body["core"]["nonce"], length=32))
            if canonical.canonical_bytes(intent) != canonical.canonical_bytes(expected):
                raise ValueError("different ceremony")
        except (KeyError, TypeError, ValueError):
            raise OnboardingError("onboarding_custody_intent_conflict") from None

    def observe(self, plan: dict) -> dict | None:
        if not self.authorize(plan):
            raise OnboardingError("identity_authorization_required")
        root = self._path(plan)
        if not root.exists():
            return None
        private_directory(root)
        if not (root / "plan.json").exists():
            if self._unrecorded(root):
                return None
            raise OnboardingError("onboarding_custody_plan_conflict")
        if being_seed._read(root / "plan.json") != plan:
            raise OnboardingError("onboarding_custody_plan_conflict")
        if not (root / "genesis.json").exists():
            return None
        from daimon_matrix import identity, operator_genesis

        self._validate_intent(root)
        value = document(root / "genesis.json")
        expected = operator_genesis.aggregate_intent(document(root / "intent.json"),
            [document(root / (role + "-share.json")) for role in ("root", "recovery")])
        if expected != value:
            raise OnboardingError("onboarding_custody_genesis_conflict")
        state = identity.verify_genesis(value)
        return {"schema": "cluster-onboarding-genesis-receipt/v1", "plan_digest": digest(plan),
                "being_ref": state.being_ref, "control_head": state.head,
                "genesis_digest": digest(value), "holder_roles": ["root", "recovery"],
                "enrolled": False, "backup_restore_verified": False}

    def prepare(self, plan: dict, *, identity_mode: str) -> dict:
        # Never infer absence of identity from an archive lacking runtime keys.
        if identity_mode != "first" or not self.authorize(plan):
            raise OnboardingError("identity_authorization_required")
        root = self._path(plan)
        private_directory(root, create=True)
        with being_seed._locked(root):
            record = root / "plan.json"
            if record.exists():
                if being_seed._read(record) != plan:
                    raise OnboardingError("onboarding_custody_plan_conflict")
            else:
                # If the initial mkdir survived a crash, only its lock may exist.
                if not self._unrecorded(root):
                    raise OnboardingError("onboarding_custody_plan_conflict")
                being_seed._write(record, plan)
            for role in ("root", "recovery"):
                if not self.authorize(plan):
                    raise OnboardingError("identity_authorization_required")
                password = root / (role + ".unlock")
                if not password.exists():
                    if (root / role).exists():
                        raise OnboardingError("existing_onboarding_custody_preserved")
                    # This is the custody unlock path, separate from encrypted
                    # backup material. It is never returned or passed in argv.
                    temporary = root / ("." + role + ".unlock-" + os.urandom(8).hex())
                    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    try:
                        with os.fdopen(descriptor, "wb") as stream:
                            stream.write(os.urandom(32).hex().encode())
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.link(temporary, password, follow_symlinks=False)
                    finally:
                        temporary.unlink(missing_ok=True)
                    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                self._reconcile_unlock(root, role)
                self._dispatch(plan, ["create-holder", "--role", role, "--output", str(root / role)], password)
            if not (root / "intent.json").exists():
                self._dispatch(plan, ["create-intent", "--descriptor", str(root / "root/descriptor.json"),
                    "--descriptor", str(root / "recovery/descriptor.json"), "--root-threshold", "1",
                    "--recovery-threshold", "1", "--output", str(root / "intent.json")])
            self._validate_intent(root)
            for role in ("root", "recovery"):
                self._dispatch(plan, ["sign", "--intent", str(root / "intent.json"), "--holder", str(root / role),
                    "--output", str(root / (role + "-share.json"))], root / (role + ".unlock"))
            self._dispatch(plan, ["aggregate", "--intent", str(root / "intent.json"),
                "--share", str(root / "root-share.json"), "--share", str(root / "recovery-share.json"),
                "--output", str(root / "genesis.json")])
            result = self.observe(plan)
            if result is None:
                raise OnboardingError("native_onboarding_custody_refused")
            return result
