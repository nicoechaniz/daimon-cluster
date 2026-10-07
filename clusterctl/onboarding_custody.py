"""Resumable native first-genesis ceremony under a separate custody grant.

Holder commands run in separate native processes; aggregation opens no holder.
Participant consent and a resource grant do not issue this custody grant.
Existing being identities are handled by native enrollment, never this ceremony.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from . import being_seed
from .onboarding import OnboardingError, digest, private_directory, validate_plan

GRANT_SCHEMA = "cluster-onboarding-custody-grant/v1"
ROLES = ["root", "recovery", "backup", "restore"]
POLICY_SCHEMA = "cluster-onboarding-custody-policy/v1"


class CustodyPolicy:
    """Operator authorization combined with the pair's exact published review.

    The operator supplies actual attribution digests. HTTP cannot supply them
    or enable custody. The decision digest binds this grant to the preserved
    authenticated owner instruction; an old inheritance-only review cannot
    authorize custody and an existing identity cannot enter first genesis.
    """
    def __init__(self, path: Path):
        self.value = document(path)
        value = self.value
        if (set(value) != {"schema", "execution_uid", "source_binding_digest",
                          "operator_instruction_digest", "roles", "revoked"}
                or value["schema"] != POLICY_SCHEMA
                or type(value["execution_uid"]) is not int or value["execution_uid"] != os.geteuid()
                or any(not isinstance(value[key], str) or not re.fullmatch(r"[0-9a-f]{64}", value[key])
                       for key in ("source_binding_digest", "operator_instruction_digest"))
                or value["roles"] != ROLES or type(value["revoked"]) is not bool):
            raise OnboardingError("invalid_onboarding_custody_policy")

    def review(self) -> dict:
        from .onboarding_consent import CUSTODY_NOTICE
        return dict(policy_digest=digest(self.value), notice=CUSTODY_NOTICE)

    def issue(self, plan: dict, proposal: dict, decision: dict, grants: Path) -> None:
        from .onboarding_consent import _expected, validate_review
        validate_review(proposal)
        selection = {key: decision.get(key) for key in (
            "review_digest", "inheritance_approved", "matrix_identity_mode")}
        if (self.value["revoked"] or proposal.get("matrix_custody") != self.review()
                or proposal["plan"] != validate_plan(plan)
                or _expected(proposal, selection) != decision):
            raise OnboardingError("identity_authorization_required")
        if decision["matrix_identity_mode"] != "first":
            return
        private_directory(grants)
        grant = dict(schema=GRANT_SCHEMA, plan_digest=digest(plan), ceremony="first-matrix-identity",
            execution_uid=os.geteuid(), source_binding_digest=self.value["source_binding_digest"],
            owner_instruction_digest=digest(decision), roles=ROLES, revoked=False)
        path = grants / (plan["name"] + ".json")
        if path.exists():
            if document(path) != grant:
                raise OnboardingError("existing_onboarding_custody_preserved")
        else:
            being_seed._write(path, grant)


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
        staging = None
        public_output = None
        try:
            command = [sys.executable, "-B", "-I", "-m", "daimon_matrix.operator_genesis", *arguments]
            if arguments[0] == "first-embodiment":
                command = [sys.executable, "-B", "-I", "-m", "daimon_matrix.operator_first_embodiment", *arguments[1:]]
            if arguments[0] == "backup-restore":
                launcher = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                            "from clusterctl.onboarding_holder_backup import main; raise SystemExit(main())")
                command = [sys.executable, "-B", "-I", "-c", launcher,
                           str(Path(__file__).resolve().parents[1]), *arguments[1:]]
            if arguments[0] == "credential-response":
                launcher = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                            "from clusterctl.onboarding_credential import main; raise SystemExit(main())")
                command = [sys.executable, "-B", "-I", "-c", launcher,
                           str(Path(__file__).resolve().parents[1]), *arguments[1:]]
            public_command = (arguments[0] in {"create-intent", "sign", "aggregate"}
                              or arguments[0] == "credential-response"
                              or arguments[:2] in [["first-embodiment", "root-share"],
                                                   ["first-embodiment", "aggregate"]])
            if public_command:
                index = command.index("--output") + 1
                candidate = being_seed._path(Path(command[index]))
                if not candidate.exists():
                    private_directory(candidate.parent)
                    staging = Path(tempfile.mkdtemp(prefix=".native-public-", dir=candidate.parent))
                    public_output = candidate
                    command[index] = str(staging / "result.json")
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
            if staging is not None and public_output is not None:
                # Native public-output CLIs write a small document directly.
                # Their incomplete output must never become a live checkpoint.
                # The enclosing custody lock owns publication; a completed
                # existing document is compared, never overwritten on retry.
                from daimon_matrix import canonical, keystore
                value = document(staging / "result.json")
                if public_output.exists():
                    if document(public_output) != value:
                        raise OnboardingError("existing_onboarding_custody_preserved")
                else:
                    keystore._atomic_write(public_output, canonical.canonical_bytes(value))
        except (OSError, subprocess.TimeoutExpired):
            raise OnboardingError("native_onboarding_custody_refused") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if staging is not None:
                shutil.rmtree(staging)

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
        backup_verified = self._observe_backups(root, plan, value)
        return {"schema": "cluster-onboarding-genesis-receipt/v1", "plan_digest": digest(plan),
                "being_ref": state.being_ref, "control_head": state.head,
                "genesis_digest": digest(value), "holder_roles": ["root", "recovery"],
                "enrolled": False, "backup_restore_verified": backup_verified}

    @staticmethod
    def _observe_backups(root: Path, plan: dict, genesis: dict) -> bool:
        from daimon_matrix import operator_genesis
        from .onboarding_holder_backup import BACKUP_SCHEMA, inventory

        witnesses = []
        for role in ("root", "recovery"):
            receipt_path = root / (role + "-backup-receipt.json")
            if not receipt_path.exists():
                return False
            receipt = document(receipt_path)
            descriptor = document(root / role / "descriptor.json")
            witness = document(root / ("restored-" + role + "-share.json"))
            expected = {"schema": BACKUP_SCHEMA, "plan_digest": digest(plan), "role": role,
                        "key_id": descriptor["key"]["key_id"], "counter": 1,
                        "control_head": operator_genesis.PENDING_CONTROL_HEAD,
                        "files": inventory(root / role), "witness_digest": digest(witness)}
            if (receipt != expected or inventory(root / ("backup-" + role)) != expected["files"]
                    or inventory(root / ("restore-" + role)) != expected["files"]):
                raise OnboardingError("onboarding_holder_backup_conflict")
            witnesses.append(witness)
        if operator_genesis.aggregate_intent(document(root / "intent.json"), witnesses) != genesis:
            raise OnboardingError("onboarding_holder_backup_conflict")
        return True

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
            for role in ("root", "recovery"):
                self._dispatch(plan, ["backup-restore", "--ceremony-root", str(root), "--role", role],
                               root / (role + ".unlock"))
            result = self.observe(plan)
            if result is None:
                raise OnboardingError("native_onboarding_custody_refused")
            return result

    def authorize_target(self, plan: dict, request: dict) -> dict:
        """Authorize one public, body-signed target request; never open its keys.

        The guest generates and retains target custody. This side receives only
        the public enrollment request, and returns public Root authorization.
        Canonical/physical admission remains a later observed effect.
        """
        observed = self.observe(plan)
        if observed is None or not observed["backup_restore_verified"]:
            raise OnboardingError("verified_onboarding_custody_required")
        from daimon_matrix import canonical, keystore, operator_first_embodiment as first, operator_rebirth

        root = self._path(plan)
        with being_seed._locked(root):
            request_path = root / "target-request.json"
            if request_path.exists() and document(request_path) != request:
                raise OnboardingError("existing_onboarding_target_preserved")
            genesis = document(root / "genesis.json")
            activation_path = root / "target-activation.json"
            if activation_path.exists():
                activation = document(activation_path)
                first.validate_activation(genesis, request, activation)
                expected = first.aggregate_activation(genesis, request,
                    [document(root / "target-root-share.json")],
                    observed_at_ms=activation["body"]["issued_at_ms"])
                if expected != activation:
                    raise OnboardingError("onboarding_target_activation_conflict")
                return activation
            verified = operator_rebirth.validate_enrollment_request(request, first._initial_base(genesis),
                observed_at_ms=time.time_ns() // 1_000_000)
            if verified["body"]["origin"]["body_ref"] != "codex:daimon-cluster:" + plan["name"]:
                raise OnboardingError("onboarding_target_binding_conflict")
            if not request_path.exists():
                # Native enrollment CLIs require canonical document bytes.
                keystore._atomic_write(request_path, canonical.canonical_bytes(verified))
            # Root is the sole holder process; the target and Recovery packages
            # are neither present in argv nor opened by this ceremony.
            self._dispatch(plan, ["first-embodiment", "root-share", "--genesis", str(root / "genesis.json"),
                "--request", str(request_path), "--holder", str(root / "root"),
                "--output", str(root / "target-root-share.json")], root / "root.unlock")
            self._dispatch(plan, ["first-embodiment", "aggregate", "--genesis", str(root / "genesis.json"),
                "--request", str(request_path), "--share", str(root / "target-root-share.json"),
                "--output", str(activation_path)])
            activation = document(activation_path)
            first.validate_activation(genesis, request, activation)
            return activation

    def authorize_credential(self, plan: dict, request: dict) -> dict:
        """Co-sign native V2 succession in a Root-only subprocess for this target."""
        from daimon_matrix import canonical, keystore, operator_first_embodiment as first
        from . import onboarding_credential

        if not self.authorize(plan):
            raise OnboardingError("identity_authorization_required")
        root = self._path(plan)
        with being_seed._locked(root):
            _, previous = first.validate_activation(document(root / "genesis.json"),
                document(root / "target-request.json"), document(root / "target-activation.json"))
            request_path, response_path = root / "credential-request.json", root / "credential-response.json"
            if request_path.exists() and document(request_path) != request:
                raise OnboardingError("existing_onboarding_credential_preserved")
            if response_path.exists():
                response = document(response_path)
                onboarding_credential.verify_response(previous, plan, request, response)
                return response
            onboarding_credential.validate_request(previous, plan, request,
                observed_at_ms=time.time_ns() // 1_000_000)
            if not request_path.exists():
                keystore._atomic_write(request_path, canonical.canonical_bytes(request))
            self._dispatch(plan, ["credential-response", "--plan", str(root / "plan.json"),
                "--genesis", str(root / "genesis.json"), "--target-request", str(root / "target-request.json"),
                "--activation", str(root / "target-activation.json"), "--request", str(request_path),
                "--holder", str(root / "root"), "--output", str(response_path)], root / "root.unlock")
            response = document(response_path)
            onboarding_credential.verify_response(previous, plan, request, response)
            return response

    def admission_coordinates(self, plan: dict) -> dict:
        """Derive the host registrar's expected binding from native public proofs.

        No receiving key, holder key or online Root custody is opened here.
        The separate host custody grant still authorizes use of this ceremony.
        """
        from daimon_matrix import identity, operator_first_embodiment as first
        from . import onboarding_credential
        if not self.authorize(plan):
            raise OnboardingError("identity_authorization_required")
        root = self._path(plan)
        with being_seed._locked(root):
            activation = document(root / "target-activation.json")
            _, previous = first.validate_activation(document(root / "genesis.json"),
                document(root / "target-request.json"), activation)
            request, response = document(root / "credential-request.json"), document(root / "credential-response.json")
            current = onboarding_credential.verify_response(previous, plan, request, response)
            origin = request["origin"]
            current.validate_origin(origin, require_active=True)
            member = current.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
            credential = current.credentials[member["embodiment_credential_id"]]
            now = time.time_ns() // 1_000_000
            identity.verify_embodiment_credential(credential, current.state, at_ms=now)
            identity.verify_incarnation_authorization(current.incarnations[member["incarnation_authorization_id"]],
                credential, current.state, at_ms=now)
            return dict(being_ref=current.manifest.being_ref, body_ref=origin["body_ref"],
                embodiment_id=origin["embodiment_id"], incarnation_id=origin["incarnation_id"],
                activation_id=activation["activation_id"], credential_id=credential["artifact_id"],
                manifest_hash=current.manifest.digest)
