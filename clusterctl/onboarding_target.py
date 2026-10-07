"""Receiving-side native target custody and first runtime preparation.

Root custody stays on the host. Only genesis, a body-signed public request and
Root authorization cross this boundary. Preparation never means admission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from . import being_seed, onboarding_release, onboarding_sdk
from .onboarding import OnboardingError, digest, private_directory, validate_plan


def document(path: Path) -> dict:
    raw = onboarding_release.regular(path, uid=os.geteuid(), limit=4 * 1024**2)
    if path.stat().st_mode & 0o077:
        raise OnboardingError("private_onboarding_target_required")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise OnboardingError("invalid_onboarding_target_document")
    return value


def profile(plan: dict) -> dict:
    validate_plan(plan)
    return dict(schema="dm.operator.rebirth-target-profile/v1", label=plan["name"] + "-codex-cluster",
                body_ref="codex:daimon-cluster:" + plan["name"],
                principal_id="principal:codex:daimon-cluster:" + plan["name"],
                listen_host="127.0.0.1", listen_port=8687,
                advertised_endpoint="http://127.0.0.1:8687/dm-peer/v1", targets=[])


class Target:
    def __init__(self, home: Path, plan: dict, genesis: dict):
        self.home = private_directory(home)
        self.plan = validate_plan(plan)
        self.genesis = genesis
        self.root = home / ".local/state/daimon-onboarding" / plan["name"] / "matrix"
        self.preparation = self.root / "preparation"
        self.package = self.root / "package"

    def _reader(self) -> bytearray:
        password = self.root / "body.unlock"
        raw = onboarding_release.regular(password, uid=os.geteuid())
        if password.stat().st_mode & 0o077 or len(raw) != 64:
            raise OnboardingError("private_onboarding_target_required")
        return bytearray(raw)

    def _binding(self) -> dict:
        return dict(schema="cluster-onboarding-target/v1", plan_digest=digest(self.plan),
                    genesis_digest=digest(self.genesis))

    def _validate(self) -> tuple[dict, dict]:
        from daimon_matrix import operator_first_embodiment as first, operator_rebirth
        if document(self.root / "plan.json") != self._binding():
            raise OnboardingError("onboarding_target_binding_conflict")
        prepared, request = document(self.preparation / "preparation.json"), document(self.preparation / "request.json")
        verified, _, _ = operator_rebirth._validated_preparation(self.preparation, prepared, request,
            first._initial_base(self.genesis), self._reader, observed_at_ms=prepared["created_at_ms"], expected_targets=set())
        if verified["profile"] != profile(self.plan):
            raise OnboardingError("onboarding_target_binding_conflict")
        return verified, request

    def prepare(self) -> dict:
        from daimon_matrix import canonical, keystore, operator_first_embodiment as first
        current = self.home
        for part in self.root.relative_to(self.home).parts:
            current /= part
            private_directory(current, create=True)
        with being_seed._locked(self.root):
            record = self.root / "plan.json"
            if not record.exists():
                # The only possible earlier effect is creation of this lock.
                if any(path.name != "lock" and not path.name.startswith(".plan.json.tmp-")
                       for path in self.root.iterdir()):
                    raise OnboardingError("existing_onboarding_target_preserved")
                keystore._atomic_write(record, canonical.canonical_bytes(self._binding()))
            if document(record) != self._binding():
                raise OnboardingError("onboarding_target_binding_conflict")
            password = self.root / "body.unlock"
            if not password.exists():
                if self.preparation.exists() or self.package.exists():
                    raise OnboardingError("existing_onboarding_target_preserved")
                keystore._atomic_write(password, os.urandom(32).hex().encode())
            if not self.preparation.exists():
                first.prepare_target(self.preparation, self.genesis, profile(self.plan), self._reader,
                                     created_at_ms=time.time_ns() // 1_000_000)
            return self._validate()[1]

    def activate(self, activation: dict) -> dict:
        from daimon_matrix import operator_first_embodiment as first
        private_directory(self.root)
        with being_seed._locked(self.root):
            prepared, request = self._validate()
            first.validate_activation(self.genesis, request, activation)
            if not self.package.exists():
                first.activate_runtime(self.package, self.genesis, self.preparation,
                                       prepared, request, activation, self._reader)
            elif document(self.package / "activation.json") != activation:
                raise OnboardingError("existing_onboarding_target_preserved")
            return self.observe()

    def observe(self) -> dict:
        if not self.root.exists() or not self.preparation.exists():
            return dict(phase="absent", request=None, receipt=None)
        _, request = self._validate()
        if not self.package.exists():
            return dict(phase="prepared", request=request, receipt=None)
        from daimon_matrix import canonical, identity, keystore, operator_first_embodiment as first
        activation = document(self.package / "activation.json")
        _, authority = first.validate_activation(self.genesis, request, activation)
        receipt = document(self.package / "receipt.json")
        bundle = document(self.package / "runtime/runtime.json")
        if (receipt["origin"] != request["body"]["origin"] or bundle["local_origin"] != receipt["origin"]
                or bundle["manifest"] != authority.manifest.value
                or receipt["runtime_sha256"] != hashlib.sha256(canonical.canonical_bytes(bundle)).hexdigest()
                or receipt["root_seeds_in_target"] is not False):
            raise OnboardingError("onboarding_target_runtime_conflict")
        store = keystore.EncryptedKeystore(self.package / "runtime/custody.json").open(
            self._reader, minimum_counter=1, required_control_head=authority.state.head)
        signing = store.secrets[bundle["keystore"]["signing_slot"]]
        if identity.signing_descriptor(signing) != activation["body"]["credential"]["body"]["signing_key"]:
            raise OnboardingError("onboarding_target_runtime_conflict")
        return dict(phase="v7", request=request, receipt=receipt)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "activate", "observe"))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--code", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        plan = validate_plan(being_seed._read(args.plan))
        onboarding_release.verify(args.code, plan["release_digest"], uid=0)
        venv = onboarding_sdk.observe(args.home, args.code)
        if Path(sys.prefix) != venv:
            launcher = ("import sys; sys.path.insert(0,sys.argv.pop(1)); "
                        "from clusterctl.onboarding_target import main; raise SystemExit(main())")
            os.execv(venv / "bin/python", [str(venv / "bin/python"), "-B", "-I", "-c", launcher,
                                          str(args.code), *(argv if argv is not None else sys.argv[1:])])
        target = Target(args.home, plan, document(args.genesis))
        if args.action == "prepare":
            target.prepare()
        elif args.action == "activate":
            if args.activation is None:
                raise OnboardingError("onboarding_target_activation_required")
            target.activate(document(args.activation))
        print(json.dumps(target.observe()))
        return 0
    except Exception:
        print(json.dumps({"error": "native_onboarding_target_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
