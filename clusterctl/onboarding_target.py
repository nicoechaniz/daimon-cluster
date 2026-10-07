"""Receiving-side native target custody and first runtime preparation.

Root custody stays on the host. Only genesis, a body-signed public request and
Root authorization cross this boundary. Preparation never means admission.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

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
        self.credential = self.root / "credential"

    def _reader(self) -> bytearray:
        password = self.root / "body.unlock"
        raw = onboarding_release.regular(password, uid=os.geteuid())
        if password.stat().st_mode & 0o077 or len(raw) != 64:
            raise OnboardingError("private_onboarding_target_required")
        return bytearray(raw)

    def _binding(self) -> dict:
        return dict(schema="cluster-onboarding-target/v1", plan_digest=digest(self.plan),
                    genesis_digest=digest(self.genesis))

    @contextmanager
    def _runtime_writer(self) -> Iterator[None]:
        from daimon_matrix import daemon
        descriptor = daemon.acquire_lock(self.package / "runtime")
        try:
            yield
        finally:
            os.close(descriptor)

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
        original = document(self.credential / "original.json") if (self.credential / "original.json").exists() else bundle
        if (receipt["origin"] != request["body"]["origin"] or bundle["local_origin"] != receipt["origin"]
                or original["manifest"] != authority.manifest.value
                or receipt["runtime_sha256"] != hashlib.sha256(canonical.canonical_bytes(original)).hexdigest()
                or receipt["root_seeds_in_target"] is not False):
            raise OnboardingError("onboarding_target_runtime_conflict")
        store = keystore.EncryptedKeystore(self.package / "runtime/custody.json").open(
            self._reader, minimum_counter=1, required_control_head=authority.state.head)
        signing = store.secrets[bundle["keystore"]["signing_slot"]]
        if identity.signing_descriptor(signing) != activation["body"]["credential"]["body"]["signing_key"]:
            raise OnboardingError("onboarding_target_runtime_conflict")
        if bundle != original:
            expected = self._credential_bundle(original, document(self.credential / "response.json"))
            if bundle != expected or document(self.credential / "candidate.json") != expected:
                raise OnboardingError("existing_onboarding_target_preserved")
            current_receipt = self._credential_receipt(original, expected)
            complete = self.credential / "receipt.json"
            if complete.exists() and document(complete) != current_receipt:
                raise OnboardingError("onboarding_target_runtime_conflict")
            return dict(phase="v8" if complete.exists() else "v8-published", request=request, receipt=current_receipt)
        return dict(phase="v7", request=request, receipt=receipt)

    def credential_request(self) -> dict:
        """Persist one Body-accepted native proposal before contacting Root."""
        from daimon_matrix import canonical, keystore, operator_rebirth
        from . import onboarding_credential
        private_directory(self.root)
        with being_seed._locked(self.root), self._runtime_writer():
            observed = self.observe()
            if observed["phase"] not in {"v7", "v8-published", "v8"}:
                raise OnboardingError("prepared_onboarding_target_required")
            private_directory(self.credential, create=True)
            original_path = self.credential / "original.json"
            if not original_path.exists():
                keystore._atomic_write(original_path, canonical.canonical_bytes(document(self.package / "runtime/runtime.json")))
            original = document(original_path)
            previous = operator_rebirth.authority_from_runtime_bundle(original)
            request_path = self.credential / "request.json"
            if not request_path.exists():
                if any((self.credential / name).exists() for name in ("response.json", "candidate.json", "receipt.json")):
                    raise OnboardingError("existing_onboarding_target_preserved")
                store = keystore.EncryptedKeystore(self.package / "runtime/custody.json").open(
                    self._reader, minimum_counter=1, required_control_head=previous.state.head)
                signing = store.secrets[original["keystore"]["signing_slot"]]
                request = onboarding_credential.receiving_request(previous, original["local_origin"], self.plan, signing,
                    issued_at_ms=time.time_ns() // 1_000_000)
                keystore._atomic_write(request_path, canonical.canonical_bytes(request))
            request = document(request_path)
            onboarding_credential.validate_request(previous, self.plan, request, observed_at_ms=request["issued_at_ms"])
            return request

    def _credential_bundle(self, original: dict, response: dict) -> dict:
        from daimon_matrix import operator_rebirth
        from . import onboarding_credential
        previous = operator_rebirth.authority_from_runtime_bundle(original)
        request = document(self.credential / "request.json")
        successor = onboarding_credential.verify_response(previous, self.plan, request, response)
        result = copy.deepcopy(original)
        result.update(schema="dm.runtime.bundle/v8", manifest=response["manifest"],
            credentials=list(successor.credentials.values()), incarnations=list(successor.incarnations.values()),
            authority_history=[*original["authority_history"],
                               {"manifest": previous.manifest.value, "successor": response["succession"]}])
        operator_rebirth.authority_from_runtime_bundle(result)
        return result

    def _credential_receipt(self, original: dict, candidate: dict) -> dict:
        from daimon_matrix import canonical
        return dict(schema="cluster-onboarding-credential-receipt/v1", plan_digest=digest(self.plan),
            origin=candidate["local_origin"], original_runtime_sha256=hashlib.sha256(canonical.canonical_bytes(original)).hexdigest(),
            runtime_sha256=hashlib.sha256(canonical.canonical_bytes(candidate)).hexdigest(),
            response_digest=digest(document(self.credential / "response.json")))

    def apply_credential(self, response: dict) -> dict:
        """Publish only the exact native successor while the runtime is stopped."""
        from daimon_matrix import canonical, daemon, keystore, native_egress, runtime
        private_directory(self.credential)
        with being_seed._locked(self.root):
            self.observe()
            original = document(self.credential / "original.json")
            candidate = self._credential_bundle(original, response)
            descriptor = daemon.acquire_lock(self.package / "runtime")
            try:
                current = self.package / "runtime/runtime.json"
                if document(current) not in (original, candidate):
                    raise OnboardingError("existing_onboarding_target_preserved")
                for name, value in (("response.json", response), ("candidate.json", candidate)):
                    path = self.credential / name
                    if path.exists():
                        if document(path) != value:
                            raise OnboardingError("existing_onboarding_target_preserved")
                    else:
                        keystore._atomic_write(path, canonical.canonical_bytes(value))
                if document(current) == original:
                    keystore._atomic_write(current, canonical.canonical_bytes(candidate))
                receipt = self._credential_receipt(original, candidate)
                marker = self.credential / "receipt.json"
                if marker.exists():
                    if document(marker) != receipt:
                        raise OnboardingError("existing_onboarding_target_preserved")
                else:
                    def clock() -> int:
                        return time.time_ns() // 1_000_000
                    hosted = runtime.load_runtime(self.package / "runtime", "runtime.json", self._reader, clock=clock,
                        egress=native_egress.closed_visibility(clock=clock, catalog_mode="migrate"))
                    hosted.egress.migrate_registered_catalogs(version=native_egress.VISIBILITY_SCHEMA_VERSION)
                    hosted.egress.validate_registered_catalogs()
                    keystore._atomic_write(marker, canonical.canonical_bytes(receipt))
                return self.observe()
            finally:
                os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "activate", "observe", "credential-prepare", "credential-apply"))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--credential-response", type=Path)
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
        elif args.action == "credential-apply":
            if args.credential_response is None:
                raise OnboardingError("onboarding_target_activation_required")
            target.apply_credential(document(args.credential_response))
        result = target.observe()
        if args.action == "credential-prepare":
            result["request"] = target.credential_request()
        print(json.dumps(result))
        return 0
    except Exception:
        print(json.dumps({"error": "native_onboarding_target_refused"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
