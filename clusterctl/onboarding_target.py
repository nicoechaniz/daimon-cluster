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
import socket
import struct
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import being_seed, onboarding_code_successor, onboarding_release, onboarding_sdk
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
    def __init__(self, home: Path, plan: dict, genesis: dict, *, code: Path | None = None, code_uid: int = 0):
        self.home = private_directory(home)
        self.plan = validate_plan(plan)
        self.genesis = genesis
        self.root = home / ".local/state/daimon-onboarding" / plan["name"] / "matrix"
        self.preparation = self.root / "preparation"
        self.package = self.root / "package"
        self.credential = self.root / "credential"
        self.code = code if code is not None else Path(__file__).resolve().parents[1]
        self.code_uid = code_uid

    def document_bundle(self) -> dict:
        return document(self.package / "runtime/runtime.json")

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
            if document(self.credential / "candidate.json") != expected:
                raise OnboardingError("existing_onboarding_target_preserved")
            current_receipt = self._credential_receipt(original, expected)
            complete = self.credential / "receipt.json"
            if complete.exists() and document(complete) != current_receipt:
                raise OnboardingError("onboarding_target_runtime_conflict")
            if bundle != expected:
                if (not complete.exists() or not (self.root / 'peer/accepted-private.json').is_file()
                        or set(bundle) != set(expected) or any(bundle[key] != expected[key]
                            for key in expected if key not in {'sources', 'relationships'})):
                    raise OnboardingError('existing_onboarding_target_preserved')
                from .onboarding_peer import augmented
                peer_receipt, peer_complete = augmented(self, expected, bundle)
                return dict(phase='v8' if peer_complete else 'peer-published', request=request, receipt=peer_receipt)
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

    def serve(self, *, receive_only: bool = False, visibility_installation: Path | None = None,
              ready_descriptor: int | None = None) -> int:
        """Hand this body's verified custody to the native single-writer daemon.

        Receive-only is an explicit qualification/initial-admission choice.
        A mirrored body must supply its signed native visibility installation;
        a missing or invalid installation never falls back to closed visibility.
        Process restarts retain the package, authority and native journals.
        """
        from daimon_matrix import daemon
        if receive_only == (visibility_installation is not None):
            raise OnboardingError("onboarding_visibility_selection_required")
        if self.observe()["phase"] != "v8":
            raise OnboardingError("current_onboarding_target_required")
        # Validate/read only this receiving body's existing password. A pipe
        # keeps custody unlock material out of argv, environment and logs.
        password = self._reader()
        reader, writer = os.pipe()
        pipe_identity = os.fstat(reader)
        try:
            os.write(writer, password)
        finally:
            password[:] = b"\x00" * len(password)
            os.close(writer)
        try:
            argv = ["--state-root", str(self.package / "runtime"), "--password-fd", str(reader)]
            if receive_only:
                argv.append("--closed-visibility")
            else:
                argv += ["--visibility-installation", str(visibility_installation)]
            if ready_descriptor is not None:
                argv += ["--ready-fd", str(ready_descriptor)]
            return daemon.main(argv)
        finally:
            # Native startup consumes/closes the FD. Early refusal may not.
            try:
                remaining = os.fstat(reader)
                if (remaining.st_dev, remaining.st_ino) == (pipe_identity.st_dev, pipe_identity.st_ino):
                    os.close(reader)
            except OSError:
                pass

    def running(self, *, admitted: bool = False) -> dict:
        """Observe a kernel-pinned daemon and authenticate its native status.

        This proves owner-local runtime presence, not a Cluster admission lease,
        a resource fence, peer delivery or a model/Telegram acceptance.
        """
        from daimon_matrix.client import ClientConfig, LocalClient
        from .owner_process import ProcessPresence
        prepared = self.observe()
        if prepared["phase"] != "v8":
            raise OnboardingError("current_onboarding_target_required")
        root = self.package / "runtime"
        socket_identity = (root / "matrix.sock").lstat()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(root / "matrix.sock"))
            pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.geteuid():
                raise OnboardingError("onboarding_daemon_owner_conflict")
            process = dict(uid=uid, pid=pid,
                start_ticks=int((Path("/proc") / str(pid) / "stat").read_text().rpartition(")")[2].split()[19]),
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
            with ProcessPresence(process) as presence:
                key = bytearray(onboarding_release.regular(root / "client.key", uid=os.geteuid()))
                config = ClientConfig.load(root / "client.json", key)
                client = LocalClient(root / "matrix.sock", config)
                _, status = client.runtime_status()
                expected = prepared["receipt"]["origin"]
                if status["ok"] is not True or any(status["server"].get(field) != value for field, value in expected.items()):
                    raise OnboardingError("onboarding_daemon_origin_conflict")
                if admitted:
                    _, observed = client.scope_me()
                    body = observed.get('result', {}).get('body', {})
                    if (observed.get('ok') is not True or body.get('state') != 'running'
                            or any(body.get(field) != expected[field] for field in
                                   ('body_ref', 'embodiment_id', 'incarnation_id'))):
                        raise OnboardingError('onboarding_admission_not_current')
                current_socket = (root / "matrix.sock").lstat()
                if (socket_identity.st_dev, socket_identity.st_ino) != (current_socket.st_dev, current_socket.st_ino):
                    raise OnboardingError("onboarding_daemon_socket_changed")
                presence.verify()
                return dict(schema="cluster-onboarding-runtime-presence/v1", plan_digest=digest(self.plan),
                    origin=expected, process=process, runtime_id=config.runtime_id,
                    runtime_sha256=prepared["receipt"]["runtime_sha256"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("sdk-observe", "sdk-prepare", "prepare", "activate", "observe", "credential-prepare", "credential-apply", "serve", "running", "admission-prepare", "admitted-serve", "admission-check", "admission-enroll", "admitted-running", "peer-identity", "peer-accept"))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--credential-response", type=Path)
    parser.add_argument("--admission-profile", type=Path)
    parser.add_argument("--public-profile-json")
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--runtime-code", type=Path)
    parser.add_argument("--runtime-digest")
    parser.add_argument("--peer-packet", type=Path)
    parser.add_argument("--peer-packet-sha256")
    parser.add_argument("--peer-being-ref")
    parser.add_argument("--messaging-application", type=Path)
    visibility = parser.add_mutually_exclusive_group()
    visibility.add_argument("--receive-only", action="store_true")
    visibility.add_argument("--visibility-installation", type=Path)
    parser.add_argument("--ready-fd", type=int)
    args = parser.parse_args(argv)
    try:
        plan = validate_plan(being_seed._read(args.plan))
        runtime = onboarding_code_successor.selection(args.runtime_code, args.runtime_digest,
            args.code, plan['release_digest'], uid=0)
        if args.action == 'sdk-prepare':
            onboarding_sdk.install(args.home, runtime, args.runtime_digest or plan['release_digest'])
            print(json.dumps(dict(ready=True, matrix_commit=onboarding_sdk.MATRIX_COMMIT)))
            return 0
        if args.action == 'sdk-observe':
            try:
                onboarding_sdk.observe(args.home, runtime)
                ready = True
            except FileNotFoundError:
                ready = False
            print(json.dumps(dict(ready=ready, matrix_commit=onboarding_sdk.MATRIX_COMMIT)))
            return 0
        venv = onboarding_sdk.observe(args.home, runtime)
        if Path(sys.prefix) != venv:
            launcher = ("import sys; sys.path.insert(0,sys.argv.pop(1)); "
                        "from clusterctl.onboarding_target import main; raise SystemExit(main())")
            os.execv(venv / "bin/python", [str(venv / "bin/python"), "-B", "-I", "-c", launcher,
                                          str(runtime), *(argv if argv is not None else sys.argv[1:])])
        target = Target(args.home, plan, document(args.genesis), code=runtime)
        if args.action == 'peer-identity':
            from .onboarding_peer import identity
            print(json.dumps(identity(target)))
            return 0
        if args.action == 'peer-accept':
            from .onboarding_peer import accept
            if args.peer_packet is None or args.peer_packet_sha256 is None or args.peer_being_ref is None:
                raise OnboardingError('approved_onboarding_peer_required')
            raw = onboarding_release.regular(args.peer_packet, uid=os.geteuid())
            if hashlib.sha256(raw).hexdigest() != args.peer_packet_sha256:
                raise OnboardingError('approved_onboarding_peer_required')
            print(json.dumps(accept(target, json.loads(raw), expected_being=args.peer_being_ref)))
            return 0
        if args.action == "admitted-serve":
            from .onboarding_runtime import serve
            if args.admission_profile is None:
                raise OnboardingError("onboarding_admission_profile_required")
            return serve(target, document(args.admission_profile), receive_only=args.receive_only,
                visibility_installation=args.visibility_installation, messaging_application=args.messaging_application,
                ready_descriptor=args.ready_fd)
        if args.action == "serve":
            return target.serve(receive_only=args.receive_only, visibility_installation=args.visibility_installation,
                                ready_descriptor=args.ready_fd)
        if args.action in {"running", "admitted-running"}:
            print(json.dumps(target.running(admitted=args.action == 'admitted-running')))
            return 0
        if args.action in {'admission-check', 'admission-enroll'}:
            from .onboarding_admission import ReceivingHolder
            if args.public_profile_json is None or len(args.public_profile_json) > 16384:
                raise OnboardingError('onboarding_admission_profile_required')
            registered = ReceivingHolder(target).ensure_enrolled(json.loads(args.public_profile_json),
                enroll=args.action == 'admission-enroll')
            print(json.dumps(dict(registered=registered)))
            return 0
        if args.action == "admission-prepare":
            from .onboarding_admission import ReceivingHolder
            print(json.dumps(ReceivingHolder(target).request()))
            return 0
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
