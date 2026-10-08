"""Existing-Root public handoff; intake cannot issue authority or open custody."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import (
    being_seed,
    onboarding_credential,
    onboarding_existing,
    onboarding_release,
    onboarding_peer,
)
from .onboarding import OnboardingError, digest, private_directory, validate_plan
from .onboarding_custody import document
from .onboarding_local_body import Requests as LocalRequests
from .onboarding_progress import Progress

SOURCE = "cluster-onboarding-existing-source/v1"
HANDOFF = "cluster-onboarding-enrollment-handoff/v1"
REPLY = "cluster-onboarding-enrollment-reply/v1"


def validate_handoff(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema",
            "name",
            "owner",
            "plan_digest",
            "phase",
            "payload",
            "request_digest",
        }
        or value["schema"] != HANDOFF
        or value["phase"] not in {"enrollment", "credential"}
        or any(
            not isinstance(value[k], str) or not being_seed.NAME.fullmatch(value[k])
            for k in ("name", "owner")
        )
        or not isinstance(value["payload"], dict)
        or value["request_digest"] != digest(value["payload"])
        or value["plan_digest"] != digest(validate_plan(value["payload"].get("plan")))
    ):
        raise OnboardingError("invalid_existing_enrollment_handoff")
    return value


class Handoffs(Progress):
    suffix = ".enrollment.json"
    validate = staticmethod(validate_handoff)


def _directory(state: Path, name: str) -> Path:
    if not isinstance(name, str) or not being_seed.NAME.fullmatch(name):
        raise OnboardingError("invalid_onboarding_name")
    parent = state / "existing-enrollment"
    private_directory(parent, create=True)
    return private_directory(parent / name, create=True)


def submit(state: Path, task: dict, handoff: dict | None, value: dict) -> dict:
    """Owner-private evidence only. The host repeats native verification."""
    root = _directory(state, task["name"])
    if isinstance(value, dict) and value.get("schema") == SOURCE:
        if (
            set(value) != {"schema", "request_id", "identity", "routes"}
            or value["request_id"] != task["request_id"]
        ):
            raise being_seed.SeedError("invalid_existing_enrollment_source")
        # Signature and exact Root are checked independently on the host when
        # the frozen plan exists. Never accept a runtime or a custody object.
        if not isinstance(value["identity"], dict) or set(value["identity"]) != {
            "document",
            "binding",
        }:
            raise being_seed.SeedError("invalid_existing_enrollment_source")
        if not isinstance(value["routes"], list) or any(
            not isinstance(row, dict)
            or set(row) != {"embodiment_id", "endpoint", "timeout_ms"}
            for row in value["routes"]
        ):
            raise being_seed.SeedError("invalid_existing_enrollment_source")
        try:
            authority = onboarding_peer.native(
                Path(__file__).resolve().parents[1], uid=Path(__file__).stat().st_uid
            ).verify_identity(value["identity"])
            if authority.state.being_ref != task["expected_being_ref"]:
                raise ValueError
        except Exception:
            raise being_seed.SeedError(
                "existing_being_signed_identity_required"
            ) from None
        destination = root / "source.json"
    else:
        if (
            handoff is None
            or not isinstance(value, dict)
            or set(value) != {"schema", "request_digest", "response"}
            or value["schema"] != REPLY
            or value["request_digest"] != handoff["request_digest"]
            or not isinstance(value["response"], dict)
        ):
            raise being_seed.SeedError("invalid_existing_enrollment_reply")
        destination = root / (value["request_digest"] + ".json")
        try:
            validate_handoff(handoff)
            from daimon_matrix import operator_rebirth

            payload = handoff["payload"]
            plan = payload["plan"]
            base = operator_rebirth.authority_from_runtime_bundle(
                onboarding_existing.public_base_bundle(payload["base"], plan)
            )
            response = value["response"]
            if handoff["phase"] == "enrollment":
                if set(response) != {"shares"} or not isinstance(
                    response["shares"], list
                ):
                    raise ValueError
                operator_rebirth.aggregate_distributed_enrollment(
                    payload["intent"],
                    payload["target_request"],
                    base,
                    response["shares"],
                    observed_at_ms=time.time_ns() // 1_000_000,
                )
            else:
                previous = operator_rebirth.validate_activation(
                    payload["activation"], base, request=payload["target_request"]
                )[1]
                onboarding_credential.verify_response(
                    previous, plan, payload["request"], response
                )
        except Exception:
            raise being_seed.SeedError(
                "existing_enrollment_signed_reply_required"
            ) from None
    if len(json.dumps(value).encode()) > being_seed.MAX_RECORD:
        raise being_seed.SeedError("existing_enrollment_input_too_large")
    with being_seed._locked(root):
        if destination.exists():
            if being_seed._read(destination) != value:
                if destination.name != "source.json" or handoff is not None:
                    raise being_seed.SeedError(
                        "existing_enrollment_input_preserved", 409
                    )
                # Preserve corrected discovery evidence before the host freezes
                # a plan. Old public submissions remain content-addressed.
                prior = being_seed._read(destination)
                being_seed._write(root / (digest(prior) + ".source.json"), prior)
                being_seed._write(destination, value)
        else:
            being_seed._write(destination, value)
    return {"stored": True, "host_verified": False}


class ExistingEnrollment:
    """Host-owned native authority adapter. No local or imported Root seeds."""

    def __init__(self, host):
        self.host, self.config = host, host.config
        if any(
            getattr(self.config, key) is None
            for key in ("custody", "consent_state", "progress")
        ):
            raise OnboardingError("identity_authorization_required")
        self.root = private_directory(self.config.custody / "existing", create=True)

    def authorize(self, plan: dict) -> bool:
        selection = self.host._decision(plan)
        return selection is not None and selection["matrix_identity_mode"] == "existing"

    def _path(self, plan: dict) -> Path:
        if not self.authorize(plan):
            raise OnboardingError("identity_authorization_required")
        return self.root / digest(validate_plan(plan))

    def _read_intake(self, name: str, filename: str) -> dict:
        root = self.config.consent_state / "existing-enrollment" / name
        for path in (root.parent, root):
            being_seed._path(path)
            info = path.stat()
            if (
                not path.is_dir()
                or info.st_uid != self.config.consent_uid
                or info.st_mode & 0o077
            ):
                raise OnboardingError("private_onboarding_consent_required")
        path = root / filename
        raw = onboarding_release.regular(
            path, uid=self.config.consent_uid, limit=being_seed.MAX_RECORD
        )
        if path.stat().st_mode & 0o077:
            raise OnboardingError("private_onboarding_consent_required")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise OnboardingError("invalid_existing_enrollment_input")
        return value

    def prepare(self, plan: dict, *, identity_mode: str) -> None:
        if identity_mode != "existing":
            raise OnboardingError("identity_authorization_required")
        root = private_directory(self._path(plan), create=True)
        with being_seed._locked(root):
            if (root / "genesis.json").exists():
                onboarding_existing.validate_base(document(root / "genesis.json"), plan)
                return
            task = LocalRequests(self.config.progress, worker_uid=os.geteuid()).read(
                plan["name"], owner=plan["owner"]
            )
            source = self._read_intake(plan["name"], "source.json")
            if (
                set(source) != {"schema", "request_id", "identity", "routes"}
                or source["schema"] != SOURCE
                or source["request_id"] != task["request_id"]
                or task["expected_being_ref"] is None
            ):
                raise OnboardingError("existing_onboarding_base_rejected")
            base = onboarding_existing.base_packet(
                plan,
                source["identity"],
                source["routes"],
                expected_being_ref=task["expected_being_ref"],
            )
            self._publish(root / "plan.json", plan)
            self._publish(root / "genesis.json", base)

    @staticmethod
    def _publish(path: Path, value: dict) -> None:
        from daimon_matrix import canonical, keystore

        if path.exists():
            if document(path) != value:
                raise OnboardingError("existing_enrollment_checkpoint_preserved")
        else:
            keystore._atomic_write(path, canonical.canonical_bytes(value))

    def observe(self, plan: dict) -> dict | None:
        root = self._path(plan)
        if not (root / "genesis.json").exists():
            try:
                self._read_intake(plan["name"], "source.json")
            except FileNotFoundError:
                return {"waiting": True}
            return None
        onboarding_existing.validate_base(document(root / "genesis.json"), plan)
        try:
            handoff = Handoffs(self.config.progress, worker_uid=os.geteuid()).read(
                plan["name"], owner=plan["owner"]
            )
        except FileNotFoundError:
            return {"waiting": False, "ready": True}
        phase = handoff["phase"]
        completed = root / (
            "target-activation.json"
            if phase == "enrollment"
            else "credential-response.json"
        )
        if completed.exists():
            return {"waiting": False, "ready": True}
        if (
            phase == "enrollment"
            and time.time_ns() // 1_000_000
            >= handoff["payload"]["intent"]["body"]["expires_at_ms"]
        ):
            # Expiry needs another public challenge, not another identity or
            # renewed consent. Execution retains the original receiving keys.
            return {"waiting": False, "ready": True}
        try:
            self._read_intake(plan["name"], handoff["request_digest"] + ".json")
        except FileNotFoundError:
            return {"waiting": True, "ready": True}
        return {"waiting": False, "ready": True}

    def _exchange(self, plan: dict, phase: str, payload: dict) -> dict | None:
        frame = dict(
            schema=HANDOFF,
            name=plan["name"],
            owner=plan["owner"],
            plan_digest=digest(plan),
            phase=phase,
            payload=payload,
            request_digest=digest(payload),
        )
        Handoffs(self.config.progress, worker_uid=os.geteuid()).publish(frame)
        try:
            reply = self._read_intake(plan["name"], frame["request_digest"] + ".json")
        except FileNotFoundError:
            return None
        if (
            set(reply) != {"schema", "request_digest", "response"}
            or reply["schema"] != REPLY
            or reply["request_digest"] != frame["request_digest"]
        ):
            raise OnboardingError("invalid_existing_enrollment_reply")
        return reply["response"]

    def authorize_target(self, plan: dict, request: dict) -> dict | None:
        from daimon_matrix import operator_rebirth

        root = self._path(plan)
        with being_seed._locked(root):
            base = document(root / "genesis.json")
            authority = operator_rebirth.authority_from_runtime_bundle(
                onboarding_existing.public_base_bundle(base, plan)
            )
            now = time.time_ns() // 1_000_000
            verified = operator_rebirth.validate_enrollment_request(
                request, authority, observed_at_ms=now
            )
            if (
                verified["body"]["origin"]["body_ref"]
                != "codex:daimon-cluster:" + plan["name"]
            ):
                raise OnboardingError("onboarding_target_binding_conflict")
            request_path = root / "target-request.json"
            if request_path.exists() and document(request_path) != request:
                prior = document(request_path)
                def stable(value):
                    return {k: v for k, v in value["body"].items() if k not in {"expires_at_ms", "nonce"}}
                if ((root / "target-activation.json").exists()
                        or now < prior["body"]["expires_at_ms"] or stable(prior) != stable(request)):
                    raise OnboardingError("existing_enrollment_checkpoint_preserved")
                self._publish(root / (digest(prior) + ".expired-request.json"), prior)
                from daimon_matrix import canonical, keystore
                keystore._atomic_write(request_path, canonical.canonical_bytes(request))
            else:
                self._publish(request_path, request)
            path = root / "target-activation.json"
            if path.exists():
                result = document(path)
                operator_rebirth.validate_activation(result, authority, request=request)
                return result
            intent_path = root / "target-intent.json"
            if intent_path.exists():
                prior = document(intent_path)
                if now >= prior["body"]["expires_at_ms"] or prior["body"]["activation_body"]["request_id"] != request["request_id"]:
                    self._publish(
                        root / (digest(prior) + ".expired-intent.json"), prior
                    )
                    from daimon_matrix import canonical, keystore

                    successor = operator_rebirth.create_distributed_enrollment_intent(
                        request,
                        authority,
                        issued_at_ms=now,
                        expires_at_ms=now + 24 * 3600000,
                        nonce=os.urandom(32),
                    )
                    keystore._atomic_write(
                        intent_path, canonical.canonical_bytes(successor)
                    )
            if not (root / "target-intent.json").exists():
                verified = operator_rebirth.validate_enrollment_request(
                    request, authority, observed_at_ms=now
                )
                if (
                    verified["body"]["origin"]["body_ref"]
                    != "codex:daimon-cluster:" + plan["name"]
                ):
                    raise OnboardingError("onboarding_target_binding_conflict")
                self._publish(
                    root / "target-intent.json",
                    operator_rebirth.create_distributed_enrollment_intent(
                        request,
                        authority,
                        issued_at_ms=now,
                        expires_at_ms=now + 24 * 3600000,
                        nonce=os.urandom(32),
                    ),
                )
            intent = document(root / "target-intent.json")
            response = self._exchange(
                plan,
                "enrollment",
                dict(plan=plan, base=base, target_request=request, intent=intent),
            )
            if response is None:
                return None
            # Every share and the threshold are verified by native rebirth.
            if set(response) != {"shares"} or not isinstance(response["shares"], list):
                raise OnboardingError("invalid_existing_enrollment_reply")
            activation = operator_rebirth.aggregate_distributed_enrollment(
                intent, request, authority, response["shares"], observed_at_ms=now
            )
            self._publish(path, activation)
            return activation

    def _previous(self, plan: dict):
        from daimon_matrix import operator_rebirth

        root = self._path(plan)
        base = document(root / "genesis.json")
        authority = operator_rebirth.authority_from_runtime_bundle(
            onboarding_existing.public_base_bundle(base, plan)
        )
        return operator_rebirth.validate_activation(
            document(root / "target-activation.json"),
            authority,
            request=document(root / "target-request.json"),
        )[1]

    def authorize_credential(self, plan: dict, request: dict) -> dict | None:
        root = self._path(plan)
        with being_seed._locked(root):
            previous = self._previous(plan)
            onboarding_credential.validate_request(
                previous, plan, request, observed_at_ms=time.time_ns() // 1_000_000
            )
            self._publish(root / "credential-request.json", request)
            path = root / "credential-response.json"
            result: dict | None
            if path.exists():
                result = document(path)
            else:
                result = self._exchange(
                    plan,
                    "credential",
                    dict(
                        plan=plan,
                        base=document(root / "genesis.json"),
                        target_request=document(root / "target-request.json"),
                        activation=document(root / "target-activation.json"),
                        request=request,
                    ),
                )
                if result is None:
                    return None
            onboarding_credential.verify_response(previous, plan, request, result)
            self._publish(path, result)
            return result

    def admission_coordinates(self, plan: dict) -> dict:
        from daimon_matrix import identity

        root = self._path(plan)
        with being_seed._locked(root):
            request = document(root / "credential-request.json")
            current = onboarding_credential.verify_response(
                self._previous(plan),
                plan,
                request,
                document(root / "credential-response.json"),
            )
            origin = request["origin"]
            current.validate_origin(origin, require_active=True)
            member = current.manifest.member(
                origin["embodiment_id"], origin["incarnation_id"]
            )
            credential = current.credentials[member["embodiment_credential_id"]]
            now = time.time_ns() // 1_000_000
            identity.verify_embodiment_credential(credential, current.state, at_ms=now)
            identity.verify_incarnation_authorization(
                current.incarnations[member["incarnation_authorization_id"]],
                credential,
                current.state,
                at_ms=now,
            )
            return dict(
                being_ref=current.manifest.being_ref,
                body_ref=origin["body_ref"],
                embodiment_id=origin["embodiment_id"],
                incarnation_id=origin["incarnation_id"],
                activation_id=document(root / "target-activation.json")[
                    "activation_id"
                ],
                credential_id=credential["artifact_id"],
                manifest_hash=current.manifest.digest,
            )
