"""Private existing-Root signer; never transport holder files to the host."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from . import onboarding_credential, onboarding_existing
from .onboarding import OnboardingError, digest
from .onboarding_custody import document
from .onboarding_enrollment import REPLY, ExistingEnrollment, validate_handoff


def sign(
    frame: dict, holder: Path, password_reader, *, root_custody: bool = False
) -> dict:
    """One native isolated holder process. Receiving keys are never inputs."""
    from daimon_matrix import operator_rebirth

    validate_handoff(frame)
    payload = frame["payload"]
    plan = payload["plan"]
    fields = (
        {"plan", "base", "target_request", "intent"}
        if frame["phase"] == "enrollment"
        else {"plan", "base", "target_request", "activation", "request"}
    )
    if (
        set(payload) != fields
        or frame["name"] != plan["name"]
        or frame["owner"] != plan["owner"]
    ):
        raise OnboardingError("invalid_existing_enrollment_handoff")
    base = onboarding_existing.public_base_bundle(payload["base"], plan)
    authority = operator_rebirth.authority_from_runtime_bundle(base)
    now = time.time_ns() // 1_000_000
    request = operator_rebirth.validate_enrollment_request(
        payload["target_request"], authority, observed_at_ms=now
    )
    if request["body"]["origin"]["body_ref"] != "codex:daimon-cluster:" + plan["name"]:
        raise OnboardingError("onboarding_target_binding_conflict")
    seed = None
    if root_custody:
        from daimon_matrix import keystore

        contents = keystore.EncryptedKeystore(holder).open(
            password_reader,
            minimum_counter=1,
            required_control_head=authority.state.head,
        )
        # The native historical offline Root store stays local and intact.
        # Runtime Body slots cannot be used as Root authority.
        if any(
            not slot.startswith(("root.signing.v1:", "recovery.signing.v1:"))
            for slot in contents.secrets
        ):
            raise OnboardingError("existing_enrollment_root_custody_rejected")
        seeds = operator_rebirth._exact_custody_role_seeds(
            contents.secrets,
            prefix="root.signing.v1:",
            policy=authority.state.root_policy,
            code="existing_enrollment_root_custody_rejected",
        )
        if authority.state.root_policy["threshold"] != 1 or not seeds:
            raise OnboardingError("existing_enrollment_root_threshold_unsupported")
        seed = seeds[0]
    if frame["phase"] == "enrollment":
        if root_custody:
            share = operator_rebirth.create_distributed_enrollment_share(
                payload["intent"], request, authority, seed, observed_at_ms=now
            )
        else:
            share = operator_rebirth.create_distributed_enrollment_share_from_holder(
                payload["intent"],
                request,
                authority,
                holder,
                password_reader,
                observed_at_ms=now,
            )
        response = {"shares": [share]}
    else:
        previous = operator_rebirth.validate_activation(
            payload["activation"], authority, request=request
        )[1]
        onboarding_credential.validate_request(
            previous, plan, payload["request"], observed_at_ms=now
        )
        # Native holder resolution verifies that the local key is in this
        # actual Root policy. No capability or source-body private key is read.
        if not root_custody:
            seed = operator_rebirth._single_holder_seed(
                holder,
                authority,
                password_reader,
                allowed_prefixes=("root.signing.v1:",),
                code="existing_enrollment_holder_rejected",
            )
        if not isinstance(seed, bytes):
            raise OnboardingError("existing_enrollment_root_custody_rejected")
        response = onboarding_credential.root_response(
            previous, plan, payload["request"], seed, observed_at_ms=now
        )
    return dict(schema=REPLY, request_digest=digest(payload), response=response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("handoff", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    custody = parser.add_mutually_exclusive_group(required=True)
    custody.add_argument("--holder", type=Path)
    custody.add_argument("--root-custody", type=Path)
    parser.add_argument("--password-fd", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        from daimon_matrix import operator_first_embodiment as first

        reply = sign(
            document(args.handoff),
            args.holder if args.holder is not None else args.root_custody,
            lambda: first._password(args.password_fd),
            root_custody=args.root_custody is not None,
        )
        ExistingEnrollment._publish(args.output, reply)
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
