"""Native same-Root enrollment from a verified public body identity.

This base projection carries signed authority and explicit peer routes only.
It is not an installed runtime or a source of credentials/capabilities. Native
rebirth creates all target custody and verifies every authority transition.
"""

from __future__ import annotations

import copy
from pathlib import Path

from . import onboarding_peer
from .onboarding import OnboardingError, digest, validate_plan
from .onboarding_target import profile

BASE = "cluster-onboarding-existing-base/v1"


def base_packet(
    plan: dict, identity: dict, routes: list[dict], *, expected_being_ref: str
) -> dict:
    value = dict(
        schema=BASE,
        plan_digest=digest(validate_plan(plan)),
        expected_being_ref=expected_being_ref,
        identity=copy.deepcopy(identity),
        routes=copy.deepcopy(routes),
    )
    validate_base(value, plan)
    return value


def validate_base(value: dict, plan: dict) -> dict:
    from daimon_matrix import operator_rebirth

    try:
        if (
            not isinstance(value, dict)
            or set(value)
            != {"schema", "plan_digest", "expected_being_ref", "identity", "routes"}
            or value["schema"] != BASE
            or value["plan_digest"] != digest(validate_plan(plan))
        ):
            raise ValueError("binding")
        authority = onboarding_peer.native(
            Path(__file__).resolve().parents[1], uid=Path(__file__).stat().st_uid
        ).verify_identity(value["identity"])
        if authority.state.being_ref != value["expected_being_ref"]:
            raise ValueError("existing being")
        # The maintained receiving V2 co-signature adapter currently signs
        # one Root key. Refuse an unsupported policy before creating a body.
        if authority.state.root_policy["threshold"] != 1:
            raise ValueError("unsupported credential threshold")
        if any(
            row["body_ref"] == profile(plan)["body_ref"]
            for row in authority.manifest.value["embodiments"]
        ):
            raise ValueError("body already enrolled")
        selected = {**profile(plan), "targets": value["routes"]}
        normalized = operator_rebirth._target_profile(selected, authority.active)
        if normalized["targets"] != value["routes"]:
            raise ValueError("canonical routes")
        return value
    except Exception:
        raise OnboardingError("existing_onboarding_base_rejected") from None


def target_profile(value: dict, plan: dict) -> dict:
    validate_base(value, plan)
    return {**profile(plan), "targets": copy.deepcopy(value["routes"])}


def public_base_bundle(value: dict, plan: dict) -> dict:
    """A keyless native base projection; never copy a source runtime file."""
    from daimon_matrix import operator_rebirth

    validate_base(value, plan)
    document = value["identity"]["document"]
    origin = document["origin"]
    bundle = dict(
        schema="dm.runtime.bundle/v8",
        operator_capability_binding=None,
        runtime_id=document["runtime_id"],
        runtime_label=document["runtime_label"],
        **{
            key: copy.deepcopy(item)
            for key, item in document["authority"].items()
            if key != "schema"
        },
        authority_history=copy.deepcopy(document["authority_history"]),
        binding=None,
        binding_activation=None,
        provisional_history=None,
        local_origin=copy.deepcopy(origin),
        ledger="ledger.sqlite",
        socket="matrix.sock",
        keystore=None,
        capabilities=[],
        routing=None,
        scopes={"body_capabilities": [], "relationships_filename": None},
        peer_transport=dict(
            enabled=True,
            encryption_slot="peer.encryption.v1:public-base",
            exchange_filename="peer-exchange.sqlite",
            listen_host="127.0.0.1",
            listen_port=8687,
            outbox_filename="peer-outbox.sqlite",
            targets=copy.deepcopy(
                [
                    row
                    for row in value["routes"]
                    if row["embodiment_id"] != origin["embodiment_id"]
                ]
            ),
        ),
        species=None,
        sources={"cas_filename": "sources.sqlite3", "known_beings": []},
        relationships={
            "known_being_refs": [],
            "store_filename": "relationships.sqlite3",
        },
    )
    authority = operator_rebirth.authority_from_runtime_bundle(bundle)
    operator_rebirth._validate_runtime_peer_transport(
        bundle, authority, exact_targets=True
    )
    return bundle
