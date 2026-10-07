"""Compose native V2 credential succession without sharing Root and Body keys.

The receiving actor emits native Body acceptance. A separate Root actor signs
that exact public material. Native Matrix validators remain the final authority;
this adapter does not enroll, publish or launch a runtime.
"""
from __future__ import annotations

import copy
import hashlib
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from daimon_matrix import authority_epochs, identity
from daimon_matrix.canonical import b64url, canonical_bytes, digest as native_digest, domain_bytes, unb64url
from daimon_matrix.weave import BeingManifest, RootAuthority

from .onboarding import OnboardingError, digest, validate_plan

REQUEST = "cluster-onboarding-credential-request/v1"
RESPONSE = "cluster-onboarding-credential-response/v1"
FIELDS = {"schema", "plan_digest", "origin", "credential", "authorization", "issued_at_ms", "acceptance"}


def _member(previous: Any, origin: dict) -> tuple[dict, dict, dict]:
    if set(origin) != {"body_ref", "embodiment_id", "incarnation_id", "principal_id"}:
        raise OnboardingError("onboarding_credential_origin_rejected")
    previous.validate_origin(origin, require_active=True)
    member = previous.manifest.member(origin["embodiment_id"], origin["incarnation_id"])
    credential = previous.credentials[member["embodiment_credential_id"]]
    authorization = previous.incarnations[member["incarnation_authorization_id"]]
    if credential["schema"] != "dm.identity.artifact/v1":
        raise OnboardingError("onboarding_credential_previous_rejected")
    return member, credential, authorization


def _body(previous: Any, old: dict) -> dict:
    result = {key: copy.deepcopy(value) for key, value in old["body"].items()
              if key not in {"valid_from_ms", "valid_until_ms"}}
    result.update(control_head=previous.state.head, validity={
        "mode": "until-revoked", "not_before_ms": old["body"]["valid_from_ms"]})
    return result


def _manifest(previous: Any, member: dict, credential: dict, authorization: dict) -> dict:
    value = copy.deepcopy(dict(previous.manifest.value))
    value["revision"] += 1
    for row in value["embodiments"]:
        if row == member:
            row.update(embodiment_credential_id=credential["artifact_id"],
                       incarnation_authorization_id=authorization["artifact_id"])
    return value


def _core(previous: Any, request: dict, manifest: dict, plan: dict) -> dict:
    member, _, _ = _member(previous, request["origin"])
    return dict(
        schema=authority_epochs.CREDENTIAL_SUCCESSION_SCHEMA,
        being_ref=previous.state.being_ref, control_head=previous.state.head,
        previous_manifest_hash=previous.manifest.digest,
        successor_manifest_hash=BeingManifest.from_value(manifest).digest,
        previous_revision=previous.manifest.value["revision"], successor_revision=manifest["revision"],
        previous_credential_id=member["embodiment_credential_id"],
        successor_credential_id=request["credential"]["artifact_id"],
        previous_authorization_id=member["incarnation_authorization_id"],
        successor_authorization_id=request["authorization"]["artifact_id"],
        embodiment_id=request["origin"]["embodiment_id"], incarnation_id=request["origin"]["incarnation_id"],
        migration_id=digest(plan) + ":credential-v2", issued_at_ms=request["issued_at_ms"],
    )


def _preimage(core: dict) -> tuple[str, bytes]:
    value = hashlib.sha256(authority_epochs.CREDENTIAL_SUCCESSION_DOMAIN + canonical_bytes(core)).hexdigest()
    return value, authority_epochs.CREDENTIAL_SUCCESSION_DOMAIN + bytes.fromhex(value)


def receiving_request(previous: Any, origin: dict, plan: dict, signing_seed: bytes, *, issued_at_ms: int) -> dict:
    """Called only in the receiving actor, with its own Body key."""
    validate_plan(plan)
    member, old, prior = _member(previous, origin)
    if identity.signing_descriptor(signing_seed) != old["body"]["signing_key"]:
        raise OnboardingError("onboarding_credential_body_key_rejected")
    identity.verify_embodiment_credential(old, previous.state, at_ms=issued_at_ms)
    body = _body(previous, old)
    signature = identity._signature(signing_seed, "embodiment-acceptance",
        identity.CREDENTIAL_V2_DOMAIN.encode("ascii") + b"/acceptance\x00"
        + native_digest(identity.CREDENTIAL_V2_DOMAIN, body))
    credential = identity._artifact("embodiment-credential", body, [signature], version=2)
    prior_body = prior["body"]
    authorization = identity.create_incarnation_authorization(credential, signing_seed,
        incarnation_id=origin["incarnation_id"], incarnation_sequence=prior_body["incarnation_sequence"],
        started_at_ms=prior_body["started_at_ms"])
    request = dict(schema=REQUEST, plan_digest=digest(plan), origin=copy.deepcopy(origin),
                   credential=credential, authorization=authorization, issued_at_ms=issued_at_ms, acceptance={})
    manifest = _manifest(previous, member, credential, authorization)
    _, preimage = _preimage(_core(previous, request, manifest, plan))
    request["acceptance"] = dict(alg="Ed25519", kid=old["body"]["signing_key"]["key_id"],
        value=b64url(Ed25519PrivateKey.from_private_bytes(signing_seed).sign(preimage + b"/acceptance")))
    validate_request(previous, plan, request, observed_at_ms=issued_at_ms)
    return request


def validate_request(previous: Any, plan: dict, request: dict, *, observed_at_ms: int) -> dict:
    """Validate exact plan, unchanged identity and both Body acceptances before signing."""
    try:
        validate_plan(plan)
        if (set(request) != FIELDS or request["schema"] != REQUEST or request["plan_digest"] != digest(plan)
                or type(request["issued_at_ms"]) is not int
                or not 0 <= request["issued_at_ms"] <= observed_at_ms < 2**53
                or request["origin"]["body_ref"] != "codex:daimon-cluster:" + plan["name"]):
            raise ValueError("binding")
        member, old, prior = _member(previous, request["origin"])
        identity.verify_embodiment_credential(old, previous.state, at_ms=observed_at_ms)
        identity.verify_embodiment_credential(old, previous.state, at_ms=request["issued_at_ms"])
        credential = request["credential"]
        body, raw_hash = identity._verify_wrapper(credential, "embodiment-credential", version=2)
        if body != _body(previous, old) or len(credential["signatures"]) != 1:
            raise ValueError("credential")
        signing = old["body"]["signing_key"]
        public = Ed25519PublicKey.from_public_bytes(unb64url(signing["public"], length=32))
        acceptance = credential["signatures"][0]
        if (set(acceptance) != {"algorithm", "key_id", "role", "value"}
                or acceptance["algorithm"] != "Ed25519" or acceptance["key_id"] != signing["key_id"]
                or acceptance["role"] != "embodiment-acceptance"):
            raise ValueError("acceptance")
        public.verify(unb64url(acceptance["value"], length=64),
            identity.CREDENTIAL_V2_DOMAIN.encode("ascii") + b"/acceptance\x00" + raw_hash)
        authorization = request["authorization"]
        authorized_body, _ = identity._verify_wrapper(authorization, "incarnation-authorization")
        if (authorized_body != {**prior["body"], "embodiment_credential_id": credential["artifact_id"]}
                or len(authorization["signatures"]) != 1):
            raise ValueError("incarnation")
        signature = authorization["signatures"][0]
        if (set(signature) != {"algorithm", "key_id", "role", "value"}
                or signature["algorithm"] != "Ed25519" or signature["key_id"] != signing["key_id"]
                or signature["role"] != "incarnation-authorization"):
            raise ValueError("incarnation acceptance")
        public.verify(unb64url(signature["value"], length=64),
                      domain_bytes(identity.DOMAINS["incarnation-authorization"], authorized_body))
        manifest = _manifest(previous, member, credential, authorization)
        core = _core(previous, request, manifest, plan)
        _, preimage = _preimage(core)
        acceptance = request["acceptance"]
        if (set(acceptance) != {"alg", "kid", "value"} or acceptance["alg"] != "Ed25519"
                or acceptance["kid"] != signing["key_id"]):
            raise ValueError("succession acceptance")
        public.verify(unb64url(acceptance["value"], length=64), preimage + b"/acceptance")
        return core
    except Exception:
        raise OnboardingError("onboarding_credential_request_rejected") from None


def root_response(previous: Any, plan: dict, request: dict, root_seed: bytes, *, observed_at_ms: int) -> dict:
    """Called in the isolated Root actor; it never receives a Body seed."""
    core = validate_request(previous, plan, request, observed_at_ms=observed_at_ms)
    credential = request["credential"]
    root_signature = identity._signature(root_seed, "root-authorization",
                                         domain_bytes(identity.CREDENTIAL_V2_DOMAIN, credential["body"]))
    completed = identity._artifact("embodiment-credential", credential["body"],
                                   [*credential["signatures"], root_signature], version=2)
    identity.verify_embodiment_credential(completed, previous.state, at_ms=observed_at_ms)
    member, _, _ = _member(previous, request["origin"])
    manifest = _manifest(previous, member, completed, request["authorization"])
    content_hash, preimage = _preimage(core)
    succession = {**core, "content_hash": content_hash, "acceptance": request["acceptance"], "signatures": [dict(
        alg="Ed25519", kid=identity.signing_descriptor(root_seed)["key_id"],
        value=b64url(Ed25519PrivateKey.from_private_bytes(root_seed).sign(preimage)))]}
    response = dict(schema=RESPONSE, plan_digest=digest(plan), request_digest=digest(request),
                    credential=completed, authorization=request["authorization"], manifest=manifest, succession=succession)
    verify_response(previous, plan, request, response)
    return response


def verify_response(previous: Any, plan: dict, request: dict, response: dict) -> Any:
    """Keyless native verification; suitable for reconciliation after a lost acknowledgement."""
    try:
        validate_request(previous, plan, request, observed_at_ms=request["issued_at_ms"])
        if (set(response) != {"schema", "plan_digest", "request_digest", "credential", "authorization", "manifest", "succession"}
                or response["schema"] != RESPONSE or response["plan_digest"] != digest(plan)
                or response["request_digest"] != digest(request)
                or response["authorization"] != request["authorization"]):
            raise ValueError("response binding")
        credential = response["credential"]
        identity.verify_embodiment_credential(credential, previous.state, at_ms=request["issued_at_ms"])
        if (credential["body"] != request["credential"]["body"]
                or credential["artifact_id"] != request["credential"]["artifact_id"]
                or request["credential"]["signatures"][0] not in credential["signatures"]):
            raise ValueError("credential binding")
        member, _, _ = _member(previous, request["origin"])
        expected = _manifest(previous, member, credential, request["authorization"])
        if response["manifest"] != expected:
            raise ValueError("manifest")
        successor = RootAuthority(BeingManifest.from_value(expected), previous.state,
            {**previous.credentials, credential["artifact_id"]: credential},
            {**previous.incarnations, response["authorization"]["artifact_id"]: response["authorization"]})
        authority_epochs.verify_credential_succession(response["succession"], previous, successor)
        return successor
    except Exception:
        raise OnboardingError("onboarding_credential_response_rejected") from None


def main(argv: list[str] | None = None) -> int:
    """Private holder command: one Root package and public inputs only."""
    import argparse
    import time
    from pathlib import Path
    from daimon_matrix import operator_first_embodiment as first, keystore
    from .onboarding_custody import document

    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "genesis", "target-request", "activation", "request", "holder", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--password-fd", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        plan, genesis = document(args.plan), document(args.genesis)
        _, previous = first.validate_activation(genesis, document(args.target_request), document(args.activation))
        request = document(args.request)
        validate_request(previous, plan, request, observed_at_ms=time.time_ns() // 1_000_000)
        seed = first._root_holder_seed(args.holder, first._initial_base(genesis),
                                      lambda: first._password(args.password_fd))
        response = root_response(previous, plan, request, seed, observed_at_ms=time.time_ns() // 1_000_000)
        if args.output.exists():
            if document(args.output) != response:
                raise OnboardingError("existing_onboarding_credential_preserved")
        else:
            keystore._atomic_write(args.output, canonical_bytes(response))
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
