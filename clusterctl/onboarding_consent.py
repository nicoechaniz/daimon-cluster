"""Owner acknowledgement of a host-published plan, never host execution authority.

The root worker publishes the exact proposed Source context. Authenticated
intake records the pair's decision in its own private store. The worker checks
both ownership boundaries and the current review digest before proceeding.
Acknowledgement alone cannot grant resources, create custody or enroll a body.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from . import being_seed
from .onboarding import OnboardingError, digest, validate_plan
from .onboarding_progress import Progress

REVIEW_SCHEMA = "cluster-onboarding-review/v1"
CONSENT_SCHEMA = "cluster-onboarding-consent/v1"


def review(plan: dict, source_text: str) -> dict:
    plan = validate_plan(plan)
    if (not isinstance(source_text, str) or not source_text.strip()
            or len(source_text.encode()) > 48000 or "\0" in source_text):
        raise OnboardingError("invalid_onboarding_review")
    document = {"schema": REVIEW_SCHEMA, "name": plan["name"], "owner": plan["owner"],
                "plan": plan, "source_text": source_text,
                "source_digest": hashlib.sha256(source_text.encode()).hexdigest()}
    value = {**document, "review_digest": digest(document)}
    if len(json.dumps(value, sort_keys=True).encode()) > 65536:
        raise OnboardingError("invalid_onboarding_review")
    return value


def validate_review(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema", "name", "owner", "plan", "source_text", "source_digest", "review_digest",
    }:
        raise OnboardingError("invalid_onboarding_review")
    if review(value["plan"], value["source_text"]) != value:
        raise OnboardingError("invalid_onboarding_review")
    return value


class Reviews(Progress):
    suffix = ".review.json"
    validate = staticmethod(validate_review)


def validate_decision(value: object, proposal: dict) -> dict:
    if (not isinstance(value, dict) or set(value) != {
        "review_digest", "inheritance_approved", "matrix_identity_mode",
    } or value["review_digest"] != proposal["review_digest"]
            or value["inheritance_approved"] is not True
            or not isinstance(value["matrix_identity_mode"], str)
            or value["matrix_identity_mode"] not in {"existing", "first"}):
        raise being_seed.SeedError("exact_onboarding_review_required", 409)
    return dict(value)


def _expected(proposal: dict, decision: dict) -> dict:
    return {"schema": CONSENT_SCHEMA, "name": proposal["name"], "owner": proposal["owner"],
            "plan_digest": digest(proposal["plan"]), **validate_decision(decision, proposal)}


def submit(state_dir: str | Path, name: str, decision: dict, *, owner: str,
           reviews: Reviews) -> dict:
    # Seed ownership and root-published review ownership must both agree.
    directory, record = being_seed._record(state_dir, name, owner)
    proposal = reviews.read(name, owner=owner)
    if record.get("created_by") != proposal["owner"] or owner != proposal["owner"]:
        raise being_seed.SeedError("seed_not_found", 404)
    value = _expected(proposal, decision)
    path = directory / ("consent-" + proposal["review_digest"] + ".json")
    with being_seed._locked(directory):
        if path.exists():
            if being_seed._read(path) != value:
                raise being_seed.SeedError("onboarding_decision_conflict", 409)
        else:
            being_seed._write(path, value)
    return {"recorded": True, "review_digest": proposal["review_digest"],
            "matrix_identity_mode": decision["matrix_identity_mode"], "active": False}


def read(state_dir: str | Path, proposal: dict, *, intake_uid: int) -> dict | None:
    """Read a participant-owned decision from the root worker without copying secrets."""
    validate_review(proposal)
    directory = being_seed._directory(state_dir, proposal["name"])
    # The store root is a configured trust boundary, not a path from the seed.
    for parent in (Path(state_dir), directory.parent, directory):
        being_seed._path(parent)
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != intake_uid or info.st_mode & 0o077:
            raise OnboardingError("private_onboarding_consent_required")
    path = directory / ("consent-" + proposal["review_digest"] + ".json")
    try:
        descriptor = os.open(being_seed._path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != intake_uid or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_size > 65536):
            raise OnboardingError("private_onboarding_consent_required")
        value = json.load(stream)
    if not isinstance(value, dict):
        raise OnboardingError("invalid_onboarding_consent")
    decision = {key: value.get(key) for key in ("review_digest", "inheritance_approved", "matrix_identity_mode")}
    if _expected(proposal, decision) != value:
        raise OnboardingError("invalid_onboarding_consent")
    return value
