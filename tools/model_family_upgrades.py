"""Compare bounded, owner-supplied model evidence without making provider calls."""

import json
import os
import re
import stat
import time

MAX_EVIDENCE = 128 * 1024
MAX_AGE_SECONDS = 24 * 3600


def model_evidence(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise ValueError("private_model_evidence_required")
        raw = stream.read(MAX_EVIDENCE + 1)
    if len(raw) > MAX_EVIDENCE:
        raise ValueError("model_evidence_capacity")
    return json.loads(raw)


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", value)


def fingerprint(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def version(value):
    if not isinstance(value, list) or len(value) != 3 or any(
        type(part) is not int or not 0 <= part <= 999 for part in value
    ):
        raise ValueError("explicit_model_release_version_required")
    return tuple(value)


def plan(document, targets):
    """Use exact receiver/route/contract evidence and versioned family membership."""
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "workloads"}
        or document["schema"] != "cluster.model-family-evidence/v1"
        or not isinstance(document["workloads"], list)
        or len(document["workloads"]) > 64
    ):
        raise ValueError("invalid_model_family_evidence")
    checked_at = int(time.time())
    result = {}
    for workload in document["workloads"]:
        if (
            not isinstance(workload, dict)
            or set(workload) != {"id", "target", "route", "contract", "family", "follow",
                                  "current", "current_version", "current_revision", "candidates"}
            or not all(identifier(workload[k]) for k in ("id", "target", "route", "family", "current"))
            or workload["target"] not in targets
            or not fingerprint(workload["contract"])
            or not fingerprint(workload["current_revision"])
            or type(workload["follow"]) is not bool
            or not isinstance(workload["candidates"], list)
            or len(workload["candidates"]) > 16
        ):
            raise ValueError("invalid_model_workload")
        key = workload["target"] + ":" + workload["id"]
        if key in result:
            raise ValueError("duplicate_model_workload")
        current = version(workload["current_version"])
        eligible = []
        seen = set()
        for candidate in workload["candidates"]:
            if (
                not isinstance(candidate, dict)
                or set(candidate) != {"model", "version", "target", "route", "contract",
                                       "family", "available", "qualification", "observed_at"}
                or not all(identifier(candidate[k]) for k in ("model", "target", "route", "family"))
                or not fingerprint(candidate["contract"])
                or type(candidate["available"]) is not bool
                or type(candidate["observed_at"]) is not int
                or candidate["model"] in seen
            ):
                raise ValueError("invalid_model_candidate_evidence")
            proof = candidate["qualification"]
            if proof is not None and (
                not isinstance(proof, dict)
                or set(proof) != {"previous_model", "previous_revision", "observed_at"}
                or not identifier(proof["previous_model"])
                or not fingerprint(proof["previous_revision"])
                or type(proof["observed_at"]) is not int
            ):
                raise ValueError("invalid_model_qualification_evidence")
            seen.add(candidate["model"])
            release = version(candidate["version"])
            if (
                release > current
                and candidate["model"] != workload["current"]
                and candidate["available"]
                and 0 <= checked_at - candidate["observed_at"] <= MAX_AGE_SECONDS
                and all(candidate[k] == workload[k] for k in ("target", "route", "contract", "family"))
            ):
                eligible.append((release, candidate))
        item = {"current": workload["current"], "current_revision": workload["current_revision"], "state": "pinned"}
        if workload["follow"]:
            item["state"] = "no-compatible-successor"
            if eligible:
                newest = max(release for release, _ in eligible)
                choices = [candidate for release, candidate in eligible if release == newest]
                if len(choices) != 1:
                    item["state"] = "ambiguous-release"
                else:
                    candidate = choices[0]
                    item["candidate"] = candidate["model"]
                    proof = candidate["qualification"]
                    item["state"] = (
                        "qualified-for-owner-apply"
                        if proof is not None
                        and proof["previous_model"] == workload["current"]
                        and proof["previous_revision"] == workload["current_revision"]
                        and 0 <= checked_at - proof["observed_at"] <= MAX_AGE_SECONDS
                        else "qualification-required"
                    )
        result[key] = item
    return result
