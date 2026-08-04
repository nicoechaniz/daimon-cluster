"""Frozen migration evidence for retiring Cluster's provisional Weave code."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path

import pytest

from clusterctl import matrix_host
from clusterctl.matrix_host import MATRIX_CONTRACT_COMMIT, MatrixHostError
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.weave import (
    BeingManifest,
    ProvisionalAuthority,
    WeaveProtocolError,
    verify_event,
)

FIXTURE = Path(__file__).parent / "fixtures" / "matrix-weave-v1"
FILE_SHA256 = {
    "configuration-proposal.json": (
        "61bcacbb6a0a3ece863cbc5f1ef80e9cc57ae61f83c0cd6611f2980ec1150d3a"
    ),
    "index.json": "e9c1bac6fb96d99bf6c0dd1743047e6cc062cbd49d7be4b18d3372c3b108d908",
    "manifest.json": "eacb48327b56e440a0daf1a8f07bc1f6066917a191a9dd5d85061a9204145864",
}


def _load(name: str) -> dict:
    value = json.loads((FIXTURE / name).read_bytes())
    assert isinstance(value, dict)
    return value


def test_pinned_matrix_accepts_frozen_provisional_bytes_exactly() -> None:
    distribution = importlib.metadata.distribution("daimon-matrix")
    direct_url = json.loads(distribution.read_text("direct_url.json") or "null")
    assert direct_url["vcs_info"]["commit_id"] == MATRIX_CONTRACT_COMMIT
    assert {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in FIXTURE.iterdir()
        if path.is_file()
    } == FILE_SHA256

    index = _load("index.json")
    manifest_value = _load(index["manifest"])
    manifest = BeingManifest.from_value(manifest_value)
    authority = ProvisionalAuthority(manifest, index["public_keys"])
    event_path = FIXTURE / index["valid_events"][0]
    event = json.loads(event_path.read_bytes())

    assert manifest.digest == index["manifest_hash"]
    assert event_path.read_bytes() == canonical_bytes(event) + b"\n"
    assert verify_event(event, authority) == event

    tampered = copy.deepcopy(event)
    tampered["payload"]["email"] = "substitution@example.invalid"
    with pytest.raises(WeaveProtocolError, match="content_hash_mismatch"):
        verify_event(tampered, authority)


def test_host_refuses_an_installed_matrix_from_any_other_commit(monkeypatch) -> None:
    class WrongDistribution:
        @staticmethod
        def read_text(_name: str) -> str:
            return json.dumps({"vcs_info": {"commit_id": "0" * 40}})

    monkeypatch.setattr(
        matrix_host.importlib.metadata,
        "distribution",
        lambda _name: WrongDistribution(),
    )
    with pytest.raises(MatrixHostError, match="daimon_matrix_contract_mismatch"):
        matrix_host._matrix_api()
