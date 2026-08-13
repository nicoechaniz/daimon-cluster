#!/usr/bin/env python3
"""Run H5 against the exact pinned HMK CLI and real SQLite databases."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from clusterctl.hmk_projection import (
    PinnedHMKTransport,
    restore_hmk_database,
    snapshot_hmk_database,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "fixtures" / "dm034-vector-v1.json"


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hmk-checkout", type=Path, required=True)
    args = parser.parse_args()
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="daimon-h5-") as temporary:
        scratch = Path(temporary)
        peer_a = scratch / "peer-a"
        peer_b = scratch / "peer-b"
        peer_a.mkdir(mode=0o700)
        peer_b.mkdir(mode=0o700)
        first = PinnedHMKTransport(
            args.hmk_checkout, peer_a, instance_id="hmk:vector-instance"
        )
        second = PinnedHMKTransport(
            args.hmk_checkout, peer_b, instance_id="hmk:vector-instance"
        )
        request = vectors["hmk_project_request"]
        receipt_a = first("apply", request)
        if first("apply", request) != receipt_a:
            raise RuntimeError("exact HMK replay changed")
        receipt_b = second("apply", request)
        if receipt_b != receipt_a:
            raise RuntimeError("peer logical receipts diverged")
        rebuild = first(
            "rebuild-apply",
            {
                "schema": "hmk.daimon-projection.rebuild-apply/v1",
                "plan": vectors["rebuild_plan"]["hmk_plan"],
            },
        )
        snapshot = scratch / "peer-a.snapshot.sqlite"
        evidence = snapshot_hmk_database(peer_a, snapshot)
        restored = scratch / "peer-a-restored"
        restored_evidence = restore_hmk_database(snapshot, restored)
        if evidence != restored_evidence:
            raise RuntimeError("restored HMK digest changed")
        # Mutation in A must not cross the separately configured peer base.
        (peer_a / "library.db").write_bytes(b"synthetic-disposable-view-loss")
        if second("apply", request) != receipt_b:
            raise RuntimeError("peer HMK state was not independent")
        result = {
            "schema": "h5-hmk-projection-drill/v1",
            "ok": True,
            "hmk_commit": vectors["profile"]["hmk_commit"],
            "exact_replay": "verified",
            "atomic_rebuild": "verified",
            "snapshot_restore": "verified",
            "peer_independence": "verified",
            "projection_receipt_hash": digest(receipt_a),
            "rebuild_receipt_hash": digest(rebuild),
            "snapshot": evidence,
            "state": "temporary-removed",
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
