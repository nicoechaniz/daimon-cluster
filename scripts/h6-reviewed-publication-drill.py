#!/usr/bin/env python3
"""Run H6 through exact compaii-state/HMK checkouts and real storage."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from clusterctl.reviewed_publication import (
    DM035ExecutorError,
    PinnedPublisherTransport,
)

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "tests" / "fixtures" / "dm035-provider-plan-v1.json"


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-checkout", type=Path, required=True)
    parser.add_argument("--hmk-checkout", type=Path, required=True)
    args = parser.parse_args()
    expected_plan = json.loads(PLAN.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="daimon-h6-") as temporary:
        scratch = Path(temporary)
        wiki = scratch / "wiki"
        project = wiki / "projects" / "daimon-matrix"
        unrelated = wiki / "projects" / "unrelated" / "keep.md"
        project.mkdir(parents=True, mode=0o700)
        wiki.chmod(0o755)
        unrelated.parent.mkdir(parents=True, mode=0o700)
        (project / "index.md").write_text("# Daimon Matrix\n", encoding="utf-8")
        unrelated.write_text("unrelated sentinel\n", encoding="utf-8")
        unrelated_before = hashlib.sha256(unrelated.read_bytes()).hexdigest()
        transport = PinnedPublisherTransport(
            args.provider_checkout,
            wiki_root=wiki,
            projection_root=scratch / "projection",
            runtime_root=scratch / "runtime",
            hmk_checkout=args.hmk_checkout,
            hmk_base=scratch / "hmk",
            fixed_clock_ms=1_800_000_000_000,
        )
        manifest = transport("manifest", {})
        plan = transport("plan", {"request": expected_plan["request"]})
        if plan != expected_plan:
            raise RuntimeError("exact provider plan changed")
        lease = transport(
            "acquire",
            {
                "target_kind": "llm-wiki",
                "namespace": "daimon-matrix",
                "owner": "daimon-matrix@localhost",
                "ttl_ms": 600_000,
            },
        )
        try:
            transport(
                "acquire",
                {
                    "target_kind": "llm-wiki",
                    "namespace": "daimon-matrix",
                    "owner": "daimon-matrix@localhost",
                    "ttl_ms": 600_000,
                },
            )
        except DM035ExecutorError as exception:
            concurrent_refusal = exception.retryable
        else:
            concurrent_refusal = False
        if not concurrent_refusal:
            raise RuntimeError("concurrent publisher was not refused")
        receipt = transport("apply", {"plan": plan, "lease": lease})
        if transport("apply", {"plan": plan, "lease": lease}) != receipt:
            raise RuntimeError("exact provider replay changed")
        reconciliation = transport("reconcile", {"receipt": receipt})
        if reconciliation["status"] != "verified":
            raise RuntimeError("provider effect was not freshly verified")
        if hashlib.sha256(unrelated.read_bytes()).hexdigest() != unrelated_before:
            raise RuntimeError("unrelated target changed")
        transport("release", {"lease": lease})
        result = {
            "schema": "h6-reviewed-publication-drill/v1",
            "ok": True,
            "provider_commit": "cf56e9de703f68f44b85fdf21f503d55a5557984",
            "hmk_commit": "f10fd5c3089c0962920314c97e14bc024feffa7a",
            "manifest_hash": digest(manifest),
            "plan_hash": digest(plan),
            "receipt_hash": digest(receipt),
            "exact_replay": "verified",
            "effect_reconciliation": "verified",
            "concurrent_publisher": "refused",
            "unrelated_target": "unchanged",
            "state": "temporary-removed",
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
