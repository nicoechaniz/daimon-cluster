"""JSON CLI for local Weave ledger operations.

Transport daemons feed validated pages through stdin/stdout; the CLI never
opens a peer database or HMK database directly.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .ledger import Ledger
from .protocol import BeingManifest, EventSigner, b64url_decode


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="weave")
    root.add_argument("--manifest", required=True, type=Path)
    root.add_argument("--runtime", required=True, type=Path,
                      help="JSON containing origin, public_keys, signing_kid and private_key")
    root.add_argument("--ledger", required=True, type=Path)
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    incoming = sub.add_parser("incoming")
    incoming.add_argument("--input", type=Path)
    pull = sub.add_parser("pull")
    pull.add_argument("--input", type=Path)
    pull.add_argument("--source", required=True)
    export = sub.add_parser("export")
    export.add_argument("--heads", default="{}", help="JSON map incarnation_id -> sequence")
    diff = sub.add_parser("diff")
    diff.add_argument("--kind")
    diff.add_argument("--subject")
    observe = sub.add_parser("observe")
    observe.add_argument("--kind", required=True)
    observe.add_argument("--subject", required=True)
    observe.add_argument("--payload", required=True, help="JSON object")
    decide = sub.add_parser("decide")
    decide.add_argument("event_id")
    decide.add_argument("decision", choices=("adopt", "reject", "defer", "revert"))
    decide.add_argument("--reason", default="")
    decide.add_argument("--supersedes")
    return root


def _input(path: Path | None) -> dict:
    if path is None:
        return json.load(__import__("sys").stdin)
    return json.loads(path.read_text(encoding="utf-8"))


def run(args: argparse.Namespace) -> dict:
    manifest = BeingManifest.load(args.manifest)
    runtime = json.loads(args.runtime.read_text(encoding="utf-8"))
    ledger = Ledger(
        args.ledger, manifest=manifest, local_origin=runtime["origin"],
        public_keys=runtime["public_keys"],
    )
    signer = EventSigner(
        runtime["signing_kid"],
        Ed25519PrivateKey.from_private_bytes(b64url_decode(runtime["private_key"], 32)),
    )
    if args.command == "status":
        return {"being_ref": manifest.value["being_ref"], "manifest_hash": manifest.digest, "origin": runtime["origin"], "heads": ledger.heads(), "peer_cursors": ledger.peer_cursors()}
    if args.command == "incoming":
        return ledger.preview(_input(args.input)["events"])
    if args.command == "pull":
        return ledger.ingest(_input(args.input)["events"], source=args.source)
    if args.command == "export":
        return {"schema": "dm.we.delta/v1", "manifest_hash": manifest.digest, "events": ledger.delta(json.loads(args.heads))}
    if args.command == "diff":
        return {"items": ledger.diff(kind=args.kind, subject=args.subject)}
    if args.command == "observe":
        return ledger.append_local(kind=args.kind, subject=args.subject, payload=json.loads(args.payload), signer=signer)
    if args.command == "decide":
        return ledger.append_local(
            kind="adoption.decided", subject="decision",
            payload={"target_event_id": args.event_id, "decision": args.decision, "reason": args.reason},
            supersedes=args.supersedes, signer=signer,
        )
    raise ValueError("unknown command")


def main() -> None:
    try:
        print(json.dumps(run(parser().parse_args()), ensure_ascii=False, sort_keys=True, indent=2))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
