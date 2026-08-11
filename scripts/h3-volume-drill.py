#!/usr/bin/env python3
"""Destructive, self-cleaning Incus acceptance drill for H3 volume relocation.

Only exact resources below an explicit ``h3-*`` prefix are created or removed.
The driver crosses every storage boundary through a fresh Python process so
the next step must resume from Incus truth rather than adapter memory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from clusterctl.adapters import IncusAdapter, IncusError

PREFIX_RE = re.compile(r"^h3-[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
SCHEMA = "h3-real-volume-drill/v1"


def _names(prefix: str) -> tuple[str, str, str]:
    if not PREFIX_RE.fullmatch(prefix):
        raise ValueError("prefix must match ^h3-[a-z0-9][a-z0-9-]{0,39}$")
    return f"{prefix}-src", f"{prefix}-dst", f"{prefix}-home"


def _attachment(instance: str) -> dict:
    return {
        "instance": instance,
        "device": "home",
        "path": "/home/agent",
        "writable": True,
    }


def _observe(adapter: IncusAdapter, prefix: str) -> dict:
    source, target, volume = _names(prefix)
    instances = {
        item["name"]: item["state"]
        for item in adapter.list_instances()
        if item["name"] in {source, target}
    }
    observation = adapter.volume_observation(volume)
    if len([item for item in observation["attachments"] if item["writable"]]) > 1:
        raise RuntimeError("more than one writable volume attachment observed")
    return {
        "volume": observation,
        "instances": instances,
    }


def _child_observation(script: Path, project: str, prefix: str) -> dict:
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--observe",
            "--project",
            project,
            "--prefix",
            prefix,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _content_evidence(adapter: IncusAdapter, instance: str) -> dict:
    output = adapter.exec(
        instance,
        [
            "sh",
            "-eu",
            "-c",
            "sha256sum /home/agent/.daimon/h3-state; "
            "ssh-keygen -lf /home/agent/.daimon/identity.pub",
        ],
    ).splitlines()
    if len(output) != 2:
        raise RuntimeError("unexpected in-container custody evidence")
    state_hash = output[0].split()[0]
    public_fingerprint = output[1].split()[1]
    return {
        "state_sha256": state_hash,
        "public_key_fingerprint": public_fingerprint,
    }


def _cleanup(adapter: IncusAdapter, source: str, target: str, volume: str) -> None:
    for instance in (target, source):
        try:
            adapter._incus("delete", instance, "--force")  # noqa: SLF001
        except IncusError as exc:
            if "not found" not in str(exc).lower():
                raise
    try:
        adapter._incus(  # noqa: SLF001
            "storage", "volume", "delete", "default", volume
        )
    except IncusError as exc:
        if "not found" not in str(exc).lower():
            raise


def _run(args: argparse.Namespace) -> dict:
    source, target, volume = _names(args.prefix)
    adapter = IncusAdapter(
        profile=args.profile,
        managed_prefix="",
        project=args.project,
    )
    script = Path(__file__).resolve()
    before = _observe(adapter, args.prefix)
    if before["instances"] or before["volume"]["present"]:
        raise RuntimeError("scratch prefix collides with existing Incus resources")

    boundaries: list[dict] = []

    def boundary(name: str) -> dict:
        observed = _child_observation(script, args.project, args.prefix)
        boundaries.append({"boundary": name, **observed})
        return observed

    try:
        adapter.create_instance(source, args.image, args.profile)
        adapter.create_instance(target, args.image, args.profile)
        adapter._incus(  # noqa: SLF001
            "storage", "volume", "create", "default", volume
        )
        boundary("target-created-stopped-without-home")

        adapter.attach_volume(volume, source)
        attached_source = boundary("source-attached")
        identity = attached_source["volume"]["identity"]
        if attached_source["volume"]["attachments"] != [_attachment(source)]:
            raise RuntimeError("source attachment did not converge exactly")

        adapter.start(source)
        marker = hashlib.sha256(args.prefix.encode()).hexdigest()
        adapter.exec(
            source,
            [
                "sh",
                "-eu",
                "-c",
                "umask 077; mkdir -p /home/agent/.daimon; "
                f"printf '%s\\n' {marker} > /home/agent/.daimon/h3-state; "
                "if [ ! -f /home/agent/.daimon/identity ]; then "
                "ssh-keygen -q -t ed25519 -N '' "
                "-f /home/agent/.daimon/identity -C h3-drill; fi",
            ],
        )
        source_content = _content_evidence(adapter, source)
        boundary("checkpoint-bytes-created")
        adapter.stop(source)
        boundary("source-stopped")

        # Simulate a detach whose successful response was lost.  The fresh
        # process observes zero attachments; the idempotent retry performs no
        # second detach and resumes from effect truth.
        adapter._incus(  # noqa: SLF001
            "storage", "volume", "detach", "default", volume, source, "home"
        )
        lost_detach = boundary("detach-response-lost")
        if lost_detach["volume"]["attachments"] != []:
            raise RuntimeError("lost detach did not leave an unattached volume")
        adapter.detach_volume(volume, source)
        boundary("detach-resumed-from-observation")

        # Same response-loss exercise for attach.
        adapter._incus(  # noqa: SLF001
            "storage",
            "volume",
            "attach",
            "default",
            volume,
            target,
            "home",
            "/home/agent",
        )
        lost_attach = boundary("attach-response-lost")
        if lost_attach["volume"]["attachments"] != [_attachment(target)]:
            raise RuntimeError("lost attach did not converge to the target")
        resumed = adapter.attach_volume(volume, target)
        if resumed["identity"] != identity:
            raise RuntimeError("volume identity changed during response-loss resume")
        boundary("attach-resumed-from-observation")

        adapter.start(target)
        running_target = boundary("target-started-after-attachment")
        if running_target["volume"]["identity"] != identity:
            raise RuntimeError("target started with a different volume identity")
        target_content = _content_evidence(adapter, target)
        if target_content != source_content:
            raise RuntimeError("durable state or key fingerprint changed")
        boundary("post-start-custody-verified")

        # Exercise the post-start rollback window.  The exact same identity
        # and bytes must return to one stopped source attachment.
        adapter.stop(target)
        boundary("rollback-target-stopped")
        adapter.detach_volume(volume, target)
        boundary("rollback-target-detached")
        adapter.attach_volume(volume, source)
        rolled_back = boundary("rollback-source-attached")
        if (
            rolled_back["volume"]["identity"] != identity
            or rolled_back["volume"]["attachments"] != [_attachment(source)]
        ):
            raise RuntimeError("rollback did not restore exact source custody")
        adapter.start(source)
        rollback_content = _content_evidence(adapter, source)
        adapter.stop(source)
        boundary("rollback-bytes-verified-source-stopped")
        if rollback_content != source_content:
            raise RuntimeError("rollback changed durable state or key fingerprint")

        return {
            "schema": SCHEMA,
            "result": "ok",
            "prefix": args.prefix,
            "image": args.image,
            "volume_identity": identity,
            "state_sha256": source_content["state_sha256"],
            "public_key_fingerprint": source_content["public_key_fingerprint"],
            "process_boundaries": [item["boundary"] for item in boundaries],
            "one_writable_attachment_at_every_boundary": True,
            "response_loss_resumed": ["detach", "attach"],
            "rollback_restored_source": True,
        }
    finally:
        _cleanup(adapter, source, target, volume)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--project", default="default")
    parser.add_argument("--profile", default="tribe-agent")
    parser.add_argument("--image", default="tribe-base/latest")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--observe", action="store_true", help=argparse.SUPPRESS)
    return parser


def main() -> int:
    args = _parser().parse_args()
    _names(args.prefix)
    adapter = IncusAdapter(
        profile=args.profile,
        managed_prefix="",
        project=args.project,
    )
    if args.observe:
        print(json.dumps(_observe(adapter, args.prefix), sort_keys=True))
        return 0
    if not args.execute:
        source, target, volume = _names(args.prefix)
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "result": "plan",
                    "creates_then_removes": {
                        "instances": [source, target],
                        "volume": volume,
                    },
                },
                sort_keys=True,
            )
        )
        return 0
    print(json.dumps(_run(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
