#!/usr/bin/env python3
"""Render and verify a content-addressed dedicated-export deployment bundle."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "daimon-backup-export"
INSTALL_SPECS = {
    "70-daimon-backup-export.conf": (
        ROOT / "configs/70-daimon-backup-export.conf",
        "/etc/ssh/sshd_config.d/70-daimon-backup-export.conf",
        0o644,
    ),
    "restic-export-command.sh": (
        ROOT / "scripts/restic-export-command.sh",
        "/opt/daimon-cluster/scripts/restic-export-command.sh",
        0o755,
    ),
}


def canonical(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_public_key(path: Path) -> tuple[bytes, str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("public_key_unsafe")
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise ValueError("public_key_must_be_one_line")
    fields = lines[0].split()
    if len(fields) not in (2, 3) or fields[0] != "ssh-ed25519":
        raise ValueError("public_key_must_be_unadorned_ed25519")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except ValueError as error:
        raise ValueError("public_key_invalid_base64") from error
    if len(decoded) < 48:
        raise ValueError("public_key_invalid_blob")
    fingerprint = base64.b64encode(hashlib.sha256(decoded).digest()).decode().rstrip("=")
    normalized = " ".join(fields).encode() + b"\n"
    return normalized, f"SHA256:{fingerprint}"


def render(public_key: Path, output: Path) -> str:
    if output.exists() or output.is_symlink():
        raise ValueError("output_must_not_exist")
    parent = output.parent.resolve(strict=True)
    key_data, fingerprint = normalized_public_key(public_key)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        candidates: dict[str, dict[str, Any]] = {}
        material = {"export-keys": (key_data, "/etc/daimon-backup/export-keys", 0o640)}
        for name, (source, install_path, mode) in INSTALL_SPECS.items():
            material[name] = (source.read_bytes(), install_path, mode)
        for name, (data, install_path, mode) in sorted(material.items()):
            candidate = temporary / name
            candidate.write_bytes(data)
            candidate.chmod(mode)
            candidates[name] = {
                "install_path": install_path,
                "mode": f"{mode:04o}",
                "sha256": sha256(data),
            }
        unsigned = {
            "schema": "dm.restic-export-preflight/v1",
            "account": ACCOUNT,
            "public_key_fingerprint": fingerprint,
            "candidates": candidates,
        }
        bundle_sha256 = sha256(canonical(unsigned))
        manifest = {**unsigned, "bundle_sha256": bundle_sha256}
        manifest_path = temporary / "manifest.json"
        manifest_path.write_bytes(canonical(manifest))
        manifest_path.chmod(0o600)
        os.replace(temporary, output)
        return bundle_sha256
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify(bundle: Path, expected: str) -> str:
    if not bundle.is_dir() or bundle.is_symlink():
        raise ValueError("bundle_unsafe")
    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("manifest_unsafe")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded = manifest.pop("bundle_sha256", None)
    actual = sha256(canonical(manifest))
    if recorded != actual or expected != actual:
        raise ValueError("bundle_hash_mismatch")
    for name, specification in manifest["candidates"].items():
        candidate = bundle / name
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"candidate_unsafe:{name}")
        if sha256(candidate.read_bytes()) != specification["sha256"]:
            raise ValueError(f"candidate_hash_mismatch:{name}")
        if f"{candidate.stat().st_mode & 0o777:04o}" != specification["mode"]:
            raise ValueError(f"candidate_mode_mismatch:{name}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    render_parser = subparsers.add_parser("render")
    render_parser.add_argument("--public-key", type=Path, required=True)
    render_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    verify_parser.add_argument("--expect-sha256", required=True)
    args = parser.parse_args()

    if args.command == "render":
        digest = render(args.public_key, args.output)
    else:
        digest = verify(args.bundle, args.expect_sha256)
    print(f"bundle_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
