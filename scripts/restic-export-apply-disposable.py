#!/usr/bin/env python3
"""Apply an exact backup-export bundle only on a marked disposable host."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ACCOUNT = "daimon-backup-export"
GROUP = "daimon-backup-export"
MARKER_CONTENT = "purpose-built disposable\n"
ALLOWED_CANDIDATES = {
    "export-keys": (Path("/etc/daimon-backup/export-keys"), 0o640, GROUP),
    "70-daimon-backup-export.conf": (
        Path("/etc/ssh/sshd_config.d/70-daimon-backup-export.conf"),
        0o644,
        "root",
    ),
    "restic-export-command.sh": (
        Path("/opt/daimon-cluster/scripts/restic-export-command.sh"),
        0o755,
        "root",
    ),
}


def run(arguments: list[str]) -> None:
    subprocess.run(arguments, check=True)


def require_disposable_marker(marker: Path) -> None:
    if not marker.is_file() or marker.is_symlink():
        raise ValueError("disposable_marker_missing")
    metadata = marker.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("disposable_marker_unsafe")
    if marker.read_text(encoding="utf-8") != MARKER_CONTENT:
        raise ValueError("disposable_marker_invalid")


def ensure_identity() -> tuple[int, int]:
    try:
        group = grp.getgrnam(GROUP)
    except KeyError:
        run(["groupadd", "--system", GROUP])
        group = grp.getgrnam(GROUP)
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        run(
            [
                "useradd",
                "--system",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/bin/sh",
                "--gid",
                GROUP,
                ACCOUNT,
            ]
        )
        run(["usermod", "--password", "NP", ACCOUNT])
        account = pwd.getpwnam(ACCOUNT)
    if (
        account.pw_gid != group.gr_gid
        or account.pw_dir != "/nonexistent"
        or account.pw_shell != "/bin/sh"
    ):
        raise ValueError("dedicated_identity_conflict")
    return account.pw_uid, group.gr_gid


def safe_directory(path: Path, mode: int, group_id: int) -> None:
    if path.is_symlink():
        raise ValueError(f"dedicated_directory_symlink:{path}")
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, 0, group_id)
    path.chmod(mode)


def atomic_install(source: Path, target: Path, mode: int, group_id: int) -> None:
    if target.is_symlink():
        raise ValueError(f"dedicated_target_symlink:{target}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, group_id)
        temporary.chmod(mode)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def apply(bundle: Path, expected: str, marker: Path) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise PermissionError("root_required")
    require_disposable_marker(marker)
    verifier = Path(__file__).with_name("restic-export-preflight.py")
    run(
        [
            os.fspath(Path(os.sys.executable)),
            os.fspath(verifier),
            "verify",
            "--bundle",
            os.fspath(bundle),
            "--expect-sha256",
            expected,
        ]
    )
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    if set(manifest["candidates"]) != set(ALLOWED_CANDIDATES):
        raise ValueError("candidate_allowlist_mismatch")
    for name, (path, mode, _owner_group) in ALLOWED_CANDIDATES.items():
        specification = manifest["candidates"][name]
        if specification["install_path"] != os.fspath(path):
            raise ValueError(f"candidate_path_mismatch:{name}")
        if specification["mode"] != f"{mode:04o}":
            raise ValueError(f"candidate_mode_mismatch:{name}")

    _account_id, group_id = ensure_identity()
    safe_directory(Path("/etc/daimon-backup"), 0o750, group_id)
    safe_directory(Path("/opt/daimon-cluster"), 0o755, 0)
    safe_directory(Path("/opt/daimon-cluster/scripts"), 0o755, 0)
    for name, (target, mode, owner_group) in ALLOWED_CANDIDATES.items():
        target_group_id = group_id if owner_group == GROUP else 0
        atomic_install(bundle / name, target, mode, target_group_id)

    run(["/usr/sbin/sshd", "-t", "-f", "/etc/ssh/sshd_config"])
    return {
        "schema": "dm.restic-export-disposable-apply/v1",
        "bundle_sha256": expected,
        "account": ACCOUNT,
        "sshd_config_valid": True,
        "sshd_reloaded": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument(
        "--disposable-marker",
        type=Path,
        default=Path("/run/daimon-disposable-host"),
    )
    args = parser.parse_args()
    receipt = apply(args.bundle, args.expect_sha256, args.disposable_marker)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
