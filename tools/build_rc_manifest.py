"""Freeze the three-repository V0 candidate into deterministic evidence.

The tool is intentionally read-only with respect to the repositories.  It
refuses dirty worktrees, verifies Cluster's exact Matrix source pin, hashes a
deterministic ``git archive`` for every component, and atomically writes one
canonical manifest.  Re-running it over the same three commits produces the
same bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

SCHEMA: Final = "daimon-release-candidate/v1"
BASELINES: Final = {
    "daimon-matrix": {
        "commit": "e855148ffac5b2f4068ba56be6324d7b78fb430f",
        "tree": "be24a07fd387c9fe10331b17507904f14f66ea71",
    },
    "daimon-cluster": {
        "commit": "734fd0037dcf84783ef7991415014af7435a46f2",
        "tree": "317d76bada51741dd3fcd40b7edbb3120b3393a6",
    },
    "tribe-bridge": {
        "commit": "187c61d881e6de830a029027144193645f2c7f62",
        "tree": "84da16611be62581d9a049d9f567652c4cc4e61b",
    },
}
PIN_PATTERN: Final = re.compile(
    r"^daimon-matrix @ git\+https://github\.com/AlterMundi/"
    r"daimon-matrix\.git@([0-9a-f]{40})$"
)


class ManifestError(RuntimeError):
    """The candidate cannot be frozen reproducibly."""


@dataclass(frozen=True)
class Component:
    name: str
    repository: Path


def _git(repository: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as exception:
        raise ManifestError(f"git_{arguments[0]}_failed:{repository.name}") from exception
    return result.stdout


def _closed_repository(component: Component) -> dict[str, str]:
    repository = component.repository.resolve(strict=True)
    if not repository.is_dir():
        raise ManifestError(f"repository_not_directory:{component.name}")
    status = str(
        _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    )
    if status:
        raise ManifestError(f"dirty_worktree:{component.name}")
    shallow = str(_git(repository, "rev-parse", "--is-shallow-repository")).strip()
    if shallow != "false":
        raise ManifestError(f"shallow_repository:{component.name}")
    commit = str(_git(repository, "rev-parse", "--verify", "HEAD^{commit}")).strip()
    tree = str(_git(repository, "rev-parse", f"{commit}^{{tree}}")).strip()
    archive_value = _git(
        repository, "archive", "--format=tar", commit, text=False
    )
    if not isinstance(archive_value, bytes):
        raise ManifestError(f"git_archive_not_binary:{component.name}")
    archive = archive_value
    return {
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "commit": commit,
        "tree": tree,
    }


def _matrix_pin(cluster: Path, commit: str) -> str:
    try:
        raw = _git(cluster, "show", f"{commit}:requirements-weave.txt")
        if not isinstance(raw, str):
            raise ManifestError("cluster_matrix_pin_not_text")
        lines = raw.splitlines()
    except ManifestError as exception:
        raise ManifestError("cluster_matrix_pin_unreadable") from exception
    matches = [match for line in lines if (match := PIN_PATTERN.fullmatch(line))]
    if len(matches) != 1:
        raise ManifestError("cluster_matrix_pin_not_exact")
    return matches[0].group(1)


def build_manifest(matrix: Path, cluster: Path, tribe: Path) -> dict[str, object]:
    components = (
        Component("daimon-matrix", matrix),
        Component("daimon-cluster", cluster),
        Component("tribe-bridge", tribe),
    )
    frozen = {item.name: _closed_repository(item) for item in components}
    cluster_repository = cluster.resolve(strict=True)
    pin = _matrix_pin(
        cluster_repository, frozen["daimon-cluster"]["commit"]
    )
    if pin != frozen["daimon-matrix"]["commit"]:
        raise ManifestError("cluster_matrix_pin_mismatch")
    for component in components:
        repository = component.repository.resolve(strict=True)
        final_commit = str(
            _git(repository, "rev-parse", "--verify", "HEAD^{commit}")
        ).strip()
        final_status = str(
            _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
        )
        if final_commit != frozen[component.name]["commit"] or final_status:
            raise ManifestError(f"repository_changed_during_freeze:{component.name}")
    return {
        "schema": SCHEMA,
        "baseline": BASELINES,
        "components": frozen,
        "cross_repository": {
            "cluster_matrix_commit": pin,
            "cluster_matrix_pin": "requirements-weave.txt",
        },
    }


def canonical_manifest(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def write_manifest(path: Path, raw: bytes) -> None:
    target = Path(os.path.abspath(path))
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.resolve(strict=True) != parent:
        raise ManifestError("manifest_parent_contains_symlink")
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise ManifestError("manifest_parent_not_owner_controlled")
    directory = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary_name = f".{target.name}.{os.urandom(16).hex()}.tmp"
    descriptor = -1
    try:
        try:
            target_info = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            target_info = None
        if target_info is not None and stat.S_ISLNK(target_info.st_mode):
            raise ManifestError("manifest_target_is_symlink")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(
            temporary_name,
            target.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--cluster", type=Path, required=True)
    parser.add_argument("--tribe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    raw = canonical_manifest(
        build_manifest(arguments.matrix, arguments.cluster, arguments.tribe)
    )
    write_manifest(arguments.output, raw)
    print(hashlib.sha256(raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
