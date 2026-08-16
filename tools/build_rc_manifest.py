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
import tempfile
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
    commit = str(_git(repository, "rev-parse", "HEAD")).strip()
    tree = str(_git(repository, "rev-parse", "HEAD^{tree}")).strip()
    archive_value = _git(
        repository, "archive", "--format=tar", "HEAD", text=False
    )
    if not isinstance(archive_value, bytes):
        raise ManifestError(f"git_archive_not_binary:{component.name}")
    archive = archive_value
    return {
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "commit": commit,
        "tree": tree,
    }


def _matrix_pin(cluster: Path) -> str:
    try:
        lines = (cluster / "requirements-weave.txt").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError as exception:
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
    pin = _matrix_pin(cluster.resolve(strict=True))
    if pin != frozen["daimon-matrix"]["commit"]:
        raise ManifestError("cluster_matrix_pin_mismatch")
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
    target = path.resolve()
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = parent.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
    ):
        raise ManifestError("manifest_parent_not_owner_controlled")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


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
