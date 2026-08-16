"""Content-addressed three-repository RC freeze acceptance."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.build_rc_manifest import ManifestError, build_manifest, canonical_manifest


def _repository(path: Path, name: str) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", path], check=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "RC Test"], check=True)
    subprocess.run(
        ["git", "-C", path, "config", "user.email", "rc-test@example.invalid"],
        check=True,
    )
    (path / "README.md").write_text(name + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", path, "add", "README.md"], check=True)
    subprocess.run(["git", "-C", path, "commit", "-qm", "fixture"], check=True)
    return path


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    matrix = _repository(tmp_path / "matrix", "matrix")
    cluster = _repository(tmp_path / "cluster", "cluster")
    tribe = _repository(tmp_path / "tribe", "tribe")
    matrix_commit = subprocess.check_output(
        ["git", "-C", matrix, "rev-parse", "HEAD"], text=True
    ).strip()
    (cluster / "requirements-weave.txt").write_text(
        "daimon-matrix @ git+https://github.com/AlterMundi/"
        f"daimon-matrix.git@{matrix_commit}\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", cluster, "add", "requirements-weave.txt"], check=True
    )
    subprocess.run(["git", "-C", cluster, "commit", "-qm", "pin"], check=True)
    return matrix, cluster, tribe


def test_same_heads_produce_byte_identical_manifest(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    first = canonical_manifest(build_manifest(matrix, cluster, tribe))
    second = canonical_manifest(build_manifest(matrix, cluster, tribe))
    assert first == second
    assert b'"schema":"daimon-release-candidate/v1"' in first


def test_dirty_component_and_wrong_pin_fail_closed(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    (tribe / "untracked").write_text("no\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="dirty_worktree:tribe-bridge"):
        build_manifest(matrix, cluster, tribe)
    (tribe / "untracked").unlink()
    (cluster / "requirements-weave.txt").write_text(
        "daimon-matrix @ git+https://github.com/AlterMundi/"
        f"daimon-matrix.git@{'0' * 40}\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", cluster, "add", "requirements-weave.txt"], check=True
    )
    subprocess.run(["git", "-C", cluster, "commit", "-qm", "wrong pin"], check=True)
    with pytest.raises(ManifestError, match="cluster_matrix_pin_mismatch"):
        build_manifest(matrix, cluster, tribe)
