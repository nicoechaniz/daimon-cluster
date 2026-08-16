"""Content-addressed three-repository RC freeze acceptance."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools.build_rc_manifest import (
    ManifestError,
    build_manifest,
    canonical_manifest,
    write_manifest,
)


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


def test_freeze_rejects_repository_changed_during_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    import tools.build_rc_manifest as subject

    original = subject._git
    matrix_head_reads = 0

    def changing_head(repository: Path, *arguments: str, text: bool = True):
        nonlocal matrix_head_reads
        value = original(repository, *arguments, text=text)
        if repository.resolve() == matrix.resolve() and arguments == (
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ):
            matrix_head_reads += 1
            if matrix_head_reads == 2:
                return "f" * 40 + "\n"
        return value

    monkeypatch.setattr(subject, "_git", changing_head)
    with pytest.raises(
        ManifestError, match="repository_changed_during_freeze:daimon-matrix"
    ):
        build_manifest(matrix, cluster, tribe)


def test_manifest_output_rejects_target_and_parent_symlinks(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir(mode=0o700)
    victim = output_root / "victim"
    victim.write_bytes(b"preserve")
    target = output_root / "manifest.json"
    target.symlink_to(victim)
    with pytest.raises(ManifestError, match="manifest_target_is_symlink"):
        write_manifest(target, b"replacement")
    assert victim.read_bytes() == b"preserve"

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ManifestError, match="manifest_parent_contains_symlink"):
        write_manifest(linked_parent / "manifest.json", b"no")
