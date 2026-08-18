"""Content-addressed three-repository RC freeze acceptance."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from tools.build_rc_manifest import (
    ManifestError,
    build_manifest,
    canonical_manifest,
    read_qualification,
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
    subprocess.run(["git", "-C", cluster, "add", "requirements-weave.txt"], check=True)
    subprocess.run(["git", "-C", cluster, "commit", "-qm", "pin"], check=True)
    return matrix, cluster, tribe


def _artifact_root(matrix: Path) -> Path:
    return matrix.parent / "artifacts"


def _qualification(matrix: Path, cluster: Path, tribe: Path) -> dict:
    repositories = {
        "daimon-matrix": matrix,
        "daimon-cluster": cluster,
        "tribe-bridge": tribe,
    }
    names = tuple(repositories)
    artifact_root = _artifact_root(matrix)
    artifact_root.mkdir(mode=0o700, exist_ok=True)
    artifacts = {}
    for name in names:
        path = artifact_root / f"{name}.artifact"
        path.write_bytes(f"exact artifact for {name}\n".encode("ascii"))
        path.chmod(0o600)
        artifacts[name] = [
            {
                "name": "release-artifact",
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        ]
    return {
        "schema": "daimon-release-qualification/v1",
        "release": "0.1.0rc1",
        "supported_python": {name: ["3.13"] for name in names},
        "artifacts": artifacts,
        "tests": {
            name: [{"name": "full", "python": "3.13", "passed": 1, "skipped": 0}]
            for name in names
        },
        "evidence": {
            name: [
                {
                    "path": "README.md",
                    "sha256": hashlib.sha256(
                        (repository / "README.md").read_bytes()
                    ).hexdigest(),
                }
            ]
            for name, repository in repositories.items()
        },
        "limitations": ["fixture qualification is not physical evidence"],
        "human_gates": [
            "cross-being-consent",
            "live-custody",
            "physical-hosts-and-backup-target",
            "physical-rehearsal-go",
            "publication-and-cutover",
            "tribe-live-operations",
            "tribe-retirement",
        ],
    }


def _baselines(matrix: Path, cluster: Path, tribe: Path) -> dict:
    repositories = {
        "daimon-matrix": matrix,
        "daimon-cluster": cluster,
        "tribe-bridge": tribe,
    }
    result = {}
    for name, repository in repositories.items():
        commit = subprocess.check_output(
            ["git", "-C", repository, "rev-list", "--max-parents=0", "HEAD"],
            text=True,
        ).strip()
        tree = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", f"{commit}^{{tree}}"],
            text=True,
        ).strip()
        result[name] = {"commit": commit, "tree": tree}
    return result


def test_same_heads_produce_byte_identical_manifest(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    baselines = _baselines(matrix, cluster, tribe)
    first = canonical_manifest(
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=baselines,
            artifact_root=_artifact_root(matrix),
        )
    )
    second = canonical_manifest(
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=baselines,
            artifact_root=_artifact_root(matrix),
        )
    )
    assert first == second
    assert b'"schema":"daimon-release-candidate/v1"' in first
    assert b'"archive_bytes":' in first
    assert b'"tribe-live-operations"' in first
    assert b'"tribe-independent-approval"' not in first


def test_dirty_component_and_wrong_pin_fail_closed(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    (tribe / "untracked").write_text("no\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="dirty_worktree:tribe-bridge"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            _qualification(matrix, cluster, tribe),
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )
    (tribe / "untracked").unlink()
    (cluster / "requirements-weave.txt").write_text(
        "daimon-matrix @ git+https://github.com/AlterMundi/"
        f"daimon-matrix.git@{'0' * 40}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", cluster, "add", "requirements-weave.txt"], check=True)
    subprocess.run(["git", "-C", cluster, "commit", "-qm", "wrong pin"], check=True)
    with pytest.raises(ManifestError, match="cluster_matrix_pin_mismatch"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            _qualification(matrix, cluster, tribe),
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )


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
        build_manifest(
            matrix,
            cluster,
            tribe,
            _qualification(matrix, cluster, tribe),
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )


def test_qualification_requires_python_coverage_and_committed_evidence(
    tmp_path: Path,
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    qualification["supported_python"]["daimon-matrix"].append("3.14")
    with pytest.raises(ManifestError, match="python_coverage_incomplete"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )

    qualification = _qualification(matrix, cluster, tribe)
    qualification["evidence"]["tribe-bridge"][0]["sha256"] = "0" * 64
    with pytest.raises(ManifestError, match="evidence_mismatch:tribe-bridge"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )


def test_manifest_requires_exact_baseline_ancestry(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    baselines = _baselines(matrix, cluster, tribe)
    baselines["daimon-cluster"]["tree"] = "0" * 40
    with pytest.raises(ManifestError, match="baseline_mismatch:daimon-cluster"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            _qualification(matrix, cluster, tribe),
            baselines=baselines,
            artifact_root=_artifact_root(matrix),
        )


@pytest.mark.parametrize(
    "component", ["daimon-matrix", "daimon-cluster", "tribe-bridge"]
)
def test_qualification_requires_artifacts_for_every_component(
    tmp_path: Path, component: str
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    qualification["artifacts"][component] = []
    with pytest.raises(ManifestError, match="qualification_artifacts_invalid"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )


def test_qualification_requires_artifact_root(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    with pytest.raises(ManifestError, match="qualification_artifact_root_missing"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            _qualification(matrix, cluster, tribe),
            baselines=_baselines(matrix, cluster, tribe),
        )


def test_qualification_requires_remaining_human_gates(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    qualification["human_gates"].remove("tribe-live-operations")
    qualification["human_gates"].insert(-1, "tribe-independent-approval")
    with pytest.raises(ManifestError, match="qualification_gates_invalid"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )


def test_manifest_hashes_external_artifacts_and_rejects_mismatch(
    tmp_path: Path,
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir(mode=0o755)
    wheel = artifact_root / "matrix.whl"
    wheel.write_bytes(b"exact-wheel-bytes")
    wheel.chmod(0o644)
    qualification = _qualification(matrix, cluster, tribe)
    qualification["artifacts"]["daimon-matrix"] = [
        {
            "name": "matrix-wheel",
            "path": "matrix.whl",
            "bytes": wheel.stat().st_size,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        }
    ]
    build_manifest(
        matrix,
        cluster,
        tribe,
        qualification,
        baselines=_baselines(matrix, cluster, tribe),
        artifact_root=artifact_root,
    )
    qualification["artifacts"]["daimon-matrix"][0]["sha256"] = "0" * 64
    with pytest.raises(ManifestError, match="qualification_artifact_mismatch"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )


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

    nested = linked_parent / "created-before-refusal"
    with pytest.raises(ManifestError, match="manifest_parent_contains_symlink"):
        write_manifest(nested / "manifest.json", b"no")
    assert not (real_parent / nested.name).exists()


def test_manifest_output_requires_an_existing_parent(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(ManifestError, match="manifest_parent_missing"):
        write_manifest(missing / "manifest.json", b"no")
    assert not missing.exists()


def test_manifest_output_never_overwrites_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    target.write_bytes(b"preserve")
    with pytest.raises(ManifestError, match="manifest_target_exists"):
        write_manifest(target, b"replacement")
    assert target.read_bytes() == b"preserve"


def test_manifest_output_is_new_owner_only_and_exact(tmp_path: Path) -> None:
    target = tmp_path / "manifest.json"
    write_manifest(target, b"exact-manifest\n")
    assert target.read_bytes() == b"exact-manifest\n"
    assert target.stat().st_mode & 0o077 == 0
    with pytest.raises(ManifestError, match="manifest_target_exists"):
        write_manifest(target, b"replacement\n")


def test_manifest_output_rejects_writable_parent(tmp_path: Path) -> None:
    output_root = tmp_path / "mutable"
    output_root.mkdir(mode=0o777)
    output_root.chmod(0o777)
    with pytest.raises(ManifestError, match="parent_not_owner_controlled"):
        write_manifest(output_root / "manifest.json", b"no")


def test_qualification_input_is_canonical_owner_only_and_not_linked(
    tmp_path: Path,
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    raw = json.dumps(
        qualification, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    source = tmp_path / "qualification.json"
    source.write_text(raw, encoding="ascii")
    source.chmod(0o600)
    assert read_qualification(source) == qualification

    source.chmod(0o640)
    with pytest.raises(ManifestError, match="qualification_file_rejected"):
        read_qualification(source)
    source.chmod(0o600)
    linked = tmp_path / "linked-qualification.json"
    linked.symlink_to(source)
    with pytest.raises(ManifestError, match="qualification_file_rejected"):
        read_qualification(linked)
