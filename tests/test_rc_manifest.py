"""Content-addressed three-repository RC freeze acceptance."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
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
    artifacts: dict[str, list[dict]] = {name: [] for name in names}

    matrix_bundle = artifact_root / "daimon-matrix.bundle"
    if matrix_bundle.exists():
        matrix_bundle.unlink()
    subprocess.run(
        [
            "git",
            "-C",
            matrix,
            "-c",
            "pack.threads=1",
            "bundle",
            "create",
            matrix_bundle,
            "HEAD",
        ],
        check=True,
    )
    matrix_wheel = artifact_root / "daimon_matrix-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(matrix_wheel, mode="w") as wheel_archive:
        wheel_archive.writestr(
            "daimon_matrix-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: daimon-matrix\nVersion: 0.1.0\n",
        )
        wheel_archive.writestr(
            "daimon_matrix-0.1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        wheel_archive.writestr("daimon_matrix-0.1.0.dist-info/RECORD", "")
    matrix_sdist = artifact_root / "daimon_matrix-0.1.0.tar.gz"
    with tarfile.open(matrix_sdist, mode="w:gz") as sdist_archive:
        for name, raw in (
            (
                "daimon_matrix-0.1.0/PKG-INFO",
                b"Metadata-Version: 2.4\nName: daimon-matrix\nVersion: 0.1.0\n",
            ),
            ("daimon_matrix-0.1.0/pyproject.toml", b"[build-system]\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            sdist_archive.addfile(info, io.BytesIO(raw))
    for path, kind, artifact_name in (
        (matrix_bundle, "git-bundle", "source-bundle"),
        (matrix_wheel, "python-wheel", "wheel"),
        (matrix_sdist, "python-sdist", "sdist"),
    ):
        path.chmod(0o600)
        artifacts["daimon-matrix"].append(
            {
                "name": artifact_name,
                "kind": kind,
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )

    for name, repository in (("daimon-cluster", cluster), ("tribe-bridge", tribe)):
        path = artifact_root / f"{name}.tar"
        path.write_bytes(
            subprocess.check_output(
                ["git", "-C", repository, "archive", "--format=tar", "HEAD"]
            )
        )
        path.chmod(0o600)
        artifacts[name].append(
            {
                "name": "source-archive",
                "kind": "git-archive",
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )

    receipts = {}
    for name, repository in repositories.items():
        commit = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", "HEAD"], text=True
        ).strip()
        tree = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        receipts[name] = {
            "schema": "daimon-artifact-qualification/v1",
            "commit": commit,
            "tree": tree,
            "source_artifact": (
                "source-bundle" if name == "daimon-matrix" else "source-archive"
            ),
            "artifacts": [
                {"name": row["name"], "sha256": row["sha256"]}
                for row in sorted(artifacts[name], key=lambda item: item["name"])
            ],
            "installations": [
                {
                    "python": "3.13",
                    "network": "disabled",
                    "result": "passed",
                    "source": (
                        "vcs-direct-url" if name == "daimon-matrix" else "git-archive"
                    ),
                    "installed_commit": commit,
                    "installed_tree": tree,
                }
            ],
        }
    return {
        "schema": "daimon-release-qualification/v2",
        "release": "0.1.0rc1",
        "supported_python": {name: ["3.13"] for name in names},
        "artifacts": artifacts,
        "artifact_receipts": receipts,
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


def _artifact(qualification: dict, component: str, kind: str) -> dict:
    return next(
        row for row in qualification["artifacts"][component] if row["kind"] == kind
    )


def _refresh_artifact(
    qualification: dict, artifact_root: Path, component: str, kind: str
) -> None:
    row = _artifact(qualification, component, kind)
    path = artifact_root / row["path"]
    row["bytes"] = path.stat().st_size
    row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    receipt_row = next(
        item
        for item in qualification["artifact_receipts"][component]["artifacts"]
        if item["name"] == row["name"]
    )
    receipt_row["sha256"] = row["sha256"]


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
    qualification = _qualification(matrix, cluster, tribe)
    build_manifest(
        matrix,
        cluster,
        tribe,
        qualification,
        baselines=_baselines(matrix, cluster, tribe),
        artifact_root=artifact_root,
    )
    qualification["artifacts"]["daimon-matrix"][1]["sha256"] = "0" * 64
    with pytest.raises(ManifestError, match="qualification_artifact_mismatch"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )


def test_semantic_source_artifacts_cannot_be_replaced_by_matching_claims(
    tmp_path: Path,
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    artifact_root = _artifact_root(matrix)
    cluster_archive = _artifact(qualification, "daimon-cluster", "git-archive")
    archive_path = artifact_root / cluster_archive["path"]
    archive_path.write_bytes(
        subprocess.check_output(
            [
                "git",
                "-C",
                cluster,
                "archive",
                "--format=tar",
                "--prefix=unexpected/",
                "HEAD",
            ]
        )
    )
    _refresh_artifact(
        qualification, artifact_root, "daimon-cluster", "git-archive"
    )
    with pytest.raises(
        ManifestError, match="qualification_git_archive_mismatch:daimon-cluster"
    ):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )


def test_matrix_bundle_must_have_one_exact_head(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    artifact_root = _artifact_root(matrix)
    bundle = _artifact(qualification, "daimon-matrix", "git-bundle")
    bundle_path = artifact_root / bundle["path"]
    subprocess.run(["git", "-C", matrix, "tag", "unexpected-head"], check=True)
    bundle_path.unlink()
    subprocess.run(
        [
            "git",
            "-C",
            matrix,
            "-c",
            "pack.threads=1",
            "bundle",
            "create",
            bundle_path,
            "HEAD",
            "refs/tags/unexpected-head",
        ],
        check=True,
    )
    bundle_path.chmod(0o600)
    _refresh_artifact(qualification, artifact_root, "daimon-matrix", "git-bundle")
    with pytest.raises(ManifestError, match="qualification_git_bundle_head_mismatch"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )


def test_matrix_bundle_must_contain_full_history(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    (matrix / "second").write_text("second\n", encoding="utf-8")
    subprocess.run(["git", "-C", matrix, "add", "second"], check=True)
    subprocess.run(["git", "-C", matrix, "commit", "-qm", "second"], check=True)
    matrix_commit = subprocess.check_output(
        ["git", "-C", matrix, "rev-parse", "HEAD"], text=True
    ).strip()
    (cluster / "requirements-weave.txt").write_text(
        "daimon-matrix @ git+https://github.com/AlterMundi/"
        f"daimon-matrix.git@{matrix_commit}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", cluster, "add", "requirements-weave.txt"], check=True)
    subprocess.run(["git", "-C", cluster, "commit", "-qm", "repin"], check=True)
    qualification = _qualification(matrix, cluster, tribe)
    artifact_root = _artifact_root(matrix)
    bundle = _artifact(qualification, "daimon-matrix", "git-bundle")
    bundle_path = artifact_root / bundle["path"]
    bundle_path.unlink()
    subprocess.run(
        [
            "git",
            "-C",
            matrix,
            "-c",
            "pack.threads=1",
            "bundle",
            "create",
            bundle_path,
            "HEAD^..HEAD",
        ],
        check=True,
    )
    bundle_path.chmod(0o600)
    _refresh_artifact(qualification, artifact_root, "daimon-matrix", "git-bundle")
    with pytest.raises(ManifestError, match="qualification_git_bundle_invalid"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )


def test_python_build_artifacts_are_structural_not_text_fixtures(
    tmp_path: Path,
) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    artifact_root = _artifact_root(matrix)
    wheel = _artifact(qualification, "daimon-matrix", "python-wheel")
    (artifact_root / wheel["path"]).write_bytes(b"not a wheel\n")
    _refresh_artifact(qualification, artifact_root, "daimon-matrix", "python-wheel")
    with pytest.raises(ManifestError, match="qualification_python_wheel_invalid"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )


def test_receipt_binds_inventory_source_and_offline_install(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    qualification["artifact_receipts"]["daimon-matrix"]["installations"][0][
        "network"
    ] = "available"
    with pytest.raises(
        ManifestError, match="qualification_receipt_installation_invalid:daimon-matrix"
    ):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )

    qualification = _qualification(matrix, cluster, tribe)
    qualification["artifact_receipts"]["tribe-bridge"]["tree"] = "0" * 40
    with pytest.raises(
        ManifestError, match="qualification_receipt_source_mismatch:tribe-bridge"
    ):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
        )


def test_matrix_bundle_wheel_and_sdist_are_all_required(tmp_path: Path) -> None:
    matrix, cluster, tribe = _fixture(tmp_path)
    qualification = _qualification(matrix, cluster, tribe)
    qualification["artifacts"]["daimon-matrix"] = [
        row
        for row in qualification["artifacts"]["daimon-matrix"]
        if row["kind"] != "python-sdist"
    ]
    with pytest.raises(
        ManifestError, match="qualification_artifact_kinds_incomplete:daimon-matrix"
    ):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=_artifact_root(matrix),
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
