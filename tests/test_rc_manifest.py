"""Content-addressed three-repository RC freeze acceptance."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from base64 import urlsafe_b64encode
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
    matrix_files = {
        ".gitignore": b"__pycache__/\n",
        "LICENSE": b"fixture license\n",
        "README.md": b"matrix\n",
        "pyproject.toml": (
            b"[build-system]\nrequires = [\"hatchling==1.31.0\"]\n"
            b"build-backend = \"hatchling.build\"\n\n"
            b"[project]\nname = \"daimon-matrix\"\nversion = \"0.1.0\"\n"
            b"description = \"fixture Matrix\"\nreadme = \"README.md\"\n"
            b"requires-python = \">=3.11\"\nlicense = \"MIT\"\n"
            b"license-files = [\"LICENSE\"]\n"
            b"authors = [{ name = \"RC Test\" }]\n"
            b"classifiers = [\"Programming Language :: Python :: 3\"]\n"
            b"dependencies = [\"fixture-dependency==1.0\"]\n"
            b"[project.scripts]\ndaimon = \"daimon_matrix.cli:main\"\n"
            b"[project.urls]\nSource = \"https://example.invalid/matrix\"\n"
        ),
        "src/daimon_matrix/__init__.py": b'__version__ = "0.1.0"\n',
        "src/daimon_matrix/cli.py": b"def main() -> None:\n    return None\n",
        "src/daimon_matrix/py.typed": b"\n",
    }
    for relative, raw in matrix_files.items():
        target = matrix / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    subprocess.run(["git", "-C", matrix, "add", "."], check=True)
    subprocess.run(["git", "-C", matrix, "commit", "-qm", "package"], check=True)
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


def _matrix_metadata(matrix: Path) -> bytes:
    return (
        b"Metadata-Version: 2.4\n"
        b"Name: daimon-matrix\n"
        b"Version: 0.1.0\n"
        b"Summary: fixture Matrix\n"
        b"Project-URL: Source, https://example.invalid/matrix\n"
        b"Author: RC Test\n"
        b"License-Expression: MIT\n"
        b"License-File: LICENSE\n"
        b"Classifier: Programming Language :: Python :: 3\n"
        b"Requires-Python: >=3.11\n"
        b"Requires-Dist: fixture-dependency==1.0\n"
        b"Description-Content-Type: text/markdown\n\n"
        + (matrix / "README.md").read_bytes()
    )


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
    package_files = {
        path.removeprefix("src/"): (matrix / path).read_bytes()
        for path in (
            "src/daimon_matrix/__init__.py",
            "src/daimon_matrix/cli.py",
            "src/daimon_matrix/py.typed",
        )
    }
    distribution = "daimon_matrix-0.1.0.dist-info"
    wheel_files = {
        **package_files,
        f"{distribution}/METADATA": _matrix_metadata(matrix),
        f"{distribution}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: hatchling 1.31.0\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{distribution}/entry_points.txt": (
            b"[console_scripts]\ndaimon = daimon_matrix.cli:main\n"
        ),
        f"{distribution}/licenses/LICENSE": (matrix / "LICENSE").read_bytes(),
    }
    record_name = f"{distribution}/RECORD"
    record = "".join(
        f"{name},sha256="
        f"{urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()},"
        f"{len(raw)}\n"
        for name, raw in wheel_files.items()
    ) + f"{record_name},,\n"
    wheel_files[record_name] = record.encode("ascii")
    matrix_wheel = artifact_root / "daimon_matrix-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(matrix_wheel, mode="w") as wheel_archive:
        for name, raw in wheel_files.items():
            wheel_archive.writestr(name, raw)
    matrix_sdist = artifact_root / "daimon_matrix-0.1.0.tar.gz"
    sdist_files = {
        f"daimon_matrix-0.1.0/{path}": (matrix / path).read_bytes()
        for path in (
            ".gitignore",
            "LICENSE",
            "README.md",
            "pyproject.toml",
            "src/daimon_matrix/__init__.py",
            "src/daimon_matrix/cli.py",
            "src/daimon_matrix/py.typed",
        )
    }
    sdist_files["daimon_matrix-0.1.0/PKG-INFO"] = _matrix_metadata(matrix)
    with tarfile.open(matrix_sdist, mode="w:gz") as sdist_archive:
        for name, raw in sdist_files.items():
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

    component_refs = {
        name: {
            "commit": subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD"], text=True
            ).strip(),
            "tree": subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD^{tree}"], text=True
            ).strip(),
        }
        for name, repository in repositories.items()
    }
    for name in repositories:
        source = next(
            row
            for row in artifacts[name]
            if row["kind"] == ("git-bundle" if name == "daimon-matrix" else "git-archive")
        )
        probe_names = ["import", "installed-metadata", "smoke"]
        if name == "daimon-matrix":
            probe_names.insert(0, "direct-url-commit")
        install_evidence = {
            "schema": "daimon-offline-install-evidence/v1",
            "producer": "daimon-rc-offline-qualifier/v1",
            "producer_commit": component_refs["daimon-cluster"]["commit"],
            "component": name,
            "commit": component_refs[name]["commit"],
            "tree": component_refs[name]["tree"],
            "source_artifact": source["name"],
            "source_sha256": source["sha256"],
            "inputs": [
                {"name": row["name"], "sha256": row["sha256"]}
                for row in sorted(artifacts[name], key=lambda item: item["name"])
            ],
            "platform": "fixture-linux-x86_64",
            "installations": [
                {
                    "python": "3.13",
                    "network": "disabled",
                    "result": "passed",
                    "source": (
                        "vcs-direct-url" if name == "daimon-matrix" else "git-archive"
                    ),
                    "installed_commit": component_refs[name]["commit"],
                    "installed_tree": component_refs[name]["tree"],
                    "probes": [
                        {
                            "name": probe,
                            "result": "passed",
                            "output_sha256": hashlib.sha256(
                                f"{name}:{probe}:passed".encode()
                            ).hexdigest(),
                        }
                        for probe in probe_names
                    ],
                }
            ],
        }
        evidence_path = artifact_root / f"{name}-install-evidence.json"
        evidence_path.write_text(
            json.dumps(
                install_evidence,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n",
            encoding="ascii",
        )
        evidence_path.chmod(0o600)
        artifacts[name].append(
            {
                "name": "install-evidence",
                "kind": "install-evidence",
                "path": evidence_path.name,
                "bytes": evidence_path.stat().st_size,
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        )

    evidence = {
        name: [
            {
                "path": "README.md",
                "sha256": hashlib.sha256(
                    (repository / "README.md").read_bytes()
                ).hexdigest(),
            }
        ]
        for name, repository in repositories.items()
    }
    receipts = {}
    for name, repository in repositories.items():
        commit = component_refs[name]["commit"]
        tree = component_refs[name]["tree"]
        install_evidence = next(
            row for row in artifacts[name] if row["kind"] == "install-evidence"
        )
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
                    "evidence_ref": {
                        "artifact": install_evidence["name"],
                        "sha256": install_evidence["sha256"],
                    },
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
        "evidence": evidence,
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
    with pytest.raises(ManifestError, match="install_evidence_invalid"):
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
    qualification = _qualification(matrix, cluster, tribe)
    artifact_root = _artifact_root(matrix)
    wheel = _artifact(qualification, "daimon-matrix", "python-wheel")
    wheel_path = artifact_root / wheel["path"]
    distribution = "daimon_matrix-0.1.0.dist-info"
    minimal = {
        f"{distribution}/METADATA": _matrix_metadata(matrix),
        f"{distribution}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: hatchling 1.31.0\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"{distribution}/entry_points.txt": (
            b"[console_scripts]\ndaimon = daimon_matrix.cli:main\n"
        ),
        f"{distribution}/licenses/LICENSE": (matrix / "LICENSE").read_bytes(),
    }
    record_name = f"{distribution}/RECORD"
    record = "".join(
        f"{name},sha256="
        f"{urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()},"
        f"{len(raw)}\n"
        for name, raw in minimal.items()
    ) + f"{record_name},,\n"
    minimal[record_name] = record.encode("ascii")
    with zipfile.ZipFile(wheel_path, mode="w") as wheel_archive:
        for name, raw in minimal.items():
            wheel_archive.writestr(name, raw)
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

    qualification = _qualification(matrix, cluster, tribe)
    sdist = _artifact(qualification, "daimon-matrix", "python-sdist")
    sdist_path = artifact_root / sdist["path"]
    minimal_sdist = {
        f"daimon_matrix-0.1.0/{name}": (matrix / name).read_bytes()
        for name in (".gitignore", "LICENSE", "README.md", "pyproject.toml")
    }
    minimal_sdist["daimon_matrix-0.1.0/PKG-INFO"] = _matrix_metadata(matrix)
    with tarfile.open(sdist_path, mode="w:gz") as sdist_archive:
        for name, raw in minimal_sdist.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            sdist_archive.addfile(info, io.BytesIO(raw))
    _refresh_artifact(qualification, artifact_root, "daimon-matrix", "python-sdist")
    with pytest.raises(ManifestError, match="qualification_python_sdist_invalid"):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )

    qualification = _qualification(matrix, cluster, tribe)
    wheel = _artifact(qualification, "daimon-matrix", "python-wheel")
    wheel_path = artifact_root / wheel["path"]
    with zipfile.ZipFile(wheel_path) as wheel_archive:
        wheel_files = {
            name: wheel_archive.read(name)
            for name in wheel_archive.namelist()
            if not name.endswith(".dist-info/RECORD")
        }
    wheel_files["daimon_matrix/cli.py"] = b"def main(): return 'substituted'\n"
    record_name = "daimon_matrix-0.1.0.dist-info/RECORD"
    record = "".join(
        f"{name},sha256="
        f"{urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()},"
        f"{len(raw)}\n"
        for name, raw in wheel_files.items()
    ) + f"{record_name},,\n"
    wheel_files[record_name] = record.encode("ascii")
    with zipfile.ZipFile(wheel_path, mode="w") as wheel_archive:
        for name, raw in wheel_files.items():
            wheel_archive.writestr(name, raw)
    _refresh_artifact(qualification, artifact_root, "daimon-matrix", "python-wheel")
    with pytest.raises(
        ManifestError, match="qualification_python_wheel_source_mismatch"
    ):
        build_manifest(
            matrix,
            cluster,
            tribe,
            qualification,
            baselines=_baselines(matrix, cluster, tribe),
            artifact_root=artifact_root,
        )

    qualification = _qualification(matrix, cluster, tribe)
    wheel = _artifact(qualification, "daimon-matrix", "python-wheel")
    wheel_path = artifact_root / wheel["path"]
    with zipfile.ZipFile(wheel_path) as wheel_archive:
        wheel_files = {
            name: wheel_archive.read(name)
            for name in wheel_archive.namelist()
            if not name.endswith(".dist-info/RECORD")
        }
    metadata_name = "daimon_matrix-0.1.0.dist-info/METADATA"
    wheel_files[metadata_name] = wheel_files[metadata_name].replace(
        b"Requires-Dist: fixture-dependency==1.0",
        b"Requires-Dist: untrusted-substitute==9.9",
    )
    record = "".join(
        f"{name},sha256="
        f"{urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b'=').decode()},"
        f"{len(raw)}\n"
        for name, raw in wheel_files.items()
    ) + f"{record_name},,\n"
    wheel_files[record_name] = record.encode("ascii")
    with zipfile.ZipFile(wheel_path, mode="w") as wheel_archive:
        for name, raw in wheel_files.items():
            wheel_archive.writestr(name, raw)
    _refresh_artifact(qualification, artifact_root, "daimon-matrix", "python-wheel")
    with pytest.raises(
        ManifestError, match="qualification_python_package_metadata_mismatch"
    ):
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
    install_row = _artifact(qualification, "daimon-matrix", "install-evidence")
    install_path = _artifact_root(matrix) / install_row["path"]
    install_evidence = json.loads(install_path.read_bytes())
    install_evidence["installations"][0]["probes"].pop()
    install_path.write_text(
        json.dumps(
            install_evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n",
        encoding="ascii",
    )
    _refresh_artifact(
        qualification, _artifact_root(matrix), "daimon-matrix", "install-evidence"
    )
    with pytest.raises(
        ManifestError, match="qualification_install_evidence_invalid:daimon-matrix"
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
    qualification["artifact_receipts"]["daimon-cluster"]["installations"][0][
        "evidence_ref"
    ]["sha256"] = "0" * 64
    with pytest.raises(
        ManifestError, match="qualification_receipt_installation_invalid:daimon-cluster"
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
    qualification["evidence"]["tribe-bridge"][0]["sha256"] = "0" * 64
    qualification["artifact_receipts"]["tribe-bridge"]["installations"][0][
        "evidence_ref"
    ]["sha256"] = "0" * 64
    with pytest.raises(
        ManifestError, match="qualification_evidence_mismatch:tribe-bridge"
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
