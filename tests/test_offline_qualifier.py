"""Executable, network-isolated install-evidence qualification tests."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

from tools.build_rc_manifest import ManifestError, _install_evidence
from tools.qualify_offline import (
    CANONICAL_SOURCE_DATE_EPOCH,
    QualificationError,
    _owner_file,
    _verified_plan,
    produce_evidence,
    replay_evidence,
)


def test_canonical_source_date_epoch_is_deterministic_and_zip_safe() -> None:
    date_time = time.gmtime(int(CANONICAL_SOURCE_DATE_EPOCH))[:6]
    assert date_time == (2000, 1, 1, 0, 0, 0)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(zipfile.ZipInfo("metadata", date_time=date_time), b"")
    assert output.getvalue().startswith(b"PK")


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", repository, *arguments], text=True
    ).strip()


def _commit_repository(path: Path, files: dict[str, bytes]) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", path], check=True)
    subprocess.run(["git", "-C", path, "config", "user.name", "Qualifier Test"], check=True)
    subprocess.run(["git", "-C", path, "config", "user.email", "qualifier@example.invalid"], check=True)
    for relative, raw in files.items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    subprocess.run(["git", "-C", path, "add", "-A"], check=True)
    subprocess.run(["git", "-C", path, "commit", "-qm", "fixture"], check=True)
    return path


BACKEND = b'''from __future__ import annotations
import csv, hashlib, os, zipfile
from base64 import urlsafe_b64encode
from pathlib import Path

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = "daimon_matrix-0.0.0-py3-none-any.whl"
    dist = "daimon_matrix-0.0.0.dist-info"
    files = {
        "daimon_matrix/__init__.py": Path("src/daimon_matrix/__init__.py").read_bytes(),
        "daimon_matrix/cli.py": Path("src/daimon_matrix/cli.py").read_bytes(),
        f"{dist}/METADATA": b"Metadata-Version: 2.4\\nName: daimon-matrix\\nVersion: 0.0.0\\n\\n",
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
        f"{dist}/entry_points.txt": b"[console_scripts]\\ndaimon = daimon_matrix.cli:main\\n",
    }
    record = f"{dist}/RECORD"
    rows = []
    for path, raw in files.items():
        digest = urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        rows.append([path, "sha256=" + digest, str(len(raw))])
    rows.append([record, "", ""])
    import io
    output = io.StringIO(); csv.writer(output, lineterminator="\\n").writerows(rows)
    files[record] = output.getvalue().encode()
    destination = Path(wheel_directory) / name
    with zipfile.ZipFile(destination, "w") as archive:
        for path, raw in files.items(): archive.writestr(path, raw)
    return name
'''


def _matrix_fixture(tmp_path: Path) -> tuple[dict, Path, Path, dict[str, dict[str, object]], dict[str, Path]]:
    matrix = _commit_repository(
        tmp_path / "matrix",
        {
            "README.md": b"fixture\n",
            "backend.py": BACKEND,
            "pyproject.toml": b'''[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["."]\n\n[project]\nname="daimon-matrix"\nversion="0.0.0"\n''',
            "src/daimon_matrix/__init__.py": b'__version__ = "0.0.0"\n',
            "src/daimon_matrix/cli.py": b'def main():\n    print("fixture daimon")\n',
        },
    )
    qualifier_raw = Path(__file__).parents[1].joinpath("tools/qualify_offline.py").read_bytes()
    cluster = _commit_repository(
        tmp_path / "cluster",
        {"README.md": b"producer\n", "tools/qualify_offline.py": qualifier_raw},
    )
    artifacts_root = tmp_path / "artifacts"
    artifacts_root.mkdir(mode=0o700)
    bundle = artifacts_root / "matrix.bundle"
    subprocess.run(["git", "-C", matrix, "bundle", "create", bundle, "HEAD"], check=True)
    wheel = artifacts_root / "daimon_matrix-0.0.0-py3-none-any.whl"
    namespace: dict[str, object] = {}
    exec(BACKEND, namespace)
    previous_directory = Path.cwd()
    try:
        os.chdir(matrix)
        namespace["build_wheel"](os.fspath(artifacts_root))
    finally:
        os.chdir(previous_directory)
    sdist = artifacts_root / "daimon_matrix-0.0.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for relative in ("backend.py", "pyproject.toml", "README.md", "src/daimon_matrix/__init__.py", "src/daimon_matrix/cli.py"):
            raw = (matrix / relative).read_bytes()
            info = tarfile.TarInfo(f"daimon_matrix-0.0.0/{relative}")
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    wheelhouse = artifacts_root / "wheelhouse.tar"
    with tarfile.open(wheelhouse, "w") as archive:
        directory = tarfile.TarInfo("wheelhouse")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
    files = {
        "source-bundle": bundle,
        "wheel": wheel,
        "sdist": sdist,
        "wheelhouse": wheelhouse,
    }
    kinds = {
        "source-bundle": "git-bundle",
        "wheel": "python-wheel",
        "sdist": "python-sdist",
        "wheelhouse": "wheelhouse",
    }
    rows = {
        name: {
            "kind": kinds[name],
            "name": name,
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for name, path in files.items()
    }
    executable = Path(sys.executable).resolve()
    plan = {
        "schema": "daimon-offline-qualification-plan/v1",
        "component": "daimon-matrix",
        "commit": _git(matrix, "rev-parse", "HEAD"),
        "tree": _git(matrix, "rev-parse", "HEAD^{tree}"),
        "repository": os.fspath(matrix),
        "cluster_repository": os.fspath(cluster),
        "producer_commit": _git(cluster, "rev-parse", "HEAD"),
        "source_artifact": "source-bundle",
        "wheelhouse_artifact": "wheelhouse",
        "matrix_dependency": None,
        "artifacts": [
            {**row, "path": os.fspath(files[name])} for name, row in sorted(rows.items())
        ],
        "python": [{"version": f"{sys.version_info.major}.{sys.version_info.minor}", "executable": os.fspath(executable)}],
    }
    for path in files.values():
        path.chmod(0o600)
    return plan, matrix, cluster, rows, files


def test_real_disposable_evidence_is_deterministic_replayed_and_freezer_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, matrix, cluster, rows, files = _matrix_fixture(tmp_path)
    monkeypatch.setenv("DAIMON_QUALIFIER_POISON", "must-not-enter-sandbox")
    first = produce_evidence(plan)
    second = produce_evidence(plan)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    replay_evidence(first, plan)
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(first, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    evidence_path.chmod(0o600)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    installations = _install_evidence(
        evidence_path,
        "daimon-matrix",
        {"commit": plan["commit"], "tree": plan["tree"]},
        "source-bundle",
        rows["source-bundle"]["sha256"],
        [{"name": name, "sha256": row["sha256"]} for name, row in sorted(rows.items())],
        {version},
        plan["producer_commit"],
        matrix,
        cluster,
        rows,
        files,
        {"commit": plan["commit"], "tree": plan["tree"]},
        {version: Path(sys.executable).resolve()},
    )
    assert installations[version]["result"] == "passed"


def test_tamper_and_missing_execution_transcript_fail_replay(tmp_path: Path) -> None:
    plan, *_ = _matrix_fixture(tmp_path)
    evidence = produce_evidence(plan)
    tampered = json.loads(json.dumps(evidence))
    tampered["installations"][0]["execution"]["stdout_sha256"] = "0" * 64
    with pytest.raises(QualificationError, match="replay_mismatch"):
        replay_evidence(tampered, plan)
    missing = json.loads(json.dumps(evidence))
    del missing["installations"][0]["execution"]
    with pytest.raises(QualificationError, match="replay_mismatch"):
        replay_evidence(missing, plan)


@pytest.mark.parametrize("component", ["daimon-cluster", "tribe-bridge"])
def test_real_source_component_branches_run_in_bubblewrap(
    tmp_path: Path, component: str
) -> None:
    matrix_plan, matrix, producer, _, matrix_files = _matrix_fixture(tmp_path)
    matrix_commit = matrix_plan["commit"]
    qualifier_raw = Path(__file__).parents[1].joinpath("tools/qualify_offline.py").read_bytes()
    if component == "daimon-cluster":
        files = {
            "README.md": b"cluster\n",
            "requirements-weave.txt": (
                "daimon-matrix @ git+https://github.com/AlterMundi/"
                f"daimon-matrix.git@{matrix_commit}\n"
            ).encode(),
            "tools/qualify_offline.py": qualifier_raw,
            "clusterctl/__init__.py": b"",
            "clusterctl/cli.py": b'import argparse\ndef main(): argparse.ArgumentParser().parse_args()\nif __name__ == "__main__": main()\n',
            "clusterctl/matrix_host.py": (
                "import importlib.metadata,json\n"
                f'MATRIX_CONTRACT_COMMIT="{matrix_commit}"\n'
                "def _matrix_api():\n"
                " d=importlib.metadata.distribution('daimon-matrix'); u=json.loads(d.read_text('direct_url.json')); assert u['vcs_info']['commit_id']==MATRIX_CONTRACT_COMMIT; return {}\n"
            ).encode(),
            "clusterd/__init__.py": b"",
            "steward_tools/__init__.py": b"",
        }
    else:
        files = {
            "README.md": b"tribe\n",
            "protocol/v1/requirements-test.txt": b"",
            "src/tribe_protocol_v1.py": b"VALUE = 1\n",
            "src/tribe_crypto_v1.py": b"VALUE = 1\n",
            "src/tribe_client_v1.py": b"VALUE = 1\n",
            "scripts/tribe": b'''#!/bin/bash\nexec "${TRIBE_V1_PYTHON}" -c 'print("tribe fixture")'\n''',
        }
    repository = _commit_repository(tmp_path / component, files)
    source = tmp_path / "artifacts" / f"{component}.tar"
    source.write_bytes(
        subprocess.check_output(["git", "-C", repository, "archive", "--format=tar", "HEAD"])
    )
    source.chmod(0o600)
    artifacts = [
        {
            "kind": "git-archive",
            "name": "source-archive",
            "path": os.fspath(source),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        {
            "kind": "wheelhouse",
            "name": "wheelhouse",
            "path": os.fspath(matrix_files["wheelhouse"]),
            "sha256": hashlib.sha256(matrix_files["wheelhouse"].read_bytes()).hexdigest(),
        },
    ]
    dependency = None
    if component == "daimon-cluster":
        artifacts.append(
            {
                "kind": "matrix-git-bundle",
                "name": "matrix-source-bundle",
                "path": os.fspath(matrix_files["source-bundle"]),
                "sha256": hashlib.sha256(matrix_files["source-bundle"].read_bytes()).hexdigest(),
            }
        )
        dependency = {"commit": matrix_commit, "tree": matrix_plan["tree"]}
        producer = repository
    executable = Path(sys.executable).resolve()
    plan = {
        "schema": "daimon-offline-qualification-plan/v1",
        "component": component,
        "commit": _git(repository, "rev-parse", "HEAD"),
        "tree": _git(repository, "rev-parse", "HEAD^{tree}"),
        "repository": os.fspath(repository),
        "cluster_repository": os.fspath(producer),
        "producer_commit": _git(producer, "rev-parse", "HEAD"),
        "source_artifact": "source-archive",
        "wheelhouse_artifact": "wheelhouse",
        "matrix_dependency": dependency,
        "artifacts": artifacts,
        "python": [{"version": f"{sys.version_info.major}.{sys.version_info.minor}", "executable": os.fspath(executable)}],
    }
    evidence = produce_evidence(plan)
    replay_evidence(evidence, plan)


@pytest.mark.parametrize("name", ["../escape", "/tmp/escape", ".", "a/b"])
def test_artifact_names_cannot_escape_private_snapshot(tmp_path: Path, name: str) -> None:
    plan, *_ = _matrix_fixture(tmp_path)
    plan["artifacts"][0]["name"] = name
    with pytest.raises(QualificationError, match="artifact_inventory_invalid"):
        _verified_plan(plan)


def test_qualification_json_cannot_select_an_executable(tmp_path: Path) -> None:
    plan, matrix, cluster, rows, files = _matrix_fixture(tmp_path)
    evidence_path = tmp_path / "evidence.json"
    evidence = {
        "schema": "daimon-offline-install-evidence/v1",
        "producer": {"commit": plan["producer_commit"], "name": "daimon-rc-offline-qualifier/v1", "path": "tools/qualify_offline.py", "sha256": "1" * 64},
        "component": "daimon-matrix", "commit": plan["commit"], "tree": plan["tree"],
        "source_artifact": "source-bundle", "source_sha256": rows["source-bundle"]["sha256"],
        "inputs": [{"name": n, "sha256": r["sha256"]} for n, r in sorted(rows.items())],
        "platform": {"machine": "x", "system": "Linux"},
        "installations": [],
    }
    evidence_path.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n")
    evidence_path.chmod(0o600)
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    with pytest.raises(ManifestError, match="install_evidence_invalid"):
        _install_evidence(evidence_path, "daimon-matrix", {"commit": plan["commit"], "tree": plan["tree"]}, "source-bundle", rows["source-bundle"]["sha256"], evidence["inputs"], {version}, plan["producer_commit"], matrix, cluster, rows, files, {"commit": plan["commit"], "tree": plan["tree"]}, {version: Path(sys.executable).resolve()})


def test_explicit_trusted_native_executable_may_have_multiple_hardlinks() -> None:
    executable = Path(sys.executable).resolve()
    with tempfile.TemporaryDirectory(
        prefix=".qualifier-hardlink-", dir=Path.home()
    ) as raw_directory:
        first = Path(raw_directory) / f"original-{executable.name}"
        linked = Path(raw_directory) / executable.name
        shutil.copyfile(executable, first)
        first.chmod(0o700)
        os.link(first, linked)
        assert linked.stat().st_nlink >= 2
        assert _owner_file(linked, executable=True) == linked


def test_trusted_executable_under_writable_parent_is_rejected(tmp_path: Path) -> None:
    writable = tmp_path / "writable"
    writable.mkdir(mode=0o777)
    writable.chmod(0o777)
    candidate = writable / "python3.13"
    candidate.write_bytes(b"\x7fELFfixture")
    candidate.chmod(0o700)
    with pytest.raises(QualificationError, match="unsafe_interpreter_parent"):
        _owner_file(candidate, executable=True)


def test_trusted_executable_reports_unsafe_permissions(tmp_path: Path) -> None:
    candidate = tmp_path / "python3.13"
    candidate.write_bytes(b"\x7fELFfixture")
    candidate.chmod(0o722)
    with pytest.raises(
        QualificationError, match="unsafe_regular_file_permissions"
    ):
        _owner_file(candidate, executable=True)


def test_trusted_executable_reports_symlink(tmp_path: Path) -> None:
    target = tmp_path / "python3.13-real"
    target.write_bytes(b"\x7fELFfixture")
    target.chmod(0o700)
    candidate = tmp_path / "python3.13"
    candidate.symlink_to(target.name)
    with pytest.raises(QualificationError, match="unsafe_regular_file_symlink"):
        _owner_file(candidate, executable=True)


def test_script_cannot_impersonate_trusted_python(tmp_path: Path) -> None:
    plan, *_ = _matrix_fixture(tmp_path)
    candidate = tmp_path / "fake-python"
    candidate.write_text("#!/bin/sh\nprintf '3.13.0\\nCPython\\n/usr\\n'\n")
    candidate.chmod(0o700)
    plan["python"][0]["executable"] = os.fspath(candidate)
    with pytest.raises(QualificationError, match="interpreter_not_native_binary"):
        _verified_plan(plan)
