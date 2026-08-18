"""Freeze the three-repository V0 candidate into deterministic evidence.

The tool is intentionally read-only with respect to the repositories.  It
refuses dirty worktrees, verifies Cluster's exact Matrix source pin, validates
typed source/build artifacts and their offline-install receipts against the
exact component commits and trees, validates committed evidence and
supported-Python qualification, and atomically writes one new canonical
manifest. Re-running it over the same inputs produces the same bytes.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

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
QUALIFICATION_SCHEMA: Final = "daimon-release-qualification/v2"
ARTIFACT_RECEIPT_SCHEMA: Final = "daimon-artifact-qualification/v1"
INSTALL_EVIDENCE_SCHEMA: Final = "daimon-offline-install-evidence/v1"
_COMPONENT_NAMES: Final = frozenset(BASELINES)
_ARTIFACT_KINDS: Final = {
    "daimon-matrix": frozenset(
        {
            "git-bundle",
            "install-evidence",
            "python-sdist",
            "python-wheel",
            "runtime-lock",
            "wheelhouse",
        }
    ),
    "daimon-cluster": frozenset(
        {"git-archive", "install-evidence", "runtime-lock", "wheelhouse"}
    ),
    "tribe-bridge": frozenset(
        {"git-archive", "install-evidence", "runtime-lock", "wheelhouse"}
    ),
}
_REQUIRED_ARTIFACT_KINDS: Final = {
    "daimon-matrix": frozenset(
        {"git-bundle", "install-evidence", "python-sdist", "python-wheel"}
    ),
    "daimon-cluster": frozenset({"git-archive", "install-evidence"}),
    "tribe-bridge": frozenset({"git-archive", "install-evidence"}),
}
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_RELEASE: Final = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+rc[1-9][0-9]*$")
_PYTHON: Final = re.compile(r"^3\.(?:[0-9]|1[0-9])$")
_EVIDENCE_PATH: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_REQUIRED_HUMAN_GATES: Final = frozenset(
    {
        "cross-being-consent",
        "live-custody",
        "physical-hosts-and-backup-target",
        "physical-rehearsal-go",
        "publication-and-cutover",
        "tribe-live-operations",
        "tribe-retirement",
    }
)
_MAX_QUALIFICATION_BYTES: Final = 1024 * 1024
_MAX_PACKAGE_MEMBER_BYTES: Final = 512 * 1024 * 1024
_MAX_PACKAGE_METADATA_BYTES: Final = 1024 * 1024
_MAX_PACKAGE_MEMBERS: Final = 10_000


class ManifestError(RuntimeError):
    """The candidate cannot be frozen reproducibly."""


@dataclass(frozen=True)
class Component:
    name: str
    repository: Path


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ManifestError(code)
    return value


def _component_map(value: Any, code: str) -> Mapping[str, Any]:
    return _closed(value, set(_COMPONENT_NAMES), code)


def _nonempty_strings(value: Any, code: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ManifestError(code)
    return list(value)


def _git(repository: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        result = subprocess.run(
            ["git", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as exception:
        raise ManifestError(
            f"git_{arguments[0]}_failed:{repository.name}"
        ) from exception
    return result.stdout


def _isolated_git(*arguments: str, cwd: Path | None = None) -> str:
    """Run Git without ambient config or hooks while inspecting an artifact."""

    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *arguments],
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exception:
        raise ManifestError("qualification_git_bundle_invalid") from exception
    return result.stdout


def _verify_git_bundle(path: Path, commit: str, tree: str) -> None:
    """Prove a bundle is a complete, single-head object source for the candidate."""

    heads = _isolated_git("bundle", "list-heads", os.fspath(path)).splitlines()
    if heads != [f"{commit} HEAD"]:
        raise ManifestError("qualification_git_bundle_head_mismatch")
    with tempfile.TemporaryDirectory(prefix="daimon-rc-bundle-") as raw_directory:
        repository = Path(raw_directory) / "objects.git"
        _isolated_git("init", "--bare", "--quiet", os.fspath(repository))
        # Verification in an empty repository rejects prerequisite/shallow bundles.
        _isolated_git("-C", os.fspath(repository), "bundle", "verify", os.fspath(path))
        _isolated_git(
            "-C", os.fspath(repository), "bundle", "unbundle", os.fspath(path)
        )
        _isolated_git(
            "-C", os.fspath(repository), "update-ref", "refs/heads/candidate", commit
        )
        observed_tree = _isolated_git(
            "-C", os.fspath(repository), "rev-parse", f"{commit}^{{tree}}"
        ).strip()
        if observed_tree != tree:
            raise ManifestError("qualification_git_bundle_tree_mismatch")
        _isolated_git(
            "-C",
            os.fspath(repository),
            "fsck",
            "--strict",
            "--full",
            "--no-dangling",
        )


def _safe_package_member(name: str) -> bool:
    path = Path(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def _metadata_field(raw: bytes, field: str) -> str:
    if len(raw) > _MAX_PACKAGE_METADATA_BYTES:
        raise ManifestError("qualification_python_package_invalid")
    for line in raw.decode("utf-8", errors="strict").splitlines():
        key, separator, value = line.partition(":")
        if separator and key.lower() == field.lower():
            return value.strip()
    raise ManifestError("qualification_python_package_invalid")


def _git_file(repository: Path, commit: str, path: str) -> bytes:
    raw = _git(repository, "show", f"{commit}:{path}", text=False)
    if not isinstance(raw, bytes):
        raise ManifestError("qualification_matrix_source_invalid")
    return raw


def _matrix_source(
    repository: Path, commit: str
) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, Any], str]:
    listing = _git(
        repository, "ls-tree", "-r", "-z", commit, "--", "src/daimon_matrix"
    )
    if not isinstance(listing, str):
        raise ManifestError("qualification_matrix_source_invalid")
    package: dict[str, bytes] = {}
    sdist: dict[str, bytes] = {}
    for raw_row in listing.rstrip("\0").split("\0"):
        metadata, separator, source_path = raw_row.partition("\t")
        mode = metadata.partition(" ")[0]
        if separator != "\t" or mode not in {"100644", "100755"}:
            raise ManifestError("qualification_matrix_source_invalid")
        relative = source_path.removeprefix("src/")
        if relative == source_path or not _safe_package_member(relative):
            raise ManifestError("qualification_matrix_source_invalid")
        content = _git_file(repository, commit, source_path)
        package[relative] = content
        sdist[source_path] = content
    if not package or "daimon_matrix/__init__.py" not in package:
        raise ManifestError("qualification_matrix_source_invalid")
    for source_path in (".gitignore", "LICENSE", "README.md", "pyproject.toml"):
        sdist[source_path] = _git_file(repository, commit, source_path)
    try:
        project = tomllib.loads(sdist["pyproject.toml"].decode("utf-8"))["project"]
        name = project["name"]
        version = project["version"]
        raw_scripts = project["scripts"]
        if (
            name != "daimon-matrix"
            or not isinstance(version, str)
            or not version
            or project["readme"] != "README.md"
            or not isinstance(project["description"], str)
            or not isinstance(project["requires-python"], str)
            or not isinstance(project["license"], str)
            or not isinstance(project["license-files"], list)
            or not isinstance(project["dependencies"], list)
            or not isinstance(project["classifiers"], list)
            or not isinstance(project["authors"], list)
            or not isinstance(project["urls"], Mapping)
            or not isinstance(raw_scripts, Mapping)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in raw_scripts.items()
            )
        ):
            raise ManifestError("qualification_matrix_source_invalid")
        build_requires = tomllib.loads(sdist["pyproject.toml"].decode("utf-8"))[
            "build-system"
        ]["requires"]
        hatchling = next(
            value.removeprefix("hatchling==")
            for value in build_requires
            if isinstance(value, str) and value.startswith("hatchling==")
        )
    except (KeyError, StopIteration, TypeError, UnicodeError, tomllib.TOMLDecodeError) as exception:
        raise ManifestError("qualification_matrix_source_invalid") from exception
    return package, sdist, dict(project), hatchling


def _metadata_values(raw: bytes, field: str) -> list[str]:
    if len(raw) > _MAX_PACKAGE_METADATA_BYTES:
        raise ManifestError("qualification_python_package_invalid")
    prefix = f"{field}:".lower()
    return [
        line.partition(":")[2].strip()
        for line in raw.decode("utf-8", errors="strict").splitlines()
        if line.lower().startswith(prefix)
    ]


def _verify_project_metadata(raw: bytes, project: Mapping[str, Any], readme: bytes) -> None:
    headers, separator, body = raw.partition(b"\n\n")
    authors = project["authors"]
    if (
        not separator
        or body != readme
        or _metadata_values(headers, "Metadata-Version") != ["2.4"]
        or _metadata_values(headers, "Name") != [project["name"]]
        or _metadata_values(headers, "Version") != [project["version"]]
        or _metadata_values(headers, "Summary") != [project["description"]]
        or _metadata_values(headers, "Requires-Python")
        != [project["requires-python"]]
        or _metadata_values(headers, "License-Expression") != [project["license"]]
        or _metadata_values(headers, "License-File") != project["license-files"]
        or _metadata_values(headers, "Requires-Dist") != project["dependencies"]
        or _metadata_values(headers, "Classifier") != project["classifiers"]
        or _metadata_values(headers, "Project-URL")
        != [f"{name}, {url}" for name, url in project["urls"].items()]
        or _metadata_values(headers, "Author")
        != [", ".join(author["name"] for author in authors)]
        or _metadata_values(headers, "Description-Content-Type") != ["text/markdown"]
    ):
        raise ManifestError("qualification_python_package_metadata_mismatch")


def _archive_bytes(archive: zipfile.ZipFile, name: str) -> bytes:
    with archive.open(name) as source:
        return source.read(_MAX_PACKAGE_MEMBER_BYTES + 1)


def _verify_wheel_record(
    archive: zipfile.ZipFile, record_name: str, expected_names: set[str]
) -> None:
    try:
        rows = list(
            csv.reader(
                io.StringIO(_archive_bytes(archive, record_name).decode("utf-8"))
            )
        )
    except (csv.Error, UnicodeError) as exception:
        raise ManifestError("qualification_python_wheel_invalid") from exception
    if len(rows) != len(expected_names) or any(len(row) != 3 for row in rows):
        raise ManifestError("qualification_python_wheel_invalid")
    by_name = {row[0]: row[1:] for row in rows}
    if set(by_name) != expected_names or by_name[record_name] != ["", ""]:
        raise ManifestError("qualification_python_wheel_invalid")
    for name in expected_names - {record_name}:
        content = _archive_bytes(archive, name)
        encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
        if by_name[name] != [f"sha256={encoded.decode('ascii')}", str(len(content))]:
            raise ManifestError("qualification_python_wheel_invalid")


def _verify_python_wheel(path: Path, repository: Path, commit: str) -> None:
    package, source_files, project, hatchling = _matrix_source(repository, commit)
    version = project["version"]
    scripts = project["scripts"]
    distribution = f"daimon_matrix-{version}.dist-info"
    generated = {
        f"{distribution}/METADATA",
        f"{distribution}/WHEEL",
        f"{distribution}/entry_points.txt",
        f"{distribution}/licenses/LICENSE",
        f"{distribution}/RECORD",
    }
    expected_names = set(package) | generated
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if (
                path.name != f"daimon_matrix-{version}-py3-none-any.whl"
                or not 1 <= len(members) <= _MAX_PACKAGE_MEMBERS
                or set(names) != expected_names
                or len(names) != len(expected_names)
                or any(not _safe_package_member(name) for name in names)
                or any(member.flag_bits & 0x1 for member in members)
                or any(
                    stat.S_ISLNK((member.external_attr >> 16) & 0xFFFF)
                    for member in members
                )
                or sum(member.file_size for member in members)
                > _MAX_PACKAGE_MEMBER_BYTES
            ):
                raise ManifestError("qualification_python_wheel_invalid")
            for name, expected in package.items():
                if _archive_bytes(archive, name) != expected:
                    raise ManifestError("qualification_python_wheel_source_mismatch")
            if _archive_bytes(archive, f"{distribution}/licenses/LICENSE") != _git_file(
                repository, commit, "LICENSE"
            ):
                raise ManifestError("qualification_python_wheel_source_mismatch")
            metadata = _archive_bytes(archive, f"{distribution}/METADATA")
            wheel = _archive_bytes(archive, f"{distribution}/WHEEL")
            expected_entries = "[console_scripts]\n" + "".join(
                f"{name} = {target}\n" for name, target in sorted(scripts.items())
            )
            if (
                _archive_bytes(archive, f"{distribution}/entry_points.txt")
                != expected_entries.encode("utf-8")
                or _metadata_field(wheel, "Wheel-Version") != "1.0"
                or _metadata_field(wheel, "Generator") != f"hatchling {hatchling}"
                or _metadata_field(wheel, "Root-Is-Purelib") != "true"
                or _metadata_field(wheel, "Tag") != "py3-none-any"
            ):
                raise ManifestError("qualification_python_wheel_invalid")
            _verify_project_metadata(metadata, project, source_files["README.md"])
            _verify_wheel_record(
                archive, f"{distribution}/RECORD", expected_names
            )
    except ManifestError:
        raise
    except (OSError, UnicodeError, zipfile.BadZipFile) as exception:
        raise ManifestError("qualification_python_wheel_invalid") from exception


def _verify_python_sdist(path: Path, repository: Path, commit: str) -> None:
    _, source_files, project, _ = _matrix_source(repository, commit)
    version = project["version"]
    root = f"daimon_matrix-{version}"
    expected_files = {f"{root}/{name}": value for name, value in source_files.items()}
    metadata_name = f"{root}/PKG-INFO"
    expected_names = set(expected_files) | {metadata_name}
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if (
                path.name != f"daimon_matrix-{version}.tar.gz"
                or not 1 <= len(members) <= _MAX_PACKAGE_MEMBERS
                or set(names) != expected_names
                or len(names) != len(expected_names)
                or any(not _safe_package_member(name) for name in names)
                or any(
                    not member.isfile()
                    for member in members
                )
                or sum(member.size for member in members) > _MAX_PACKAGE_MEMBER_BYTES
            ):
                raise ManifestError("qualification_python_sdist_invalid")
            for name, expected in expected_files.items():
                member = archive.extractfile(name)
                if member is None or member.read(len(expected) + 1) != expected:
                    raise ManifestError("qualification_python_sdist_source_mismatch")
            metadata_member = archive.extractfile(metadata_name)
            metadata = (
                b""
                if metadata_member is None
                else metadata_member.read(_MAX_PACKAGE_METADATA_BYTES + 1)
            )
            if (
                metadata_member is None
            ):
                raise ManifestError("qualification_python_sdist_invalid")
            _verify_project_metadata(metadata, project, source_files["README.md"])
    except ManifestError:
        raise
    except (OSError, UnicodeError, tarfile.TarError) as exception:
        raise ManifestError("qualification_python_sdist_invalid") from exception


def _read_canonical_json_artifact(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (OSError, UnicodeError, ValueError) as exception:
        raise ManifestError("qualification_install_evidence_invalid") from exception
    if (
        not 1 <= len(raw) <= _MAX_QUALIFICATION_BYTES
        or raw not in {canonical, canonical + b"\n"}
        or not isinstance(value, Mapping)
    ):
        raise ManifestError("qualification_install_evidence_invalid")
    return value


def _install_evidence(
    path: Path,
    component: str,
    frozen: Mapping[str, object],
    source_name: str,
    source_sha256: str,
    expected_inputs: list[dict[str, str]],
    supported_python: set[str],
    producer_commit: str,
) -> dict[str, Mapping[str, Any]]:
    evidence = _closed(
        _read_canonical_json_artifact(path),
        {
            "commit",
            "component",
            "installations",
            "inputs",
            "platform",
            "producer",
            "producer_commit",
            "schema",
            "source_artifact",
            "source_sha256",
            "tree",
        },
        "qualification_install_evidence_malformed",
    )
    if (
        evidence["schema"] != INSTALL_EVIDENCE_SCHEMA
        or evidence["producer"] != "daimon-rc-offline-qualifier/v1"
        or evidence["producer_commit"] != producer_commit
        or evidence["component"] != component
        or evidence["commit"] != frozen["commit"]
        or evidence["tree"] != frozen["tree"]
        or evidence["source_artifact"] != source_name
        or evidence["source_sha256"] != source_sha256
        or evidence["inputs"] != expected_inputs
        or not isinstance(evidence["platform"], str)
        or not evidence["platform"]
        or not isinstance(evidence["installations"], list)
    ):
        raise ManifestError(f"qualification_install_evidence_invalid:{component}")
    expected_probes = ["import", "installed-metadata", "smoke"]
    if component == "daimon-matrix":
        expected_probes.insert(0, "direct-url-commit")
    installations: dict[str, Mapping[str, Any]] = {}
    for raw_installation in evidence["installations"]:
        installation = _closed(
            raw_installation,
            {
                "installed_commit",
                "installed_tree",
                "network",
                "probes",
                "python",
                "result",
                "source",
            },
            "qualification_install_evidence_malformed",
        )
        python = installation["python"]
        probes = installation["probes"]
        if not isinstance(probes, list):
            raise ManifestError(f"qualification_install_evidence_invalid:{component}")
        observed_probes: list[str] = []
        for raw_probe in probes:
            probe = _closed(
                raw_probe,
                {"name", "output_sha256", "result"},
                "qualification_install_evidence_malformed",
            )
            if (
                not isinstance(probe["name"], str)
                or probe["result"] != "passed"
                or not isinstance(probe["output_sha256"], str)
                or _SHA256.fullmatch(probe["output_sha256"]) is None
            ):
                raise ManifestError(
                    f"qualification_install_evidence_invalid:{component}"
                )
            observed_probes.append(probe["name"])
        expected_source = (
            "vcs-direct-url" if component == "daimon-matrix" else "git-archive"
        )
        if (
            not isinstance(python, str)
            or python not in supported_python
            or python in installations
            or installation["network"] != "disabled"
            or installation["result"] != "passed"
            or installation["source"] != expected_source
            or installation["installed_commit"] != frozen["commit"]
            or installation["installed_tree"] != frozen["tree"]
            or observed_probes != expected_probes
        ):
            raise ManifestError(f"qualification_install_evidence_invalid:{component}")
        installations[python] = installation
    expected_versions = sorted(
        supported_python, key=lambda item: tuple(map(int, item.split(".")))
    )
    if list(installations) != expected_versions:
        raise ManifestError(f"qualification_install_evidence_invalid:{component}")
    return installations


def _closed_repository(component: Component) -> dict[str, object]:
    repository = component.repository.resolve(strict=True)
    if not repository.is_dir():
        raise ManifestError(f"repository_not_directory:{component.name}")
    status = str(_git(repository, "status", "--porcelain=v1", "--untracked-files=all"))
    if status:
        raise ManifestError(f"dirty_worktree:{component.name}")
    shallow = str(_git(repository, "rev-parse", "--is-shallow-repository")).strip()
    if shallow != "false":
        raise ManifestError(f"shallow_repository:{component.name}")
    commit = str(_git(repository, "rev-parse", "--verify", "HEAD^{commit}")).strip()
    tree = str(_git(repository, "rev-parse", f"{commit}^{{tree}}")).strip()
    archive_value = _git(repository, "archive", "--format=tar", commit, text=False)
    if not isinstance(archive_value, bytes):
        raise ManifestError(f"git_archive_not_binary:{component.name}")
    archive = archive_value
    return {
        "archive_bytes": len(archive),
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


def _verified_evidence(
    value: Any,
    components: tuple[Component, ...],
    frozen: Mapping[str, Mapping[str, object]],
) -> None:
    evidence = _component_map(value, "qualification_evidence_malformed")
    repositories = {
        component.name: component.repository.resolve(strict=True)
        for component in components
    }
    for name in _COMPONENT_NAMES:
        rows = evidence[name]
        if not isinstance(rows, list) or not rows:
            raise ManifestError("qualification_evidence_invalid")
        observed: set[str] = set()
        for raw_row in rows:
            row = _closed(
                raw_row, {"path", "sha256"}, "qualification_evidence_malformed"
            )
            path = row["path"]
            digest = row["sha256"]
            if (
                not isinstance(path, str)
                or _EVIDENCE_PATH.fullmatch(path) is None
                or ".." in Path(path).parts
                or path in observed
                or not isinstance(digest, str)
                or _SHA256.fullmatch(digest) is None
            ):
                raise ManifestError("qualification_evidence_invalid")
            object_type = _git(
                repositories[name],
                "cat-file",
                "-t",
                f"{frozen[name]['commit']}:{path}",
            )
            if not isinstance(object_type, str) or object_type.strip() != "blob":
                raise ManifestError("qualification_evidence_invalid")
            raw = _git(
                repositories[name],
                "show",
                f"{frozen[name]['commit']}:{path}",
                text=False,
            )
            if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != digest:
                raise ManifestError(f"qualification_evidence_mismatch:{name}:{path}")
            observed.add(path)


def _qualification(
    value: Any,
    components: tuple[Component, ...],
    frozen: Mapping[str, Mapping[str, object]],
    artifact_root: Path | None,
) -> dict[str, Any]:
    qualification = _closed(
        value,
        {
            "artifact_receipts",
            "artifacts",
            "evidence",
            "human_gates",
            "limitations",
            "release",
            "schema",
            "supported_python",
            "tests",
        },
        "qualification_malformed",
    )
    if (
        qualification["schema"] != QUALIFICATION_SCHEMA
        or not isinstance(qualification["release"], str)
        or _RELEASE.fullmatch(qualification["release"]) is None
    ):
        raise ManifestError("qualification_release_invalid")

    supported = _component_map(
        qualification["supported_python"], "qualification_python_malformed"
    )
    python_by_component: dict[str, set[str]] = {}
    for name in _COMPONENT_NAMES:
        versions = _nonempty_strings(supported[name], "qualification_python_invalid")
        if any(
            _PYTHON.fullmatch(version) is None for version in versions
        ) or versions != sorted(
            versions, key=lambda item: tuple(map(int, item.split(".")))
        ):
            raise ManifestError("qualification_python_invalid")
        python_by_component[name] = set(versions)

    repositories = {
        component.name: component.repository.resolve(strict=True)
        for component in components
    }
    _verified_evidence(qualification["evidence"], components, frozen)

    artifacts = _component_map(
        qualification["artifacts"], "qualification_artifacts_malformed"
    )
    for name in _COMPONENT_NAMES:
        rows = artifacts[name]
        if not isinstance(rows, list) or not rows or len(rows) > 64:
            raise ManifestError("qualification_artifacts_invalid")
    if artifact_root is None:
        raise ManifestError("qualification_artifact_root_missing")
    requested_root = Path(os.path.abspath(artifact_root))
    resolved_artifact_root = requested_root.resolve(strict=True)
    root_info = resolved_artifact_root.lstat()
    if (
        requested_root != resolved_artifact_root
        or not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
        or root_info.st_uid != os.geteuid()
        or stat.S_IMODE(root_info.st_mode) & 0o022
    ):
        raise ManifestError("qualification_artifact_root_rejected")
    artifact_paths: set[str] = set()
    artifact_rows: dict[str, dict[str, dict[str, object]]] = {}
    artifact_files: dict[str, dict[str, Path]] = {}
    for name in _COMPONENT_NAMES:
        rows = artifacts[name]
        assert isinstance(rows, list)
        names: set[str] = set()
        kinds: set[str] = set()
        artifact_rows[name] = {}
        artifact_files[name] = {}
        for raw_row in rows:
            row = _closed(
                raw_row,
                {"bytes", "kind", "name", "path", "sha256"},
                "qualification_artifact_malformed",
            )
            path = row["path"]
            kind = row["kind"]
            if (
                not isinstance(row["name"], str)
                or not row["name"]
                or row["name"] in names
                or not isinstance(kind, str)
                or kind not in _ARTIFACT_KINDS[name]
                or kind in kinds
                or not isinstance(path, str)
                or _EVIDENCE_PATH.fullmatch(path) is None
                or ".." in Path(path).parts
                or path in artifact_paths
                or not isinstance(row["bytes"], int)
                or isinstance(row["bytes"], bool)
                or row["bytes"] <= 0
                or not isinstance(row["sha256"], str)
                or _SHA256.fullmatch(row["sha256"]) is None
            ):
                raise ManifestError("qualification_artifact_invalid")
            candidate = resolved_artifact_root / path
            try:
                resolved_candidate = candidate.resolve(strict=True)
                info = candidate.lstat()
                if (
                    resolved_candidate != candidate
                    or not resolved_candidate.is_relative_to(resolved_artifact_root)
                    or stat.S_ISLNK(info.st_mode)
                    or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or info.st_size != row["bytes"]
                ):
                    raise ManifestError("qualification_artifact_invalid")
                descriptor = os.open(
                    candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    opened = os.fstat(descriptor)
                    digest = hashlib.sha256()
                    observed_bytes = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                        observed_bytes += len(chunk)
                finally:
                    os.close(descriptor)
                after = candidate.lstat()
            except OSError as exception:
                raise ManifestError("qualification_artifact_invalid") from exception
            if (
                (info.st_dev, info.st_ino, info.st_size)
                != (opened.st_dev, opened.st_ino, opened.st_size)
                or (info.st_dev, info.st_ino, info.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or observed_bytes != row["bytes"]
                or digest.hexdigest() != row["sha256"]
            ):
                raise ManifestError("qualification_artifact_mismatch")
            names.add(row["name"])
            kinds.add(kind)
            artifact_paths.add(path)
            artifact_rows[name][row["name"]] = dict(row)
            artifact_files[name][row["name"]] = candidate
            if kind == "git-archive":
                if (
                    row["bytes"] != frozen[name]["archive_bytes"]
                    or row["sha256"] != frozen[name]["archive_sha256"]
                ):
                    raise ManifestError(f"qualification_git_archive_mismatch:{name}")
            elif kind == "git-bundle":
                _verify_git_bundle(
                    candidate,
                    str(frozen[name]["commit"]),
                    str(frozen[name]["tree"]),
                )
            elif kind == "python-wheel":
                _verify_python_wheel(
                    candidate, repositories[name], str(frozen[name]["commit"])
                )
            elif kind == "python-sdist":
                _verify_python_sdist(
                    candidate, repositories[name], str(frozen[name]["commit"])
                )
        if not _REQUIRED_ARTIFACT_KINDS[name].issubset(kinds):
            raise ManifestError(f"qualification_artifact_kinds_incomplete:{name}")

    installation_evidence: dict[str, dict[str, Mapping[str, Any]]] = {}
    for name in _COMPONENT_NAMES:
        expected_source_kind = "git-bundle" if name == "daimon-matrix" else "git-archive"
        source_name = next(
            artifact_name
            for artifact_name, row in artifact_rows[name].items()
            if row["kind"] == expected_source_kind
        )
        evidence_name = next(
            artifact_name
            for artifact_name, row in artifact_rows[name].items()
            if row["kind"] == "install-evidence"
        )
        installation_evidence[name] = _install_evidence(
            artifact_files[name][evidence_name],
            name,
            frozen[name],
            source_name,
            str(artifact_rows[name][source_name]["sha256"]),
            [
                {"name": artifact_name, "sha256": str(row["sha256"])}
                for artifact_name, row in sorted(artifact_rows[name].items())
                if row["kind"] != "install-evidence"
            ],
            python_by_component[name],
            str(frozen["daimon-cluster"]["commit"]),
        )

    receipts = _component_map(
        qualification["artifact_receipts"], "qualification_receipts_malformed"
    )
    for name in _COMPONENT_NAMES:
        receipt = _closed(
            receipts[name],
            {
                "artifacts",
                "commit",
                "installations",
                "schema",
                "source_artifact",
                "tree",
            },
            "qualification_receipt_malformed",
        )
        expected_source_kind = "git-bundle" if name == "daimon-matrix" else "git-archive"
        source_names = [
            artifact_name
            for artifact_name, row in artifact_rows[name].items()
            if row["kind"] == expected_source_kind
        ]
        source_artifact = receipt["source_artifact"]
        if (
            receipt["schema"] != ARTIFACT_RECEIPT_SCHEMA
            or receipt["commit"] != frozen[name]["commit"]
            or receipt["tree"] != frozen[name]["tree"]
            or not isinstance(source_artifact, str)
            or source_names != [source_artifact]
        ):
            raise ManifestError(f"qualification_receipt_source_mismatch:{name}")
        inventory = receipt["artifacts"]
        expected_inventory = [
            {"name": artifact_name, "sha256": row["sha256"]}
            for artifact_name, row in sorted(artifact_rows[name].items())
        ]
        if not isinstance(inventory, list) or inventory != expected_inventory:
            raise ManifestError(f"qualification_receipt_inventory_mismatch:{name}")
        installations = receipt["installations"]
        if not isinstance(installations, list):
            raise ManifestError(f"qualification_receipt_installations_invalid:{name}")
        expected_source = "vcs-direct-url" if name == "daimon-matrix" else "git-archive"
        observed_versions: list[str] = []
        for raw_installation in installations:
            installation = _closed(
                raw_installation,
                {
                    "evidence_ref",
                    "installed_commit",
                    "installed_tree",
                    "network",
                    "python",
                    "result",
                    "source",
                },
                "qualification_receipt_installation_malformed",
            )
            python = installation["python"]
            evidence_ref = _closed(
                installation["evidence_ref"],
                {"artifact", "sha256"},
                "qualification_receipt_evidence_malformed",
            )
            evidence_names = [
                artifact_name
                for artifact_name, row in artifact_rows[name].items()
                if row["kind"] == "install-evidence"
            ]
            external_installation = (
                installation_evidence[name].get(python)
                if isinstance(python, str)
                else None
            )
            if (
                not isinstance(python, str)
                or python not in python_by_component[name]
                or installation["network"] != "disabled"
                or installation["result"] != "passed"
                or installation["source"] != expected_source
                or installation["installed_commit"] != frozen[name]["commit"]
                or installation["installed_tree"] != frozen[name]["tree"]
                or not isinstance(evidence_ref["artifact"], str)
                or not isinstance(evidence_ref["sha256"], str)
                or evidence_names != [evidence_ref["artifact"]]
                or evidence_ref["sha256"]
                != artifact_rows[name][evidence_ref["artifact"]]["sha256"]
                or external_installation is None
                or any(
                    installation[field] != external_installation[field]
                    for field in (
                        "installed_commit",
                        "installed_tree",
                        "network",
                        "python",
                        "result",
                        "source",
                    )
                )
            ):
                raise ManifestError(
                    f"qualification_receipt_installation_invalid:{name}"
                )
            observed_versions.append(python)
        expected_versions = sorted(
            python_by_component[name], key=lambda item: tuple(map(int, item.split(".")))
        )
        if observed_versions != expected_versions:
            raise ManifestError(f"qualification_receipt_python_coverage_incomplete:{name}")

    tests = _component_map(qualification["tests"], "qualification_tests_malformed")
    for name in _COMPONENT_NAMES:
        rows = tests[name]
        if not isinstance(rows, list) or not rows:
            raise ManifestError("qualification_tests_invalid")
        covered: set[str] = set()
        identities: set[tuple[str, str]] = set()
        for raw_row in rows:
            row = _closed(
                raw_row,
                {"name", "passed", "python", "skipped"},
                "qualification_test_malformed",
            )
            identity = (row["name"], row["python"])
            if (
                not isinstance(row["name"], str)
                or not row["name"]
                or not isinstance(row["python"], str)
                or row["python"] not in python_by_component[name]
                or identity in identities
                or not isinstance(row["passed"], int)
                or isinstance(row["passed"], bool)
                or row["passed"] <= 0
                or not isinstance(row["skipped"], int)
                or isinstance(row["skipped"], bool)
                or row["skipped"] < 0
            ):
                raise ManifestError("qualification_test_invalid")
            identities.add(identity)
            covered.add(row["python"])
        if covered != python_by_component[name]:
            raise ManifestError("qualification_python_coverage_incomplete")

    gates = _nonempty_strings(
        qualification["human_gates"], "qualification_gates_invalid"
    )
    if set(gates) != _REQUIRED_HUMAN_GATES or gates != sorted(gates):
        raise ManifestError("qualification_gates_invalid")
    _nonempty_strings(qualification["limitations"], "qualification_limitations_invalid")
    return json.loads(
        json.dumps(
            qualification, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    )


def build_manifest(
    matrix: Path,
    cluster: Path,
    tribe: Path,
    qualification: Mapping[str, Any],
    *,
    baselines: Mapping[str, Mapping[str, str]] = BASELINES,
    artifact_root: Path | None = None,
) -> dict[str, object]:
    components = (
        Component("daimon-matrix", matrix),
        Component("daimon-cluster", cluster),
        Component("tribe-bridge", tribe),
    )
    if set(baselines) != set(_COMPONENT_NAMES):
        raise ManifestError("baseline_malformed")
    frozen = {item.name: _closed_repository(item) for item in components}
    for component in components:
        baseline = _closed(
            baselines[component.name], {"commit", "tree"}, "baseline_malformed"
        )
        commit = baseline["commit"]
        tree = baseline["tree"]
        if (
            not isinstance(commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            or not isinstance(tree, str)
            or re.fullmatch(r"[0-9a-f]{40}", tree) is None
        ):
            raise ManifestError("baseline_malformed")
        repository = component.repository.resolve(strict=True)
        try:
            observed_commit = str(
                _git(repository, "rev-parse", "--verify", f"{commit}^{{commit}}")
            ).strip()
            observed_tree = str(
                _git(repository, "rev-parse", "--verify", f"{commit}^{{tree}}")
            ).strip()
            _git(
                repository,
                "merge-base",
                "--is-ancestor",
                commit,
                str(frozen[component.name]["commit"]),
            )
        except ManifestError as exception:
            raise ManifestError(
                f"baseline_not_ancestor:{component.name}"
            ) from exception
        if observed_commit != commit or observed_tree != tree:
            raise ManifestError(f"baseline_mismatch:{component.name}")
    cluster_repository = cluster.resolve(strict=True)
    pin = _matrix_pin(cluster_repository, str(frozen["daimon-cluster"]["commit"]))
    if pin != frozen["daimon-matrix"]["commit"]:
        raise ManifestError("cluster_matrix_pin_mismatch")
    qualified = _qualification(qualification, components, frozen, artifact_root)
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
        "baseline": json.loads(
            json.dumps(baselines, sort_keys=True, separators=(",", ":"))
        ),
        "components": frozen,
        "cross_repository": {
            "cluster_matrix_commit": pin,
            "cluster_matrix_pin": "requirements-weave.txt",
        },
        "qualification": qualified,
    }


def canonical_manifest(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def read_qualification(path: Path) -> Mapping[str, Any]:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 1 <= info.st_size <= _MAX_QUALIFICATION_BYTES
        ):
            raise ManifestError("qualification_file_rejected")
        chunks: list[bytes] = []
        remaining = _MAX_QUALIFICATION_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_QUALIFICATION_BYTES:
            raise ManifestError("qualification_file_rejected")
        value = json.loads(raw)
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if raw.rstrip(b"\n") != canonical or not isinstance(value, Mapping):
            raise ManifestError("qualification_file_not_canonical")
        return value
    except ManifestError:
        raise
    except (OSError, ValueError, UnicodeEncodeError) as exception:
        raise ManifestError("qualification_file_rejected") from exception
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_manifest(path: Path, raw: bytes) -> None:
    target = Path(os.path.abspath(path))
    parent = target.parent
    if parent.resolve(strict=False) != parent:
        raise ManifestError("manifest_parent_contains_symlink")
    try:
        info = parent.lstat()
    except FileNotFoundError as exception:
        raise ManifestError("manifest_parent_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ManifestError("manifest_parent_not_owner_controlled")
    directory = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    directory_info = os.fstat(directory)
    if (
        not stat.S_ISDIR(directory_info.st_mode)
        or directory_info.st_uid != os.geteuid()
        or stat.S_IMODE(directory_info.st_mode) & 0o022
        or (directory_info.st_dev, directory_info.st_ino) != (info.st_dev, info.st_ino)
    ):
        os.close(directory)
        raise ManifestError("manifest_parent_not_owner_controlled")
    temporary_name = f".{target.name}.{os.urandom(16).hex()}.tmp"
    descriptor = -1
    try:
        try:
            target_info = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            target_info = None
        if target_info is not None:
            if stat.S_ISLNK(target_info.st_mode):
                raise ManifestError("manifest_target_is_symlink")
            raise ManifestError("manifest_target_exists")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
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
        os.link(
            temporary_name,
            target.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory)
        os.fsync(directory)
    except ManifestError:
        raise
    except OSError as exception:
        raise ManifestError("manifest_write_failed") from exception
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
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    raw = canonical_manifest(
        build_manifest(
            arguments.matrix,
            arguments.cluster,
            arguments.tribe,
            read_qualification(arguments.qualification),
            artifact_root=arguments.artifact_root,
        )
    )
    write_manifest(arguments.output, raw)
    print(hashlib.sha256(raw).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
