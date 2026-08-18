#!/usr/bin/env python3
"""Execute and replay exact-artifact installs in a private network namespace.

The JSON emitted by this module is not an assertion that the freezer trusts.
``build_rc_manifest`` calls :func:`replay_evidence` and accepts it only when a
fresh bubblewrap run produces the same canonical execution transcript.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

PLAN_SCHEMA: Final = "daimon-offline-qualification-plan/v1"
EVIDENCE_SCHEMA: Final = "daimon-offline-install-evidence/v1"
PRODUCER: Final = "daimon-rc-offline-qualifier/v1"
TOOL_PATH: Final = "tools/qualify_offline.py"
COMPONENTS: Final = frozenset(
    {"daimon-matrix", "daimon-cluster", "tribe-bridge"}
)
SHA1: Final = re.compile(r"^[0-9a-f]{40}$")
SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
PYTHON_VERSION: Final = re.compile(r"^3\.(?:[0-9]|1[0-9])$")
ARTIFACT_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_MEMBERS: Final = 20_000
MAX_MEMBER_BYTES: Final = 512 * 1024 * 1024
CANONICAL_SOURCE_DATE_EPOCH: Final = "946684800"


class QualificationError(RuntimeError):
    """Offline qualification could not be reproduced exactly."""


def _externally_writable(info: os.stat_result) -> bool:
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o002:
        return True
    if not mode & 0o020:
        return False
    if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
        return True
    group = grp.getgrgid(info.st_gid)
    primary_users = {entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == info.st_gid}
    allowed = {pwd.getpwuid(os.geteuid()).pw_name}
    return set(group.gr_mem) | primary_users != allowed


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise QualificationError(code)
    return value


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        while chunk := os.read(descriptor, 1024 * 1024):
            value.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise QualificationError("artifact_changed_while_reading")
    return value.hexdigest()


def _owner_file(path: Path, *, executable: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    try:
        info = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as exception:
        raise QualificationError("unsafe_regular_file_missing") from exception
    if stat.S_ISLNK(info.st_mode):
        raise QualificationError("unsafe_regular_file_symlink")
    if absolute != resolved:
        raise QualificationError("unsafe_regular_file_path")
    if not stat.S_ISREG(info.st_mode):
        raise QualificationError("unsafe_regular_file_type")
    if info.st_nlink != 1 and not executable:
        raise QualificationError("unsafe_regular_file_links")
    if info.st_uid not in ({0, os.geteuid()} if executable else {os.geteuid()}):
        raise QualificationError("unsafe_regular_file_owner")
    writable = (
        _externally_writable(info)
        if executable
        else bool(stat.S_IMODE(info.st_mode) & 0o022)
    )
    if writable:
        raise QualificationError("unsafe_regular_file_permissions")
    if executable and not os.access(absolute, os.X_OK):
        raise QualificationError("unsafe_regular_file_not_executable")
    if executable:
        descriptor = -1
        try:
            descriptor = os.open(
                absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            opened = os.fstat(descriptor)
            prefix = os.read(descriptor, 4)
            opened_after = os.fstat(descriptor)
        except OSError as exception:
            raise QualificationError("unsafe_regular_file_changed") from exception
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_mode)
        if identity != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mode,
        ) or identity != (
            opened_after.st_dev,
            opened_after.st_ino,
            opened_after.st_size,
            opened_after.st_mode,
        ):
            raise QualificationError("unsafe_regular_file_changed")
        if prefix != b"\x7fELF":
            raise QualificationError("interpreter_not_native_binary")
        parent = absolute.parent
        while parent != parent.parent:
            parent_info = parent.stat()
            if parent_info.st_uid not in {0, os.geteuid()} or _externally_writable(parent_info):
                raise QualificationError("unsafe_interpreter_parent")
            parent = parent.parent
    return absolute


def _git(repository: Path, *arguments: str, binary: bool = False) -> str | bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        completed = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", os.fspath(repository), *arguments],
            check=True,
            capture_output=True,
            env=environment,
            text=not binary,
        )
    except (OSError, subprocess.CalledProcessError) as exception:
        raise QualificationError("git_verification_failed") from exception
    return completed.stdout


def _cluster_runtime_requirements(
    weave_requirements: str, runtime_requirements: str
) -> list[str]:
    matrix = re.compile(
        r"daimon-matrix @ git\+https://github\.com/AlterMundi/"
        r"daimon-matrix\.git@[0-9a-f]{40}"
    )
    pinned = re.compile(
        r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9._+-]*"
    )
    weave: list[str] = []
    matrix_count = 0
    for raw_line in weave_requirements.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if matrix.fullmatch(line) is not None:
            matrix_count += 1
            continue
        if pinned.fullmatch(line) is None or line in weave:
            raise QualificationError("cluster_runtime_requirement_invalid")
        weave.append(line)
    if matrix_count != 1:
        raise QualificationError("cluster_runtime_requirement_invalid")

    declared: list[str] = []
    include_count = 0
    for raw_line in runtime_requirements.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "-r requirements-weave.txt":
            include_count += 1
            continue
        if pinned.fullmatch(line) is None or line in declared:
            raise QualificationError("cluster_runtime_requirement_invalid")
        declared.append(line)
    if include_count != 1 or weave != declared:
        raise QualificationError("cluster_runtime_requirements_incomplete")
    return weave


def _isolated_git(*arguments: str) -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *arguments],
            check=True,
            capture_output=True,
            env=environment,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exception:
        raise QualificationError("git_verification_failed") from exception


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _write_new(path: Path, value: Any) -> None:
    target = Path(os.path.abspath(path))
    parent = target.parent.resolve(strict=True)
    info = parent.lstat()
    if (
        target.parent != parent
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise QualificationError("unsafe_output_parent")
    directory = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    opened_parent = os.fstat(directory)
    if (opened_parent.st_dev, opened_parent.st_ino) != (info.st_dev, info.st_ino):
        os.close(directory)
        raise QualificationError("unsafe_output_parent")
    temporary = f".{target.name}.{os.urandom(16).hex()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
        raw = _canonical(value)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(
            temporary,
            target.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _safe_tar(path: Path) -> None:
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= MAX_MEMBERS:
                raise QualificationError("unsafe_archive")
            names: set[str] = set()
            total = 0
            for member in members:
                member_path = Path(member.name)
                if (
                    not member.name
                    or member.name in names
                    or member_path.is_absolute()
                    or ".." in member_path.parts
                    or not (member.isfile() or member.isdir())
                    or member.size < 0
                    or member.size > MAX_MEMBER_BYTES
                ):
                    raise QualificationError("unsafe_archive")
                total += member.size
                names.add(member.name)
            if total > MAX_MEMBER_BYTES:
                raise QualificationError("unsafe_archive")
    except QualificationError:
        raise
    except (OSError, tarfile.TarError) as exception:
        raise QualificationError("unsafe_archive") from exception


def _normalise(raw: bytes, run_root: Path) -> bytes:
    result = raw.replace(os.fsencode(run_root), b"{RUN}").replace(b"\r\n", b"\n")
    result = re.sub(rb"/work/tmp/[A-Za-z0-9._-]+", b"/work/tmp/{TMP}", result)
    result = re.sub(rb"\bin [0-9]+(?:\.[0-9]+)?s\b", b"in {TIME}s", result)
    return result


PROBE: Final = r'''from __future__ import annotations
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys

component = os.environ["QUAL_COMPONENT"]
source = Path(os.environ["QUAL_SOURCE"])
commit = os.environ["QUAL_COMMIT"]
tree = os.environ["QUAL_TREE"]
if "DAIMON_QUALIFIER_POISON" in os.environ:
    raise SystemExit("ambient environment leaked into sandbox")

def emit(name, value):
    Path(name).write_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n", encoding="ascii")

owned = {
    "daimon-matrix": ["daimon_matrix"],
    "daimon-cluster": ["clusterctl", "clusterd", "steward_tools"],
    "tribe-bridge": ["tribe_protocol_v1", "tribe_crypto_v1", "tribe_client_v1"],
}[component]
imports = []
for name in owned:
    module = importlib.import_module(name)
    module_file = Path(module.__file__).resolve()
    imports.append({"module": name, "file_sha256": hashlib.sha256(module_file.read_bytes()).hexdigest()})
emit("probe-import.out", {"component": component, "imports": imports})

metadata = {"component": component, "commit": commit, "tree": tree, "python": platform_python() if False else sys.version.split()[0]}
if component == "daimon-matrix":
    distribution = importlib.metadata.distribution("daimon-matrix")
    metadata.update({"distribution": distribution.metadata["Name"], "version": distribution.version})
elif component == "daimon-cluster":
    from clusterctl.matrix_host import MATRIX_CONTRACT_COMMIT, _matrix_api
    _matrix_api()
    direct = json.loads(importlib.metadata.distribution("daimon-matrix").read_text("direct_url.json"))
    vcs = direct.get("vcs_info", {})
    if vcs.get("commit_id") != MATRIX_CONTRACT_COMMIT:
        raise SystemExit("Cluster Matrix direct_url commit mismatch")
    metadata.update({"matrix_commit": vcs["commit_id"]})
emit("probe-installed-metadata.out", metadata)

if component == "daimon-matrix":
    direct = json.loads(importlib.metadata.distribution("daimon-matrix").read_text("direct_url.json"))
    vcs = direct.get("vcs_info", {})
    if vcs.get("vcs") != "git" or vcs.get("commit_id") != commit or vcs.get("requested_revision") != commit:
        raise SystemExit("direct_url commit mismatch")
    emit("probe-direct-url-commit.out", {"commit_id": vcs["commit_id"], "requested_revision": vcs["requested_revision"], "vcs": vcs["vcs"]})
    command = [str(Path(sys.executable).parent / "daimon"), "--help"]
elif component == "daimon-cluster":
    command = [sys.executable, "-m", "clusterctl.cli", "--help"]
else:
    command = ["/bin/bash", str(source / "scripts" / "tribe"), "--help"]
smoke_env = dict(os.environ)
smoke_env["TRIBE_V1_PYTHON"] = sys.executable
completed = subprocess.run(command, cwd=source, env=smoke_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
if completed.returncode != 0:
    raise SystemExit(f"smoke failed: {completed.returncode}")
Path("probe-smoke.out").write_bytes(completed.stdout)
checked = subprocess.run([sys.executable, "-m", "pip", "check"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
if checked.returncode != 0:
    raise SystemExit("pip check failed")
Path("probe-dependency-check.out").write_bytes(checked.stdout)
'''


SHELL: Final = r'''
set -euo pipefail
umask 077
mkdir -m 700 "$HOME" "$TMPDIR" wheelhouse source
tar -xf "$QUAL_WHEELHOUSE" -C wheelhouse --no-same-owner --no-same-permissions
test "$("$QUAL_PYTHON" -I -c 'import sys; print(sys.base_prefix)')" = /python
"$QUAL_PYTHON" -m venv --copies venv
if [[ "$QUAL_COMPONENT" == daimon-matrix ]]; then
  rmdir source
  git clone -q "$QUAL_ARTIFACT" source
  test "$(git -C source rev-parse HEAD)" = "$QUAL_COMMIT"
  test "$(git -C source rev-parse HEAD^{tree})" = "$QUAL_TREE"
  venv/bin/python -m pip install -qqq --no-index --find-links wheelhouse --no-cache-dir "git+file://$PWD/source@$QUAL_COMMIT"
  "$QUAL_PYTHON" -m venv --copies venv-wheel
  venv-wheel/bin/python -m pip install -qqq --no-index --find-links wheelhouse --no-cache-dir "$QUAL_MATRIX_WHEEL"
  venv-wheel/bin/python -I -c 'import daimon_matrix; print(daimon_matrix.__file__)' > probe-wheel-install.out
  venv-wheel/bin/python -m pip check >> probe-wheel-install.out
  "$QUAL_PYTHON" -m venv --copies venv-sdist
  venv-sdist/bin/python -m pip install -qqq --no-index --find-links wheelhouse --no-cache-dir "$QUAL_MATRIX_SDIST"
  venv-sdist/bin/python -I -c 'import daimon_matrix; print(daimon_matrix.__file__)' > probe-sdist-install.out
  venv-sdist/bin/python -m pip check >> probe-sdist-install.out
elif [[ "$QUAL_COMPONENT" == daimon-cluster ]]; then
  tar -xf "$QUAL_ARTIFACT" -C source --no-same-owner --no-same-permissions
  git -C source init -q
  git -C source add -f --all
  test "$(git -C source write-tree)" = "$QUAL_TREE"
  git clone -q "$QUAL_MATRIX_BUNDLE" matrix-source
  test "$(git -C matrix-source rev-parse HEAD)" = "$QUAL_MATRIX_COMMIT"
  venv/bin/python -m pip install -qqq --no-index --find-links wheelhouse --no-cache-dir "git+file://$PWD/matrix-source@$QUAL_MATRIX_COMMIT"
  if [[ -s runtime-requirements.txt ]]; then venv/bin/python -m pip install -qqq --no-index --find-links wheelhouse --no-cache-dir -r runtime-requirements.txt; fi
else
  tar -xf "$QUAL_ARTIFACT" -C source --no-same-owner --no-same-permissions
  git -C source init -q
  git -C source add -f --all
  test "$(git -C source write-tree)" = "$QUAL_TREE"
  test -f source/protocol/v1/requirements-test.txt
  if [[ -s source/protocol/v1/requirements-test.txt ]]; then venv/bin/python -m pip install -qqq --no-index --find-links wheelhouse --no-cache-dir -r source/protocol/v1/requirements-test.txt; fi
fi
cd "$QUAL_RUN"
if [[ "$QUAL_COMPONENT" != daimon-matrix ]]; then
  export PYTHONPATH="$QUAL_SOURCE"
  if [[ "$QUAL_COMPONENT" == tribe-bridge ]]; then export PYTHONPATH="$QUAL_SOURCE/src:$PYTHONPATH"; fi
fi
venv/bin/python probe.py
'''


def _producer(cluster_repository: Path, producer_commit: str) -> dict[str, str]:
    if SHA1.fullmatch(producer_commit) is None:
        raise QualificationError("invalid_producer_commit")
    raw = _git(cluster_repository, "show", f"{producer_commit}:{TOOL_PATH}", binary=True)
    if not isinstance(raw, bytes) or raw != Path(__file__).read_bytes():
        raise QualificationError("producer_tool_blob_mismatch")
    return {
        "commit": producer_commit,
        "name": PRODUCER,
        "path": TOOL_PATH,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _verified_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    value = _closed(
        plan,
        {
            "artifacts",
            "cluster_repository",
            "commit",
            "component",
            "matrix_dependency",
            "producer_commit",
            "python",
            "repository",
            "schema",
            "source_artifact",
            "tree",
            "wheelhouse_artifact",
        },
        "plan_malformed",
    )
    component = value["component"]
    commit = value["commit"]
    tree = value["tree"]
    if (
        value["schema"] != PLAN_SCHEMA
        or component not in COMPONENTS
        or not isinstance(commit, str)
        or SHA1.fullmatch(commit) is None
        or not isinstance(tree, str)
        or SHA1.fullmatch(tree) is None
    ):
        raise QualificationError("plan_identity_invalid")
    repository = Path(str(value["repository"])).resolve(strict=True)
    cluster_repository = Path(str(value["cluster_repository"])).resolve(strict=True)
    observed_commit = str(_git(repository, "rev-parse", "HEAD^{commit}")).strip()
    observed_tree = str(_git(repository, "rev-parse", "HEAD^{tree}")).strip()
    if observed_commit != commit or observed_tree != tree:
        raise QualificationError("repository_identity_mismatch")
    producer = _producer(cluster_repository, str(value["producer_commit"]))
    rows = value["artifacts"]
    if not isinstance(rows, list) or not rows:
        raise QualificationError("artifact_inventory_invalid")
    artifacts: dict[str, dict[str, str]] = {}
    for raw_row in rows:
        row = _closed(raw_row, {"kind", "name", "path", "sha256"}, "artifact_row_malformed")
        name = row["name"]
        digest = row["sha256"]
        if (
            not isinstance(name, str)
            or ARTIFACT_NAME.fullmatch(name) is None
            or name in artifacts
            or not isinstance(row["kind"], str)
            or not isinstance(row["path"], str)
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise QualificationError("artifact_inventory_invalid")
        path = _owner_file(Path(row["path"]))
        if _digest(path) != digest:
            raise QualificationError("artifact_hash_mismatch")
        artifacts[name] = {"kind": str(row["kind"]), "name": name, "path": os.fspath(path), "sha256": digest}
    source_name = value["source_artifact"]
    wheelhouse_name = value["wheelhouse_artifact"]
    if source_name not in artifacts or wheelhouse_name not in artifacts:
        raise QualificationError("qualification_inputs_missing")
    source = Path(artifacts[str(source_name)]["path"])
    wheelhouse = Path(artifacts[str(wheelhouse_name)]["path"])
    matrix_bundle: Path | None = None
    matrix_commit = ""
    runtime_requirements: list[str] = []
    matrix_dependency = value["matrix_dependency"]
    if component == "daimon-cluster":
        dependency = _closed(matrix_dependency, {"commit", "tree"}, "cluster_matrix_dependency_malformed")
        bundle_rows = [row for row in artifacts.values() if row["kind"] == "matrix-git-bundle"]
        if len(bundle_rows) != 1:
            raise QualificationError("cluster_matrix_bundle_missing")
        matrix_bundle = Path(bundle_rows[0]["path"])
        raw_pin = _git(repository, "show", f"{commit}:requirements-weave.txt")
        if not isinstance(raw_pin, str):
            raise QualificationError("cluster_matrix_pin_invalid")
        matches = re.findall(r"daimon-matrix @ git\+https://github\.com/AlterMundi/daimon-matrix\.git@([0-9a-f]{40})", raw_pin)
        if len(matches) != 1:
            raise QualificationError("cluster_matrix_pin_invalid")
        matrix_commit = matches[0]
        raw_runtime = _git(repository, "show", f"{commit}:requirements.txt")
        if not isinstance(raw_runtime, str):
            raise QualificationError("cluster_runtime_requirement_invalid")
        runtime_requirements = _cluster_runtime_requirements(raw_pin, raw_runtime)
        if dependency["commit"] != matrix_commit or not isinstance(dependency["tree"], str) or SHA1.fullmatch(dependency["tree"]) is None:
            raise QualificationError("cluster_matrix_dependency_mismatch")
        heads = _isolated_git("bundle", "list-heads", os.fspath(matrix_bundle)).splitlines()
        if heads != [f"{matrix_commit} HEAD"]:
            raise QualificationError("cluster_matrix_bundle_mismatch")
        with tempfile.TemporaryDirectory(prefix="daimon-cluster-matrix-bundle-") as raw:
            checkout = Path(raw) / "repo"
            _isolated_git("clone", "-q", os.fspath(matrix_bundle), os.fspath(checkout))
            if str(_git(checkout, "rev-parse", "HEAD^{tree}")).strip() != dependency["tree"]:
                raise QualificationError("cluster_matrix_bundle_mismatch")
            _git(checkout, "fsck", "--strict", "--full", "--no-dangling")
    elif matrix_dependency is not None:
        raise QualificationError("unexpected_matrix_dependency")
    _safe_tar(wheelhouse)
    if component == "daimon-matrix":
        heads = _isolated_git("bundle", "list-heads", os.fspath(source)).splitlines()
        if heads != [f"{commit} HEAD"]:
            raise QualificationError("bundle_head_mismatch")
        with tempfile.TemporaryDirectory(prefix="daimon-bundle-check-") as raw:
            checkout = Path(raw) / "repo"
            _isolated_git("clone", "-q", os.fspath(source), os.fspath(checkout))
            if str(_git(checkout, "rev-parse", "HEAD^{tree}")).strip() != tree:
                raise QualificationError("bundle_tree_mismatch")
            _git(checkout, "fsck", "--strict", "--full", "--no-dangling")
        if len([row for row in artifacts.values() if row["kind"] == "python-wheel"]) != 1 or len([row for row in artifacts.values() if row["kind"] == "python-sdist"]) != 1:
            raise QualificationError("matrix_package_artifacts_missing")
    else:
        _safe_tar(source)
        archived = _git(repository, "archive", "--format=tar", commit, binary=True)
        if not isinstance(archived, bytes) or hashlib.sha256(archived).hexdigest() != artifacts[str(source_name)]["sha256"]:
            raise QualificationError("archive_not_exact")
    pythons = value["python"]
    if not isinstance(pythons, list) or not pythons:
        raise QualificationError("python_matrix_invalid")
    interpreters: list[dict[str, str]] = []
    observed_versions: set[str] = set()
    for raw_python in pythons:
        row = _closed(raw_python, {"executable", "version"}, "python_row_malformed")
        version = row["version"]
        if not isinstance(version, str) or PYTHON_VERSION.fullmatch(version) is None or version in observed_versions:
            raise QualificationError("python_matrix_invalid")
        executable = _owner_file(Path(str(row["executable"])), executable=True)
        completed = subprocess.run(
            [executable, "-I", "-c", "import platform,sys; print(platform.python_version()); print(platform.python_implementation()); print(sys.base_prefix)"],
            check=True,
            capture_output=True,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            text=True,
        ).stdout.splitlines()
        if len(completed) != 3 or ".".join(completed[0].split(".")[:2]) != version:
            raise QualificationError("python_version_mismatch")
        base_prefix = Path(completed[2]).resolve(strict=True)
        if base_prefix == Path("/") or executable.parent != base_prefix / "bin":
            raise QualificationError("python_prefix_rejected")
        interpreters.append({"base_prefix": os.fspath(base_prefix), "executable": os.fspath(executable), "executable_sha256": _digest(executable), "implementation": completed[1], "version": version, "version_full": completed[0]})
        observed_versions.add(version)
    if [item["version"] for item in interpreters] != sorted(observed_versions, key=lambda item: tuple(map(int, item.split(".")))):
        raise QualificationError("python_matrix_invalid")
    return {"artifacts": artifacts, "cluster_repository": cluster_repository, "commit": commit, "component": component, "interpreters": interpreters, "matrix_bundle": matrix_bundle, "matrix_commit": matrix_commit, "producer": producer, "repository": repository, "runtime_requirements": runtime_requirements, "source": source, "source_name": source_name, "tree": tree, "wheelhouse": wheelhouse}


def _run_version(verified: Mapping[str, Any], interpreter: Mapping[str, str]) -> dict[str, Any]:
    bwrap_raw = Path("/usr/bin/bwrap")
    if not bwrap_raw.exists():
        raise QualificationError("bubblewrap_missing")
    bwrap = _owner_file(bwrap_raw, executable=True)
    with tempfile.TemporaryDirectory(prefix="daimon-offline-qualifier-") as raw_root:
        run_root = Path(raw_root).resolve()
        run_root.chmod(0o700)
        inputs = run_root / "inputs"
        inputs.mkdir(mode=0o700)
        snapshots: dict[str, Path] = {}
        snapshot_names: set[str] = set()
        for name, row in verified["artifacts"].items():
            source_basename = Path(row["path"]).name
            if (
                ARTIFACT_NAME.fullmatch(source_basename) is None
                or source_basename in snapshot_names
            ):
                raise QualificationError("artifact_filename_invalid")
            snapshot_names.add(source_basename)
            destination = inputs / source_basename
            source_descriptor = os.open(
                row["path"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            target_descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            observed = hashlib.sha256()
            try:
                before = os.fstat(source_descriptor)
                while chunk := os.read(source_descriptor, 1024 * 1024):
                    observed.update(chunk)
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(target_descriptor, chunk[offset:])
                os.fsync(target_descriptor)
                after = os.fstat(source_descriptor)
            finally:
                os.close(source_descriptor)
                os.close(target_descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size)
                != (after.st_dev, after.st_ino, after.st_size)
                or observed.hexdigest() != row["sha256"]
            ):
                raise QualificationError("artifact_snapshot_mismatch")
            snapshots[name] = destination
        probe = run_root / "probe.py"
        probe.write_text(PROBE, encoding="utf-8")
        probe.chmod(0o600)
        requirements = run_root / "runtime-requirements.txt"
        requirements.write_text(
            "".join(f"{item}\n" for item in verified["runtime_requirements"]),
            encoding="ascii",
        )
        requirements.chmod(0o600)
        env = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_KEY_0": "advice.detachedHead",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": "/work/home",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_LIBRARY_PATH": "/python/lib",
            "PATH": "/usr/bin:/bin",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_FIND_LINKS": "/work/wheelhouse",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_NO_INDEX": "1",
            "PIP_PROGRESS_BAR": "off",
            "PIP_ROOT_USER_ACTION": "ignore",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "QUAL_ARTIFACT": "/work/inputs/" + snapshots[str(verified["source_name"])].name,
            "QUAL_COMMIT": str(verified["commit"]),
            "QUAL_COMPONENT": str(verified["component"]),
            "QUAL_MATRIX_BUNDLE": "" if verified["matrix_bundle"] is None else "/work/inputs/" + snapshots[next(name for name, row in verified["artifacts"].items() if row["kind"] == "matrix-git-bundle")].name,
            "QUAL_MATRIX_COMMIT": str(verified["matrix_commit"]),
            "QUAL_MATRIX_SDIST": "" if verified["component"] != "daimon-matrix" else "/work/inputs/" + snapshots[next(name for name, row in verified["artifacts"].items() if row["kind"] == "python-sdist")].name,
            "QUAL_MATRIX_WHEEL": "" if verified["component"] != "daimon-matrix" else "/work/inputs/" + snapshots[next(name for name, row in verified["artifacts"].items() if row["kind"] == "python-wheel")].name,
            "QUAL_PYTHON": "/python/bin/" + Path(interpreter["executable"]).name,
            "QUAL_RUN": "/work",
            "QUAL_SOURCE": "/work/source",
            "QUAL_TREE": str(verified["tree"]),
            "QUAL_WHEELHOUSE": "/work/inputs/" + snapshots[next(name for name, row in verified["artifacts"].items() if row["kind"] == "wheelhouse")].name,
            "SOURCE_DATE_EPOCH": CANONICAL_SOURCE_DATE_EPOCH,
            "TMPDIR": "/work/tmp",
            "TZ": "UTC",
        }
        interpreter_prefix = Path(interpreter["base_prefix"])
        command = [
            os.fspath(bwrap),
            "--die-with-parent",
            "--unshare-all",
            "--new-session",
            "--clearenv",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt",
            "--tmpfs", "/tmp",
            "--dev", "/dev",
            "--proc", "/proc",
            "--ro-bind", os.fspath(interpreter_prefix), "/python",
            "--dir", "/work",
            "--bind", os.fspath(run_root), "/work",
            "--chdir", "/work",
        ]
        for key, value in sorted(env.items()):
            command.extend(("--setenv", key, value))
        command.extend(("/bin/bash", "-c", SHELL))
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                timeout=900,
            )
        except subprocess.TimeoutExpired as exception:
            raise QualificationError(
                f"offline_install_timeout:{verified['component']}:{interpreter['version']}"
            ) from exception
        stdout = _normalise(completed.stdout, run_root)
        stderr = _normalise(completed.stderr, run_root)
        if completed.returncode != 0:
            raise QualificationError(
                f"offline_install_failed:{verified['component']}:{interpreter['version']}:"
                f"{hashlib.sha256(stdout + stderr).hexdigest()}"
            )
        probe_names = ["import", "installed-metadata", "smoke", "dependency-check"]
        if verified["component"] == "daimon-matrix":
            probe_names.insert(0, "direct-url-commit")
            probe_names.extend(("wheel-install", "sdist-install"))
        probes: list[dict[str, str]] = []
        for name in probe_names:
            output = _owner_file(run_root / f"probe-{name}.out")
            probes.append({"name": name, "output_sha256": _digest(output), "result": "passed"})
        return {
            "execution": {
                "contract_sha256": hashlib.sha256((PROBE + "\0" + SHELL).encode()).hexdigest(),
                "ca_bundle_sha256": _digest(Path("/etc/ssl/certs/ca-certificates.crt")),
                "exit_code": completed.returncode,
                "sandbox": "bubblewrap-unshare-all",
                "sandbox_executable": os.fspath(bwrap),
                "sandbox_sha256": _digest(bwrap),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            },
            "installed_commit": verified["commit"],
            "installed_tree": verified["tree"],
            "interpreter": dict(interpreter),
            "network": "disabled",
            "probes": probes,
            "python": interpreter["version"],
            "result": "passed",
            "source": "vcs-direct-url" if verified["component"] == "daimon-matrix" else "git-archive",
        }


def produce_evidence(plan: Mapping[str, Any]) -> dict[str, Any]:
    verified = _verified_plan(plan)
    installations = [_run_version(verified, row) for row in verified["interpreters"]]
    uname = platform.uname()
    inputs = [
        {"name": name, "sha256": row["sha256"]}
        for name, row in sorted(verified["artifacts"].items())
    ]
    return {
        "commit": verified["commit"],
        "component": verified["component"],
        "inputs": inputs,
        "installations": installations,
        "platform": {"machine": uname.machine, "system": uname.system},
        "producer": verified["producer"],
        "schema": EVIDENCE_SCHEMA,
        "source_artifact": verified["source_name"],
        "source_sha256": next(row["sha256"] for row in inputs if row["name"] == verified["source_name"]),
        "tree": verified["tree"],
    }


def replay_evidence(evidence: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    expected = produce_evidence(plan)
    if _canonical(evidence) != _canonical(expected):
        raise QualificationError("execution_evidence_replay_mismatch")


def _read_plan(path: Path) -> Mapping[str, Any]:
    source = _owner_file(path)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
            total += len(chunk)
            if total > 1024 * 1024:
                raise QualificationError("plan_too_large")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise QualificationError("plan_changed_while_reading")
    raw = b"".join(chunks)
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError) as exception:
        raise QualificationError("plan_not_canonical") from exception
    if raw != _canonical(value) or not isinstance(value, Mapping):
        raise QualificationError("plan_not_canonical")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    evidence = produce_evidence(_read_plan(arguments.plan))
    _write_new(arguments.output, evidence)
    print(f"{_digest(arguments.output)}  {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
