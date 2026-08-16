"""Validate and freeze an offline physical-rehearsal plan without executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

REQUEST_SCHEMA: Final = "dm.cluster.physical-rehearsal-plan/v1"
PREFLIGHT_SCHEMA: Final = "dm.cluster.physical-preflight/v1"
_DOMAIN: Final = b"daimon/physical-preflight/v1\x00"
_HEX: Final = re.compile(r"^[0-9a-f]{40}$")
_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
_HOST_REF: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMPONENTS: Final = frozenset({"daimon-matrix", "daimon-cluster", "tribe-bridge"})
_HOST_ROLES: Final = frozenset({"source", "target", "backup"})
_SHELLS: Final = frozenset(
    {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "zsh"}
)
_SHELL_DISPATCHERS: Final = _SHELLS | {"env"}
_STAGES: Final = (
    "preflight",
    "backup-export",
    "volume-transfer",
    "restore",
    "start-reboot",
    "loss-fence",
    "rollback",
)
_STAGE_ROLES: Final = (
    "source",
    "backup",
    "source",
    "target",
    "target",
    "target",
    "source",
)
_RC_SCHEMA: Final = "daimon-release-candidate/v1"
_MAX_DOCUMENT = 1024 * 1024


class PhysicalPreflightError(RuntimeError):
    """A proposed rehearsal is incomplete, mutable or unsafe to authorize."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exception:
        raise PhysicalPreflightError("preflight_document_not_canonical") from exception


def _closed(value: Any, fields: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PhysicalPreflightError(code)
    return value


def _strings(value: Any, code: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise PhysicalPreflightError(code)
    return list(value)


def _contains_shell_dispatcher(values: list[str]) -> bool:
    return any(
        Path(token).name in _SHELL_DISPATCHERS
        for value in values
        for token in value.split()
        if token
    )


def _release_manifest(value: Any) -> tuple[dict[str, dict[str, str]], list[dict[str, str]]]:
    manifest = _closed(
        value,
        {"baseline", "components", "cross_repository", "qualification", "schema"},
        "physical_rc_manifest_malformed",
    )
    if manifest["schema"] != _RC_SCHEMA:
        raise PhysicalPreflightError("physical_rc_manifest_malformed")
    components = _closed(
        manifest["components"], set(_COMPONENTS), "physical_rc_manifest_malformed"
    )
    component_refs: dict[str, dict[str, str]] = {}
    for name in _COMPONENTS:
        row = _closed(
            components[name],
            {"archive_bytes", "archive_sha256", "commit", "tree"},
            "physical_rc_manifest_malformed",
        )
        commit = row["commit"]
        tree = row["tree"]
        if (
            not isinstance(commit, str)
            or _HEX.fullmatch(commit) is None
            or not isinstance(tree, str)
            or _HEX.fullmatch(tree) is None
            or not isinstance(row["archive_bytes"], int)
            or isinstance(row["archive_bytes"], bool)
            or row["archive_bytes"] <= 0
            or not isinstance(row["archive_sha256"], str)
            or _SHA256.fullmatch(row["archive_sha256"]) is None
        ):
            raise PhysicalPreflightError("physical_rc_manifest_malformed")
        component_refs[name] = {"commit": commit, "tree": tree}
    qualification = manifest["qualification"]
    if not isinstance(qualification, Mapping):
        raise PhysicalPreflightError("physical_rc_manifest_malformed")
    artifact_map = _closed(
        qualification.get("artifacts"),
        set(_COMPONENTS),
        "physical_rc_manifest_malformed",
    )
    artifact_refs: list[dict[str, str]] = []
    for component in sorted(_COMPONENTS):
        rows = artifact_map[component]
        if not isinstance(rows, list) or not rows:
            raise PhysicalPreflightError("physical_rc_artifacts_incomplete")
        for value_row in rows:
            row = _closed(
                value_row,
                {"bytes", "name", "path", "sha256"},
                "physical_rc_manifest_malformed",
            )
            if (
                not isinstance(row["name"], str)
                or not row["name"]
                or not isinstance(row["path"], str)
                or not row["path"]
                or not isinstance(row["bytes"], int)
                or isinstance(row["bytes"], bool)
                or row["bytes"] <= 0
                or not isinstance(row["sha256"], str)
                or _SHA256.fullmatch(row["sha256"]) is None
            ):
                raise PhysicalPreflightError("physical_rc_manifest_malformed")
            artifact_refs.append(
                {"name": f"{component}:{row['name']}", "sha256": row["sha256"]}
            )
    if len({row["name"] for row in artifact_refs}) != len(artifact_refs):
        raise PhysicalPreflightError("physical_rc_manifest_malformed")
    return component_refs, artifact_refs


def validate_plan(value: Any, rc_manifest: Any) -> dict[str, Any]:
    manifest_components, manifest_artifacts = _release_manifest(rc_manifest)
    manifest_sha256 = hashlib.sha256(_canonical(rc_manifest) + b"\n").hexdigest()
    plan = _closed(
        value,
        {
            "artifacts",
            "components",
            "execution_authorized",
            "gates",
            "hosts",
            "limitations",
            "rc_manifest_sha256",
            "schema",
            "steps",
        },
        "physical_plan_malformed",
    )
    if plan["schema"] != REQUEST_SCHEMA or plan["execution_authorized"] is not False:
        raise PhysicalPreflightError("physical_execution_must_remain_unauthorized")
    if (
        not isinstance(plan["rc_manifest_sha256"], str)
        or _SHA256.fullmatch(plan["rc_manifest_sha256"]) is None
        or plan["rc_manifest_sha256"] != manifest_sha256
    ):
        raise PhysicalPreflightError("physical_rc_manifest_mismatch")

    components = _closed(
        plan["components"], set(_COMPONENTS), "physical_components_malformed"
    )
    for name in _COMPONENTS:
        row = _closed(
            components[name], {"commit", "tree"}, "physical_component_malformed"
        )
        if (
            not isinstance(row["commit"], str)
            or _HEX.fullmatch(row["commit"]) is None
            or not isinstance(row["tree"], str)
            or _HEX.fullmatch(row["tree"]) is None
        ):
            raise PhysicalPreflightError("physical_component_hash_invalid")
    if components != manifest_components:
        raise PhysicalPreflightError("physical_component_manifest_mismatch")

    artifacts = plan["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) < 3:
        raise PhysicalPreflightError("physical_artifacts_incomplete")
    artifact_names: set[str] = set()
    for value_row in artifacts:
        row = _closed(value_row, {"name", "sha256"}, "physical_artifact_malformed")
        name = row["name"]
        digest = row["sha256"]
        if (
            not isinstance(name, str)
            or not name
            or name in artifact_names
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise PhysicalPreflightError("physical_artifact_invalid")
        artifact_names.add(name)
    if artifacts != manifest_artifacts:
        raise PhysicalPreflightError("physical_artifact_manifest_mismatch")

    hosts = plan["hosts"]
    if not isinstance(hosts, list) or len(hosts) != len(_HOST_ROLES):
        raise PhysicalPreflightError("physical_hosts_incomplete")
    observed_roles: set[str] = set()
    observed_refs: set[str] = set()
    for value_row in hosts:
        row = _closed(
            value_row,
            {"host_ref", "production", "purpose_built", "role"},
            "physical_host_malformed",
        )
        role = row["role"]
        host_ref = row["host_ref"]
        if (
            not isinstance(role, str)
            or role not in _HOST_ROLES
            or role in observed_roles
            or not isinstance(host_ref, str)
            or _HOST_REF.fullmatch(host_ref) is None
            or host_ref in observed_refs
            or row["purpose_built"] is not True
            or row["production"] is not False
        ):
            raise PhysicalPreflightError("physical_host_not_purpose_built")
        observed_roles.add(str(role))
        observed_refs.add(host_ref)
    if observed_roles != _HOST_ROLES:
        raise PhysicalPreflightError("physical_hosts_incomplete")

    steps = plan["steps"]
    if not isinstance(steps, list) or len(steps) != len(_STAGES):
        raise PhysicalPreflightError("physical_steps_incomplete")
    for sequence, (value_row, stage, required_role) in enumerate(
        zip(steps, _STAGES, _STAGE_ROLES, strict=True), 1
    ):
        row = _closed(
            value_row,
            {
                "argv",
                "effects",
                "host_role",
                "rollback_argv",
                "sequence",
                "stage",
                "success",
            },
            "physical_step_malformed",
        )
        argv = _strings(row["argv"], "physical_step_argv_invalid")
        rollback = _strings(row["rollback_argv"], "physical_step_rollback_invalid")
        if (
            not isinstance(row["sequence"], int)
            or isinstance(row["sequence"], bool)
            or row["sequence"] != sequence
            or row["stage"] != stage
            or not isinstance(row["host_role"], str)
            or row["host_role"] != required_role
            or any("\x00" in item or "\n" in item for item in [*argv, *rollback])
            or _contains_shell_dispatcher(argv)
            or _contains_shell_dispatcher(rollback)
        ):
            raise PhysicalPreflightError("physical_step_invalid")
        _strings(row["effects"], "physical_step_effects_missing")
        _strings(row["success"], "physical_step_success_missing")

    gates = _closed(
        plan["gates"],
        {"exact_go_required", "external_contact_approved", "live_custody_approved"},
        "physical_gates_malformed",
    )
    if gates != {
        "exact_go_required": True,
        "external_contact_approved": False,
        "live_custody_approved": False,
    }:
        raise PhysicalPreflightError("physical_gate_widening_rejected")
    _strings(plan["limitations"], "physical_limitations_missing")
    return json.loads(_canonical(plan))


def build_preflight(value: Any, rc_manifest: Any) -> dict[str, Any]:
    plan = validate_plan(value, rc_manifest)
    digest = hashlib.sha256(_DOMAIN + _canonical(plan)).hexdigest()
    return {
        "schema": PREFLIGHT_SCHEMA,
        "execution_authorized": False,
        "plan": plan,
        "plan_sha256": digest,
        "rc_manifest_sha256": plan["rc_manifest_sha256"],
        "required_go": f"GO {digest}",
    }


def _read_document(path: Path) -> Any:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 1 <= info.st_size <= _MAX_DOCUMENT
        ):
            raise PhysicalPreflightError("physical_plan_file_rejected")
        chunks: list[bytes] = []
        remaining = _MAX_DOCUMENT + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_DOCUMENT:
            raise PhysicalPreflightError("physical_plan_file_rejected")
        value = json.loads(raw)
        if raw.rstrip(b"\n") != _canonical(value):
            raise PhysicalPreflightError("preflight_document_not_canonical")
        return value
    except PhysicalPreflightError:
        raise
    except (OSError, ValueError) as exception:
        raise PhysicalPreflightError("physical_plan_file_rejected") from exception
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    target = Path(os.path.abspath(path))
    requested_parent = target.parent
    parent = requested_parent.resolve(strict=True)
    info = parent.lstat()
    if (
        parent != requested_parent
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise PhysicalPreflightError("physical_preflight_output_rejected")
    raw = _canonical(value) + b"\n"
    parent_descriptor = -1
    descriptor = -1
    created = False
    completed = False
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        parent_info = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or stat.S_IMODE(parent_info.st_mode) & 0o022
            or (parent_info.st_dev, parent_info.st_ino) != (info.st_dev, info.st_ino)
        ):
            raise PhysicalPreflightError("physical_preflight_output_rejected")
        descriptor = os.open(
            target.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
        os.fsync(parent_descriptor)
        completed = True
    except PhysicalPreflightError:
        raise
    except OSError as exception:
        raise PhysicalPreflightError(
            "physical_preflight_output_rejected"
        ) from exception
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if created and not completed and parent_descriptor >= 0:
            # A failed write must never leave a partial document that resembles a receipt.
            try:
                os.unlink(target.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--rc-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    preflight = build_preflight(
        _read_document(arguments.plan), _read_document(arguments.rc_manifest)
    )
    _write_new(arguments.output, preflight)
    print(preflight["plan_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
