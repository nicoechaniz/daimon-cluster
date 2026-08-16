"""Declared-state inventory and reconciliation.

Declared state lives in ``<state_dir>/instances/<name>.yaml`` files
(schema ``instance-spec/v1``). Actual state comes from an ``Adapter``.
Reconciliation classifies every instance as one of:

- ``running``    — declared, present, state running, no drift
- ``stopped``    — declared, present, state stopped, no drift
- ``missing``    — declared, absent from incus
- ``undeclared`` — present in incus, not declared
- ``drifted``    — declared budgets or image differ from actual config

Read and reconciliation functions are side-effect free. Spec mutations use
the durable `write_spec`/`update_spec` boundary.
"""

from __future__ import annotations

import dataclasses
import os
import stat
import time
from pathlib import Path

import yaml

from .adapters import Adapter

SPEC_SCHEMA = "instance-spec/v1"
STATUS_SCHEMA = "instance-status/v2"

DRIFT_FIELDS = ("cpu", "memory_mib", "disk_gib")


class SpecError(Exception):
    """Raised when an instance spec file is invalid."""


@dataclasses.dataclass(frozen=True)
class InstanceSpec:
    name: str
    species: str
    image_version: str | None
    budgets: dict
    created_ms: int | None
    created_by: str | None
    body_ref: str | None = None
    embodiment_id: str | None = None
    current_incarnation_id: str | None = None


def load_specs(instances_dir: str | Path) -> dict[str, InstanceSpec]:
    """Load all declared instance specs. Missing directory = empty inventory."""
    d = Path(instances_dir)
    specs: dict[str, InstanceSpec] = {}
    if not d.is_dir():
        return specs
    for path in sorted(d.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise SpecError(f"invalid YAML in spec {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise SpecError(f"spec {path} must be a YAML mapping")
        schema = raw.get("schema")
        if schema != SPEC_SCHEMA:
            raise SpecError(f"spec {path}: schema must be {SPEC_SCHEMA!r}, got {schema!r}")
        name = raw.get("name")
        if not name:
            raise SpecError(f"spec {path}: missing 'name'")
        budgets = raw.get("budgets") or {}
        matrix_managed = raw.get("instance_kind") == "matrix-embodiment"
        specs[str(name)] = InstanceSpec(
            name=str(name),
            species=str(raw.get("species") or "unknown"),
            image_version=raw.get("image_version"),
            budgets={
                "cpu": budgets.get("cpu"),
                "memory_mib": budgets.get("memory_mib"),
                "disk_gib": budgets.get("disk_gib"),
            },
            created_ms=raw.get("created_ms"),
            created_by=raw.get("created_by"),
            body_ref=raw.get("body_ref") if matrix_managed else None,
            embodiment_id=raw.get("embodiment_id") if matrix_managed else None,
            current_incarnation_id=(
                raw.get("current_incarnation_id") if matrix_managed else None
            ),
        )
    return specs


def compute_drift(spec: InstanceSpec, actual: dict) -> list[dict]:
    """Return drift entries ``{field, declared, actual}`` (empty = no drift).

    Fields whose actual value is unknown (None) are not treated as drifted.
    """
    drift = []
    actual_budgets = actual.get("budgets") or {}
    for field in DRIFT_FIELDS:
        declared = (spec.budgets or {}).get(field)
        actual_val = actual_budgets.get(field)
        if declared is not None and actual_val is not None and declared != actual_val:
            drift.append({"field": field, "declared": declared, "actual": actual_val})
    if (
        spec.image_version is not None
        and actual.get("image_version") is not None
        and spec.image_version != actual["image_version"]
    ):
        drift.append(
            {
                "field": "image_version",
                "declared": spec.image_version,
                "actual": actual["image_version"],
            }
        )
    return drift


def _status_record(
    name: str,
    host_id: str,
    state: str,
    species: str,
    image_version,
    budgets: dict,
    uptime_s,
    body_ref=None,
    embodiment_id=None,
    incarnation_id=None,
    *,
    observed_at_ms: int,
    declared: bool,
    runtime_present: bool,
    runtime_state: str | None,
) -> dict:
    return {
        "schema": STATUS_SCHEMA,
        "name": name,
        "species": species,
        "host": host_id,
        "state": state,
        "resource_fence_state": "unknown",
        "image_version": image_version,
        "budgets": {
            "cpu": budgets.get("cpu"),
            "memory_mib": budgets.get("memory_mib"),
            "disk_gib": budgets.get("disk_gib"),
        },
        "durable_bytes": None,
        "hmk_integrity": "unknown",
        "uptime_s": uptime_s,
        "last_audit_event": None,
        "body_ref": body_ref,
        "embodiment_id": embodiment_id,
        "incarnation_id": incarnation_id,
        "observed_at_ms": observed_at_ms,
        # These observations deliberately remain separate.  The legacy
        # aggregate ``state`` above is useful for CLI reconciliation, but it
        # is never evidence for identity, embodiment, incarnation, or Matrix
        # process health.
        "observations": {
            "declared": {
                "state": "declared" if declared else "absent",
                "observed_at_ms": observed_at_ms,
                "created_by": None,
            },
            "runtime": {
                "state": runtime_state if runtime_present else "missing",
                "present": runtime_present,
                "observed_at_ms": observed_at_ms,
            },
            "embodiment": {
                "state": "unavailable",
                "observed_at_ms": observed_at_ms,
                "reason": "registry-not-observed-by-inventory",
            },
            "incarnation": {
                "state": "unavailable",
                "observed_at_ms": observed_at_ms,
                "reason": "registry-not-observed-by-inventory",
            },
            "matrix_process": {
                "state": "unavailable",
                "observed_at_ms": observed_at_ms,
                "reason": "matrix-process-not-observed-by-inventory",
            },
        },
    }


def reconcile(specs: dict[str, InstanceSpec], adapter: Adapter, host_id: str) -> list[dict]:
    """Reconcile declared specs with actual state into status records.

    Pure read: queries the adapter once, writes nothing. Each returned
    record conforms to ``instance-status/v2``; drifted records carry a
    ``drift`` array of ``{field, declared, actual}`` entries.
    """
    observed_at_ms = int(time.time() * 1000)
    actual_by_name = {inst["name"]: inst for inst in adapter.list_instances()}
    records: list[dict] = []

    for name, spec in sorted(specs.items()):
        actual = actual_by_name.get(name)
        if actual is None:
            records.append(
                _status_record(name, host_id, "missing", spec.species,
                               spec.image_version, spec.budgets, None,
                               spec.body_ref, spec.embodiment_id,
                               spec.current_incarnation_id,
                               observed_at_ms=observed_at_ms,
                               declared=True,
                               runtime_present=False,
                               runtime_state=None)
            )
            records[-1]["observations"]["declared"]["created_by"] = spec.created_by
            continue
        drift = compute_drift(spec, actual)
        if drift:
            state = "drifted"
        else:
            actual_state = actual.get("state")
            state = actual_state if actual_state in ("running", "stopped") else (actual_state or "unknown")
        rec = _status_record(name, host_id, state, spec.species,
                             spec.image_version, spec.budgets, actual.get("uptime_s"),
                             spec.body_ref, spec.embodiment_id,
                             spec.current_incarnation_id,
                             observed_at_ms=observed_at_ms,
                             declared=True,
                             runtime_present=True,
                             runtime_state=actual.get("state") or "unknown")
        rec["observations"]["declared"]["created_by"] = spec.created_by
        if drift:
            rec["drift"] = drift
        records.append(rec)

    for name, actual in sorted(actual_by_name.items()):
        if name in specs:
            continue
        records.append(
            _status_record(name, host_id, "undeclared", "unknown",
                           actual.get("image_version"), actual.get("budgets") or {},
                           actual.get("uptime_s"),
                           observed_at_ms=observed_at_ms,
                           declared=False,
                           runtime_present=True,
                           runtime_state=actual.get("state") or "unknown")
        )

    return records


def load_spec_raw(instances_dir: str | Path, name: str) -> dict | None:
    """Load one spec as the raw YAML mapping (all fields, not just the
    dataclass subset). Returns None when the instance is not declared."""
    path = Path(instances_dir) / f"{name}.yaml"
    if not path.is_file():
        return None
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SpecError(f"invalid YAML in spec {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SpecError(f"spec {path} must be a YAML mapping")
    if raw.get("schema") != SPEC_SCHEMA:
        raise SpecError(f"spec {path}: schema must be {SPEC_SCHEMA!r}")
    return raw


def write_spec(instances_dir: str | Path, spec: dict) -> Path:
    """Durably replace one schema-checked instance spec."""
    if spec.get("schema") != SPEC_SCHEMA:
        raise SpecError(f"spec schema must be {SPEC_SCHEMA!r}")
    name = spec.get("name")
    if not isinstance(name, str) or not name:
        raise SpecError("spec name is required")
    parent = Path(instances_dir)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = parent.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise SpecError("instance spec directory is not owner-controlled")
    parent.chmod(0o700)
    path = parent / f"{name}.yaml"
    if path.is_symlink():
        raise SpecError("instance spec symlink is forbidden")
    temporary = path.with_suffix(".yaml.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        raw = yaml.safe_dump(spec, sort_keys=False).encode()
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def update_spec(instances_dir: str | Path, name: str, updates: dict) -> dict:
    """The spec-store write API: merge ``updates`` into the declared spec
    and persist. Callers (park, lifecycle) MUST go through here instead of
    writing YAML directly so spec writes stay schema-checked and in one
    place. Returns the updated raw mapping."""
    raw = load_spec_raw(instances_dir, name)
    if raw is None:
        raise SpecError(f"instance {name!r} is not declared")
    raw.update(updates)
    write_spec(instances_dir, raw)
    return raw


def find_record(records: list[dict], name: str) -> dict | None:
    for rec in records:
        if rec["name"] == name:
            return rec
    return None
