"""Declared-state inventory and reconciliation.

Declared state lives in ``<state_dir>/instances/<name>.yaml`` files
(schema ``instance-spec/v1``). Actual state comes from an ``Adapter``.
Reconciliation classifies every instance as one of:

- ``running``    — declared, present, state running, no drift
- ``stopped``    — declared, present, state stopped, no drift
- ``missing``    — declared, absent from incus
- ``undeclared`` — present in incus, not declared
- ``drifted``    — declared budgets or image differ from actual config

All functions here are strictly side-effect free.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import yaml

from .adapters import Adapter

SPEC_SCHEMA = "instance-spec/v1"
STATUS_SCHEMA = "instance-status/v1"

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
            body_ref=raw.get("body_ref"),
            embodiment_id=raw.get("embodiment_id"),
            current_incarnation_id=raw.get("current_incarnation_id"),
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
    }


def reconcile(specs: dict[str, InstanceSpec], adapter: Adapter, host_id: str) -> list[dict]:
    """Reconcile declared specs with actual state into status records.

    Pure read: queries the adapter once, writes nothing. Each returned
    record conforms to ``instance-status/v1``; drifted records carry a
    ``drift`` array of ``{field, declared, actual}`` entries.
    """
    actual_by_name = {inst["name"]: inst for inst in adapter.list_instances()}
    records: list[dict] = []

    for name, spec in sorted(specs.items()):
        actual = actual_by_name.get(name)
        if actual is None:
            records.append(
                _status_record(name, host_id, "missing", spec.species,
                               spec.image_version, spec.budgets, None,
                               spec.body_ref, spec.embodiment_id,
                               spec.current_incarnation_id)
            )
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
                             spec.current_incarnation_id)
        if drift:
            rec["drift"] = drift
        records.append(rec)

    for name, actual in sorted(actual_by_name.items()):
        if name in specs:
            continue
        records.append(
            _status_record(name, host_id, "undeclared", "unknown",
                           actual.get("image_version"), actual.get("budgets") or {},
                           actual.get("uptime_s"))
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


def update_spec(instances_dir: str | Path, name: str, updates: dict) -> dict:
    """The spec-store write API: merge ``updates`` into the declared spec
    and persist. Callers (park, lifecycle) MUST go through here instead of
    writing YAML directly so spec writes stay schema-checked and in one
    place. Returns the updated raw mapping."""
    raw = load_spec_raw(instances_dir, name)
    if raw is None:
        raise SpecError(f"instance {name!r} is not declared")
    raw.update(updates)
    path = Path(instances_dir) / f"{name}.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return raw


def find_record(records: list[dict], name: str) -> dict | None:
    for rec in records:
        if rec["name"] == name:
            return rec
    return None
