"""Cluster-owned body, embodiment, and incarnation registry."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

REGISTRY_SCHEMA = "embodiment-registry/v1"


class RegistryError(RuntimeError):
    pass


def new_id(kind: str) -> str:
    return f"{kind}:{uuid.uuid4()}"


class Registry:
    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "embodiments.json"

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"schema": REGISTRY_SCHEMA, "embodiments": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError("cannot read embodiment registry") from exc
        if not isinstance(value, dict) or value.get("schema") != REGISTRY_SCHEMA or not isinstance(value.get("embodiments"), dict):
            raise RegistryError("invalid embodiment registry")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)

    def register(self, *, body_ref: str, embodiment_id: str | None = None) -> dict[str, Any]:
        state = self.load()
        for record in state["embodiments"].values():
            if record["body_ref"] == body_ref and record["status"] != "retired":
                raise RegistryError(f"body already registered: {body_ref}")
        now = int(time.time() * 1000)
        identifier = embodiment_id or new_id("embodiment")
        record = {
            "embodiment_id": identifier, "body_ref": body_ref,
            "status": "stopped", "created_at_ms": now,
            "current_incarnation_id": None, "incarnations": [],
        }
        state["embodiments"][identifier] = record
        self._save(state)
        return dict(record)

    def start(self, embodiment_id: str) -> dict[str, Any]:
        state = self.load()
        try:
            record = state["embodiments"][embodiment_id]
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc
        if record["status"] == "retired":
            raise RegistryError("cannot start retired embodiment")
        if record["status"] == "running":
            raise RegistryError("embodiment already running")
        identifier = new_id("incarnation")
        started = int(time.time() * 1000)
        incarnation = {"incarnation_id": identifier, "started_at_ms": started, "stopped_at_ms": None}
        record["incarnations"].append(incarnation)
        record["current_incarnation_id"] = identifier
        record["status"] = "running"
        self._save(state)
        return dict(incarnation)

    def stop(self, embodiment_id: str) -> dict[str, Any]:
        state = self.load()
        try:
            record = state["embodiments"][embodiment_id]
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc
        if record["status"] == "retired":
            raise RegistryError("cannot stop retired embodiment")
        current = record.get("current_incarnation_id")
        if current is not None:
            for incarnation in record["incarnations"]:
                if incarnation["incarnation_id"] == current and incarnation["stopped_at_ms"] is None:
                    incarnation["stopped_at_ms"] = int(time.time() * 1000)
                    break
        record["current_incarnation_id"] = None
        record["status"] = "stopped"
        self._save(state)
        return dict(record)

    def status(self, embodiment_id: str) -> dict[str, Any]:
        state = self.load()
        try:
            return dict(state["embodiments"][embodiment_id])
        except KeyError as exc:
            raise RegistryError(f"unknown embodiment: {embodiment_id}") from exc

    def list_all(self) -> list[dict[str, Any]]:
        """Return the registry in stable embodiment-id order."""
        state = self.load()
        return [dict(state["embodiments"][key]) for key in sorted(state["embodiments"])]
