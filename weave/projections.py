"""Preview-first local projections for accepted Weave events."""

from __future__ import annotations

import hashlib
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .protocol import canonical_json


class ProjectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Preview:
    adapter: str
    event_id: str
    target: str
    changes: dict[str, dict[str, Any]]
    impact: str
    authority: str
    reversible: bool
    preview_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter, "event_id": self.event_id,
            "target": self.target, "changes": self.changes,
            "impact": self.impact, "authority": self.authority,
            "reversible": self.reversible, "preview_hash": self.preview_hash,
        }


def _preview(**values: Any) -> Preview:
    body = dict(values)
    digest = hashlib.sha256(canonical_json(body)).hexdigest()
    return Preview(**body, preview_hash=digest)


class GitIdentityAdapter:
    """Select a Git identity per embodiment/repository without copying secrets."""

    name = "git-identity/v1"

    def __init__(self, config_file: str | Path):
        self.path = Path(config_file)

    def _get(self, key: str) -> str | None:
        result = subprocess.run(
            ["git", "config", "--file", str(self.path), "--get", key],
            text=True, capture_output=True, check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else None

    def preview(self, event: dict[str, Any]) -> Preview:
        if event.get("kind") != "configuration.proposed" or event.get("subject") != "github.identity":
            raise ProjectionError("unsupported event for git identity adapter")
        payload = event.get("payload") or {}
        allowed = {"name", "email", "signing_key_ref", "secret_slot_ref"}
        if not set(payload) <= allowed or not ({"name", "email"} & set(payload)):
            raise ProjectionError("invalid git identity proposal")
        changes = {}
        for field, git_key in (("name", "user.name"), ("email", "user.email"), ("signing_key_ref", "user.signingkey")):
            if field in payload:
                changes[git_key] = {"before": self._get(git_key), "after": payload[field]}
        return _preview(
            adapter=self.name, event_id=event["event_id"], target=str(self.path),
            changes=changes, impact="external-identity", authority="human",
            reversible=True,
        )

    def apply(self, preview: Preview, *, confirm: bool, actor: str) -> dict[str, Any]:
        if not confirm:
            raise ProjectionError("human confirmation required")
        if preview.adapter != self.name:
            raise ProjectionError("preview belongs to another adapter")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for key, change in preview.changes.items():
            subprocess.run(
                ["git", "config", "--file", str(self.path), key, str(change["after"])],
                check=True, capture_output=True, text=True,
            )
        observed = {key: self._get(key) for key in preview.changes}
        expected = {key: value["after"] for key, value in preview.changes.items()}
        if observed != expected:
            raise ProjectionError("git identity postcondition mismatch")
        return {
            "schema": "projection-receipt/v1", "adapter": self.name,
            "event_id": preview.event_id, "preview_hash": preview.preview_hash,
            "actor": actor, "authority": "human", "result": "applied",
            "observed_postcondition": observed, "completed_at_ms": int(time.time() * 1000),
            "resource_fence": None,
        }


class HMKAdapter:
    """Project an accepted experience using HMK's public command surface."""

    name = "hmk-memory/v1"

    def __init__(self, memoryctl: str | Path, *, runner: Callable[..., Any] = subprocess.run):
        self.memoryctl = str(memoryctl)
        self.runner = runner

    def preview(self, event: dict[str, Any]) -> Preview:
        if event.get("kind") not in {"experience.observed", "skill.proposed"}:
            raise ProjectionError("unsupported event for HMK adapter")
        payload = event.get("payload") or {}
        summary = payload.get("summary") or payload.get("content")
        if not isinstance(summary, str) or not summary:
            raise ProjectionError("HMK projection needs text content")
        title = f"[weave:{event['event_id']}] {event['subject']}"
        return _preview(
            adapter=self.name, event_id=event["event_id"], target="hmk:episodes",
            changes={"chapter": {"before": None, "after": {"title": title, "text": summary}}},
            impact="personal-memory", authority="daimon", reversible=True,
        )

    def apply(self, preview: Preview, *, actor: str) -> dict[str, Any]:
        chapter = preview.changes["chapter"]["after"]
        result = self.runner(
            [self.memoryctl, "add-text", "--shelf", "episodes", "--title", chapter["title"], "--text", chapter["text"]],
            check=False, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise ProjectionError("HMK public projection command failed")
        return {
            "schema": "projection-receipt/v1", "adapter": self.name,
            "event_id": preview.event_id, "preview_hash": preview.preview_hash,
            "actor": actor, "authority": "daimon", "result": "applied",
            "observed_postcondition": {"event_marker": f"[weave:{preview.event_id}]"},
            "completed_at_ms": int(time.time() * 1000), "resource_fence": None,
        }
