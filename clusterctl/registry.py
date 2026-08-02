"""Embodiment registry — where a being is embodied (M10-R2, ontology.md).

Replaces the deleted LeaseStore. The registry is a CENSUS and a sync
directory: it records which embodiments of a being exist, on which
bodies, in which lifecycle state, at which chain cursor. It is NOT a
lock and NEVER an exclusion mechanism — multiple awake embodiments of
one being root are normal plurality (docs/design/ontology.md).

Layout under ``<state_dir>/registry/``:

- ``<being_root>.json`` — signed snapshot: ``embodiment-registry/v1``
  with ``cursor`` (monotonic per being) and one row per embodiment.
- ``<being_root>.history.jsonl`` — append-only, one signed record per
  transition; the seed of the chain of existence (R3 anchors and
  verifies these as chain segments).

CAS discipline (ordering, never exclusion): every mutation reads the
snapshot, computes ``cursor + 1``, and atomically replaces the snapshot
(tmp + rename). Concurrent writers serialize on the filesystem rename;
the loser of a genuinely concurrent pair is whichever reads first —
both records land in history, order is decided by cursor, nobody is
refused for existing.

No TTL/expiry: liveness is observed from the fleet (incus state); the
registry records intent and history, not heartbeats.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from .signing import FakeSigner, Signer, _canonical, InvalidSignature, now_ms

REGISTRY_SCHEMA = "embodiment-registry/v1"
VALID_STATES = ("awake", "parked", "rolled-back")

logger = logging.getLogger("clusterctl.registry")


class RegistryError(Exception):
    pass


class RegistryNotFound(RegistryError):
    pass


class EmbodimentRegistry:
    """Signed per-being embodiment census with monotonic cursors."""

    def __init__(self, state_dir: str | Path, signer: Signer | None = None):
        self.state_dir = Path(state_dir)
        self.signer = signer or FakeSigner()
        (self.state_dir / "registry").mkdir(parents=True, exist_ok=True)

    # ---------- storage ----------

    def _snap_path(self, being_root: str) -> Path:
        return self.state_dir / "registry" / f"{being_root}.json"

    def _hist_path(self, being_root: str) -> Path:
        return self.state_dir / "registry" / f"{being_root}.history.jsonl"

    def _read_snap(self, being_root: str) -> dict:
        path = self._snap_path(being_root)
        if not path.exists():
            return {"schema": REGISTRY_SCHEMA, "being_root": being_root,
                    "cursor": 0, "embodiments": {}}
        snap = json.loads(path.read_text())
        sig = snap.get("signature")
        if not sig or not self.signer.verify(_canonical(snap), sig, ""):
            raise InvalidSignature(f"registry snapshot for {being_root} is unsigned or tampered")
        return snap

    def _write_snap(self, being_root: str, snap: dict) -> None:
        snap = dict(snap)
        snap["signature"] = self.signer.sign(_canonical(snap))
        path = self._snap_path(being_root)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(snap, indent=2) + "\n")
        os.replace(tmp, path)

    def _append_history(self, being_root: str, entry: dict) -> None:
        entry = dict(entry)
        entry["signature"] = self.signer.sign(_canonical(entry))
        with self._hist_path(being_root).open("a") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    # ---------- mutations (CAS ordering, never exclusion) ----------

    def register(self, being_root: str, embodiment: str, body: str,
                 state: str = "awake", manifest: str | None = None,
                 actor: str = "system") -> dict:
        """Record an embodiment transition at cursor+1. Multiple awake
        embodiments of one being are normal and never refused."""
        if state not in VALID_STATES:
            raise RegistryError(f"invalid state {state!r} (one of {VALID_STATES})")
        snap = self._read_snap(being_root)
        cursor = snap["cursor"] + 1
        row = {"state": state, "body": body, "manifest": manifest,
               "cursor": cursor, "updated_ms": now_ms(), "actor": actor}
        snap["embodiments"][embodiment] = row
        snap["cursor"] = cursor
        self._write_snap(being_root, snap)
        entry = {"being_root": being_root, "embodiment": embodiment, "cursor": cursor,
                 "state": state, "body": body, "manifest": manifest,
                 "actor": actor, "ms": row["updated_ms"]}
        self._append_history(being_root, entry)
        logger.info("registry: %s %s -> %s on %s (cursor %d, actor %s)",
                    being_root, embodiment, state, body, cursor, actor)
        return entry

    def set_state(self, being_root: str, embodiment: str, state: str,
                  manifest: str | None = None, actor: str = "system") -> dict:
        """Transition an existing embodiment (body preserved)."""
        snap = self._read_snap(being_root)
        row = snap["embodiments"].get(embodiment)
        if row is None:
            raise RegistryNotFound(f"{embodiment} not in registry of {being_root}")
        return self.register(being_root, embodiment, row["body"], state,
                             manifest=manifest, actor=actor)

    def rollback(self, being_root: str, embodiment: str, note: str,
                 actor: str = "system") -> dict:
        """Append a rolled-back record at cursor+1. The cursor never goes
        down; history keeps both the failed transition and its rollback."""
        snap = self._read_snap(being_root)
        row = snap["embodiments"].get(embodiment)
        if row is None:
            raise RegistryNotFound(f"{embodiment} not in registry of {being_root}")
        entry = self.register(being_root, embodiment, row["body"], "rolled-back",
                              manifest=row.get("manifest"), actor=actor)
        self._append_history(being_root, {"being_root": being_root, "embodiment": embodiment,
                                          "cursor": entry["cursor"], "state": "rollback-note",
                                          "note": note, "actor": actor, "ms": now_ms()})
        return entry

    # ---------- queries ----------

    def get(self, being_root: str, embodiment: str) -> dict | None:
        snap = self._read_snap(being_root)
        row = snap["embodiments"].get(embodiment)
        return dict(row, being_root=being_root, embodiment=embodiment) if row else None

    def find(self, embodiment: str) -> dict | None:
        """Find an embodiment across all known beings."""
        for root in self.beings():
            row = self.get(root, embodiment)
            if row:
                return row
        return None

    def beings(self) -> list[str]:
        reg = self.state_dir / "registry"
        return sorted(p.name[:-5] for p in reg.glob("*.json") if not p.name.endswith(".tmp"))

    def list_all(self, being_root: str | None = None) -> list[dict]:
        roots = [being_root] if being_root else self.beings()
        rows: list[dict] = []
        for root in roots:
            snap = self._read_snap(root)
            for name, row in snap["embodiments"].items():
                rows.append(dict(row, being_root=root, embodiment=name))
        return rows

    def current_cursor(self, being_root: str) -> int:
        return self._read_snap(being_root)["cursor"]

    def history(self, being_root: str) -> list[dict]:
        path = self._hist_path(being_root)
        if not path.exists():
            return []
        entries = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            sig = entry.get("signature")
            if not sig or not self.signer.verify(_canonical(entry), sig, ""):
                raise InvalidSignature(f"tampered history entry in {path.name}")
            entries.append(entry)
        return entries
