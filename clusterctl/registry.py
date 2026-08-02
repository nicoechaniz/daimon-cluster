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

from .signing import (FakeSigner, Signer, _canonical, _sha256_hex,
                      InvalidSignature, now_ms)

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
            # The chain is authoritative; the snapshot is a derived view.
            # A host that received a chain segment (R4 /we.sync import)
            # rebuilds its snapshot from the chain before mutating.
            if self._hist_path(being_root).exists():
                return self._rebuild_snap(being_root)
            return {"schema": REGISTRY_SCHEMA, "being_root": being_root,
                    "cursor": 0, "embodiments": {}}
        snap = json.loads(path.read_text())
        sig = snap.get("signature")
        if not sig or not self.signer.verify(_canonical(snap), sig, ""):
            raise InvalidSignature(f"registry snapshot for {being_root} is unsigned or tampered")
        return snap

    def _rebuild_snap(self, being_root: str) -> dict:
        """Derive the snapshot from the chain (last write wins per
        embodiment; cursor = chain tip). Writes the derived snapshot so
        subsequent reads are cheap."""
        snap = {"schema": REGISTRY_SCHEMA, "being_root": being_root,
                "cursor": 0, "embodiments": {}}
        for entry in self.history(being_root):
            if entry.get("state") == "rollback-note":
                continue
            snap["embodiments"][entry["embodiment"]] = {
                "state": entry["state"], "body": entry["body"],
                "manifest": entry.get("manifest"),
                "cursor": entry["cursor"], "updated_ms": entry["ms"],
                "actor": entry.get("actor", "system")}
            snap["cursor"] = max(snap["cursor"], entry["cursor"])
        self._write_snap(being_root, snap)
        return snap

    def _write_snap(self, being_root: str, snap: dict) -> None:
        snap = dict(snap)
        snap["signature"] = self.signer.sign(_canonical(snap))
        path = self._snap_path(being_root)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(snap, indent=2) + "\n")
        os.replace(tmp, path)

    def _append_history(self, being_root: str, entry: dict) -> None:
        """Append a chained, signed entry (M10-R3 chain of existence).

        Each entry carries ``prev_sha256`` (sha of the canonical previous
        entry, signature included) and ``genesis_sha`` (sha of entry 1 —
        the being's root anchor). Two chains belong to the same being iff
        their genesis_sha matches and each is internally unbroken.
        """
        entry = dict(entry)
        last = self._last_history_line(being_root)
        if last is not None:
            prev = json.loads(last)
            entry["prev_sha256"] = _sha256_hex(_canonical(prev))
            entry["genesis_sha"] = prev.get("genesis_sha") or _sha256_hex(
                _canonical({k: v for k, v in prev.items()
                            if k not in ("signature", "genesis_sha")}))
        else:
            # Genesis: reproducible self-anchor — sha of the canonical
            # entry minus signature/genesis_sha, prev=None.
            entry["prev_sha256"] = None
            entry["genesis_sha"] = _sha256_hex(_canonical(entry))
        entry["signature"] = self.signer.sign(_canonical(entry))
        with self._hist_path(being_root).open("a") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    def _last_history_line(self, being_root: str) -> str | None:
        path = self._hist_path(being_root)
        if not path.exists():
            return None
        lines = path.read_text().splitlines()
        return lines[-1] if lines else None

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

    # ---------- chain of existence (M10-R3) ----------

    def verify_chain(self, being_root: str) -> dict:
        """Verify the being's chain of existence: common root + unbroken
        path (ontology.md invariant, made checkable).

        Checks: every entry signature (via history()), cursors strictly
        increasing from 1, prev_sha256 links intact, one genesis_sha
        throughout, the genesis entry declares this being_root.
        Returns {"ok", "length", "genesis_sha", "cursor", "error"}.
        """
        result = {"ok": False, "length": 0, "genesis_sha": None,
                  "cursor": 0, "error": None}
        try:
            entries = self.history(being_root)
        except InvalidSignature as exc:
            result["error"] = str(exc)
            return result
        if not entries:
            result["error"] = "empty chain"
            return result

        genesis = entries[0]
        genesis_sha = genesis.get("genesis_sha")
        recomputed = _sha256_hex(_canonical(
            {k: v for k, v in genesis.items()
             if k not in ("signature", "genesis_sha")}))
        if genesis.get("prev_sha256") is not None:
            result["error"] = "genesis entry has a prev link"
            return result
        if genesis_sha != recomputed:
            result["error"] = "genesis self-anchor mismatch"
            return result
        if genesis.get("being_root") != being_root:
            result["error"] = "genesis declares a different being_root"
            return result

        prev_entry = genesis
        prev_cursor = genesis["cursor"]
        for entry in entries[1:]:
            if entry.get("genesis_sha") != genesis_sha:
                result["error"] = f"genesis_sha changed at cursor {entry.get('cursor')}"
                return result
            if entry.get("prev_sha256") != _sha256_hex(_canonical(prev_entry)):
                result["error"] = f"broken prev link at cursor {entry.get('cursor')}"
                return result
            if entry["cursor"] <= prev_cursor:
                result["error"] = f"cursor not increasing at {entry.get('cursor')}"
                return result
            prev_entry, prev_cursor = entry, entry["cursor"]

        result.update(ok=True, length=len(entries),
                      genesis_sha=genesis_sha,
                      cursor=entries[-1]["cursor"])
        return result

    def segment(self, being_root: str, after_cursor: int = 0) -> list[dict]:
        """Chain entries with cursor > after_cursor, in order — the
        /we.sync (R4) export primitive. ``after_cursor`` is the peer's
        high-water mark; the returned segment is what they have not
        seen."""
        return [e for e in self.history(being_root)
                if e["cursor"] > after_cursor]


def verify_common_root(entries_a: list[dict], entries_b: list[dict]) -> bool:
    """Two chains belong to the SAME being iff both are non-empty and
    share a genesis_sha (common root). Internal unbrokenness is each
    side's own verify_chain job — this is the cross-chain comparison
    /we.sync (R4) runs before merging segments."""
    if not entries_a or not entries_b:
        return False
    ga, gb = entries_a[0].get("genesis_sha"), entries_b[0].get("genesis_sha")
    return bool(ga) and ga == gb
