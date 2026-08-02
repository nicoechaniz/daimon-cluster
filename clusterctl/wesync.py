"""/we.sync v1 — weaving between embodiments of one being (M10-R4).

Ontology (docs/design/ontology.md): /we is all embodiments of the SAME
being that can answer; /we.sync is the protocol that weaves them —
experiences marked by origin, chain segments, skills. Coherence comes
from sync, never from exclusion.

What v1 syncs, per being:

- **Experiences** — append-only records in
  ``state_dir/wesync/<being_root>.experiences.jsonl``, schema
  ``we-experience/v1``: ``{being_root, origin, origin_seq, kind,
  payload, ms, signature}``. ``origin`` is the embodiment that lived
  the experience; ``origin_seq`` is monotonic PER ORIGIN. Origin
  attribution is preserved forever — a synced experience still says
  who lived it (DM-070 mirror).
- **Chain segments** — the R3 primitives (``registry.segment`` /
  ``verify_common_root``) carried in the same bundle.

**Sync cursors per peer** live in
``state_dir/wesync/<being_root>.peers/<peer>.json``:
``{"chain_cursor": n, "experiences": {origin: seq}}`` — the high-water
marks of what THIS host has imported from that peer. Export computes
the delta against a peer cursor set; import advances them.

Merge semantics:

- Experiences converge by UNION keyed on ``(origin, origin_seq)`` —
  no conflict is possible between origins, and re-import is idempotent
  (no duplicates).
- Chain entries append only if they link onto the local tip. Same
  cursor with different content = a BRANCH (partitioned embodiments
  appended independently): v1 does not pick a winner — it flags
  ``state_dir/wesync/<being_root>.merge.json`` (the "mergeando" state
  of the R7 dashboard) and still imports experiences. Branch merge is
  R6.

Bundles are plain JSON (``we-sync-bundle/v1``) — transportable over
tribe-bridge v1 as message payloads for the cross-host path.

Signatures: experience records are signed by the origin host; chain
entries keep their original signatures through sync (never re-signed —
attribution). Verification delegates to the configured Signer; with
SSHSigner, cross-host key trust is the cross-host milestone's concern
(documented, not silent).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from .registry import EmbodimentRegistry, verify_common_root
from .signing import FakeSigner, Signer, _canonical, _sha256_hex, now_ms

WE_EXPERIENCE_SCHEMA = "we-experience/v1"
WE_BUNDLE_SCHEMA = "we-sync-bundle/v1"
MERGE_SCHEMA = "we-merge-state/v1"

logger = logging.getLogger(__name__)


class WeSyncError(Exception):
    """Bundle validation / import failure."""


class WeSync:
    """The /we.sync v1 engine for one host's state_dir."""

    def __init__(self, state_dir: str | Path, signer: Signer | None = None):
        self.state_dir = Path(state_dir)
        self.signer = signer or FakeSigner()
        self.registry = EmbodimentRegistry(state_dir, self.signer)

    # ---------- paths ----------

    def _dir(self, being_root: str) -> Path:
        return self.state_dir / "wesync" / being_root

    def _log_path(self, being_root: str) -> Path:
        return self._dir(being_root) / "experiences.jsonl"

    def _peers_dir(self, being_root: str) -> Path:
        return self._dir(being_root) / "peers"

    def _merge_path(self, being_root: str) -> Path:
        return self._dir(being_root) / "merge.json"

    # ---------- experiences ----------

    def record_experience(self, being_root: str, origin: str, kind: str,
                          payload: dict, actor: str = "system") -> dict:
        """Append an experience lived by ``origin`` (an embodiment of the
        being). origin_seq is monotonic per origin."""
        seq = self._next_origin_seq(being_root, origin)
        entry = {"schema": WE_EXPERIENCE_SCHEMA, "being_root": being_root,
                 "origin": origin, "origin_seq": seq, "kind": kind,
                 "payload": payload, "actor": actor, "ms": now_ms()}
        entry["signature"] = self.signer.sign(_canonical(entry))
        path = self._log_path(being_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        return entry

    def _next_origin_seq(self, being_root: str, origin: str) -> int:
        seqs = self._origin_high_water(being_root)
        return seqs.get(origin, 0) + 1

    def _origin_high_water(self, being_root: str) -> dict:
        hw: dict[str, int] = {}
        for e in self.experiences(being_root):
            hw[e["origin"]] = max(hw.get(e["origin"], 0), e["origin_seq"])
        return hw

    def experiences(self, being_root: str, origin: str | None = None,
                    after_seq: int = 0) -> list[dict]:
        path = self._log_path(being_root)
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            sig = entry.get("signature")
            if not sig or not self.signer.verify(_canonical(entry), sig, ""):
                raise WeSyncError(f"tampered experience in {path.name}")
            if origin is not None and entry["origin"] != origin:
                continue
            if entry["origin_seq"] <= after_seq:
                continue
            out.append(entry)
        return out

    # ---------- peer cursors ----------

    def peer_cursors(self, being_root: str, peer: str) -> dict:
        path = self._peers_dir(being_root) / f"{peer}.json"
        if path.exists():
            return json.loads(path.read_text())
        return {"chain_cursor": 0, "experiences": {}}

    def _write_peer_cursors(self, being_root: str, peer: str,
                            cursors: dict) -> None:
        d = self._peers_dir(being_root)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f"{peer}.json.tmp"
        tmp.write_text(json.dumps(cursors, indent=2) + "\n")
        os.replace(tmp, d / f"{peer}.json")

    # ---------- export ----------

    def export_bundle(self, being_root: str, from_embodiment: str,
                      peer_cursors: dict | None = None) -> dict:
        """What ``from_embodiment`` has that the peer has not seen.

        ``peer_cursors``: {"chain_cursor": n, "experiences": {origin:
        seq}} — the peer's high-water marks (absent = send everything).
        """
        peer_cursors = peer_cursors or {}
        chain_seg = self.registry.segment(
            being_root, peer_cursors.get("chain_cursor", 0))
        exp_hw = peer_cursors.get("experiences", {})
        exps = [e for e in self.experiences(being_root)
                if e["origin_seq"] > exp_hw.get(e["origin"], 0)]
        bundle = {"schema": WE_BUNDLE_SCHEMA, "being_root": being_root,
                  "from": from_embodiment, "ms": now_ms(),
                  "genesis_sha": (self.registry.verify_chain(being_root)
                                  .get("genesis_sha")),
                  "chain_segment": chain_seg,
                  "experiences": exps}
        bundle["signature"] = self.signer.sign(_canonical(bundle))
        return bundle

    # ---------- import ----------

    def preview_import(self, bundle: dict) -> dict:
        """What importing this bundle WOULD do — no mutation."""
        self._validate_bundle(bundle)
        being_root = bundle["being_root"]
        local_tip = self.registry.current_cursor(being_root)
        new_chain = [e for e in bundle["chain_segment"]
                     if e["cursor"] > local_tip]
        local_keys = {(e["origin"], e["origin_seq"])
                      for e in self.experiences(being_root)}
        new_exps = [e for e in bundle["experiences"]
                    if (e["origin"], e["origin_seq"]) not in local_keys]
        return {"being_root": being_root, "from": bundle["from"],
                "new_chain_entries": len(new_chain),
                "new_experiences": len(new_exps),
                "chain_branch": self._detect_branch(bundle, local_tip)}

    def import_bundle(self, bundle: dict, actor: str = "wesync") -> dict:
        """Weave a peer's bundle into the local store.

        Idempotent: re-importing the same bundle adds nothing (dedupe by
        chain cursor and by (origin, origin_seq)). Chain branches are
        flagged (merge.json), never silently resolved. Origin
        attribution is preserved — entries are appended AS-IS, never
        re-signed.
        """
        self._validate_bundle(bundle)
        being_root = bundle["being_root"]
        report = {"being_root": being_root, "from": bundle["from"],
                  "chain_appended": 0, "chain_duplicates": 0,
                  "experiences_appended": 0, "experiences_duplicates": 0,
                  "branch": False}

        # --- chain segment ---
        local_tip = self.registry.current_cursor(being_root)
        tip_sha = self._chain_tip_sha(being_root)
        hist_path = self.registry._hist_path(being_root)
        for entry in bundle["chain_segment"]:
            if entry["cursor"] <= local_tip:
                report["chain_duplicates"] += 1
                # same cursor, different content = a partition branch
                if self._entry_differs(bundle, entry):
                    report["branch"] = True
                continue
            if tip_sha is None and entry["cursor"] != 1:
                # mid-chain segment on an empty local chain — we cannot
                # verify continuity; flag, don't fake it
                report["branch"] = True
                continue
            if tip_sha is not None and entry.get("prev_sha256") != tip_sha:
                # does not link onto our tip — a branch, not an append
                report["branch"] = True
                continue
            sig = entry.get("signature")
            if not sig or not self.signer.verify(_canonical(entry), sig, ""):
                raise WeSyncError(
                    f"unsigned/tampered chain entry at cursor {entry['cursor']}")
            hist_path.parent.mkdir(parents=True, exist_ok=True)
            with hist_path.open("a") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            local_tip = entry["cursor"]
            tip_sha = _sha256_hex(_canonical(entry))
            report["chain_appended"] += 1

        if report["chain_appended"]:
            # the snapshot is a derived view (R3): refresh it from the
            # extended chain so subsequent reads see the new tip
            snap_path = self.registry._snap_path(being_root)
            if snap_path.exists():
                snap_path.unlink()
            self.registry._rebuild_snap(being_root)

        if report["branch"]:
            self._flag_merge(being_root, bundle["from"], actor)

        # --- experiences (union, idempotent) ---
        local_keys = {(e["origin"], e["origin_seq"])
                      for e in self.experiences(being_root)}
        log_path = self._log_path(being_root)
        for entry in bundle["experiences"]:
            key = (entry["origin"], entry["origin_seq"])
            if key in local_keys:
                report["experiences_duplicates"] += 1
                continue
            sig = entry.get("signature")
            if not sig or not self.signer.verify(_canonical(entry), sig, ""):
                raise WeSyncError(
                    f"unsigned/tampered experience {entry['origin']}#{entry['origin_seq']}")
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a") as fh:
                fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
            local_keys.add(key)
            report["experiences_appended"] += 1

        # --- advance peer cursors ---
        cursors = self.peer_cursors(being_root, bundle["from"])
        if bundle["chain_segment"]:
            cursors["chain_cursor"] = max(
                cursors.get("chain_cursor", 0),
                max(e["cursor"] for e in bundle["chain_segment"]))
        exp_hw = cursors.setdefault("experiences", {})
        for e in bundle["experiences"]:
            exp_hw[e["origin"]] = max(exp_hw.get(e["origin"], 0),
                                      e["origin_seq"])
        self._write_peer_cursors(being_root, bundle["from"], cursors)
        logger.info("wesync: imported from %s — chain +%d, experiences +%d%s",
                    bundle["from"], report["chain_appended"],
                    report["experiences_appended"],
                    " (BRANCH flagged)" if report["branch"] else "")
        return report

    # ---------- internals ----------

    def _validate_bundle(self, bundle: dict) -> None:
        if bundle.get("schema") != WE_BUNDLE_SCHEMA:
            raise WeSyncError(f"not a {WE_BUNDLE_SCHEMA} bundle")
        sig = bundle.get("signature")
        if not sig or not self.signer.verify(_canonical(bundle), sig, ""):
            raise WeSyncError("unsigned or tampered bundle")
        being_root = bundle["being_root"]
        local_chain = self.registry.history(being_root)
        if local_chain and bundle["chain_segment"]:
            if not verify_common_root(local_chain, bundle["chain_segment"]):
                raise WeSyncError(
                    f"bundle for {being_root} does not share our genesis — "
                    "a different being, refusing")
        elif local_chain and bundle.get("genesis_sha"):
            if local_chain[0].get("genesis_sha") != bundle["genesis_sha"]:
                raise WeSyncError(
                    f"bundle for {being_root} does not share our genesis — "
                    "a different being, refusing")

    def _chain_tip_sha(self, being_root: str) -> str | None:
        line = self.registry._last_history_line(being_root)
        if line is None:
            return None
        return _sha256_hex(_canonical(json.loads(line)))

    def _detect_branch(self, bundle: dict, local_tip: int) -> bool:
        for entry in bundle["chain_segment"]:
            if entry["cursor"] <= local_tip:
                return self._entry_differs(bundle, entry)
        return False

    def _entry_differs(self, bundle: dict, entry: dict) -> bool:
        local = {e["cursor"]: e for e in
                 self.registry.history(bundle["being_root"])}
        mine = local.get(entry["cursor"])
        if mine is None:
            return False
        strip = lambda e: {k: v for k, v in e.items() if k != "signature"}
        return strip(mine) != strip(entry)

    def _flag_merge(self, being_root: str, peer: str, actor: str) -> None:
        """The 'mergeando' state (R7 dashboard): a branch exists and no
        winner is picked — convergence is a later, explicit act (R6)."""
        d = self._dir(being_root)
        d.mkdir(parents=True, exist_ok=True)
        state = {"schema": MERGE_SCHEMA, "being_root": being_root,
                 "branch_with": peer, "flagged_by": actor, "ms": now_ms()}
        state["signature"] = self.signer.sign(_canonical(state))
        self._merge_path(being_root).write_text(
            json.dumps(state, indent=2) + "\n")

    def merge_state(self, being_root: str) -> dict | None:
        path = self._merge_path(being_root)
        return json.loads(path.read_text()) if path.exists() else None
