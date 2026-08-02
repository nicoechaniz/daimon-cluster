"""Transactional independent ledger for one embodiment."""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .protocol import (
    MAX_PAGE_BYTES,
    MAX_PAGE_EVENTS,
    BeingManifest,
    EventSigner,
    ProtocolError,
    canonical_json,
    event_core,
    sign_event,
    validate_event,
)


class WeaveError(RuntimeError):
    """Ledger or synchronization invariant failed."""


class Ledger:
    def __init__(
        self,
        path: str | Path,
        *,
        manifest: BeingManifest,
        local_origin: Mapping[str, str],
        public_keys: Mapping[str, str],
    ):
        self.path = Path(path)
        self.manifest = manifest
        self.local_origin = dict(local_origin)
        manifest.origin_member(self.local_origin)
        self.public_keys = dict(public_keys)

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    incarnation_id TEXT NOT NULL,
                    embodiment_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    event_json BLOB NOT NULL,
                    imported_from TEXT NOT NULL,
                    inserted_at_ms INTEGER NOT NULL,
                    UNIQUE(incarnation_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS peer_cursors (
                    peer_id TEXT NOT NULL,
                    incarnation_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    tip_hash TEXT NOT NULL,
                    PRIMARY KEY(peer_id, incarnation_id)
                );
                CREATE TABLE IF NOT EXISTS peer_sync_state (
                    peer_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    error TEXT,
                    updated_at_ms INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_kind_subject
                    ON events(kind, subject);
                """
            )

    def _head(self, db: sqlite3.Connection, incarnation_id: str) -> sqlite3.Row | None:
        return db.execute(
            "SELECT event_id, sequence, content_hash FROM events WHERE incarnation_id=? ORDER BY sequence DESC LIMIT 1",
            (incarnation_id,),
        ).fetchone()

    def append_local(
        self,
        *,
        kind: str,
        subject: str,
        payload: Mapping[str, Any],
        signer: EventSigner,
        sensitivity: str = "personal",
        causal_parents: list[str] | None = None,
        supersedes: str | None = None,
        occurred_at_ms: int | None = None,
    ) -> dict[str, Any]:
        self.initialize()
        incarnation = self.local_origin["incarnation_id"]
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            head = self._head(db, incarnation)
            sequence = 1 if head is None else int(head["sequence"]) + 1
            core = event_core(
                event_id=str(uuid.uuid4()), manifest=self.manifest,
                origin=self.local_origin, sequence=sequence,
                previous_event_id=None if head is None else str(head["event_id"]),
                occurred_at_ms=int(time.time() * 1000) if occurred_at_ms is None else occurred_at_ms,
                causal_parents=sorted(set(causal_parents or [])), kind=kind,
                subject=subject, payload=payload, supersedes=supersedes,
                sensitivity=sensitivity,
            )
            event = sign_event(core, signer)
            validate_event(event, self.manifest, self.public_keys)
            self._insert(db, event, "local")
        return event

    @staticmethod
    def _insert(db: sqlite3.Connection, event: Mapping[str, Any], source: str) -> None:
        db.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event["event_id"], event["origin"]["incarnation_id"],
                event["origin"]["embodiment_id"], event["sequence"],
                event["kind"], event["subject"], event["content_hash"],
                canonical_json(event), source, int(time.time() * 1000),
            ),
        )

    def preview(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        self.initialize()
        if len(events) > MAX_PAGE_EVENTS or len(canonical_json({"events": events})) > MAX_PAGE_BYTES:
            raise ProtocolError("delta_page_too_large")
        validated = [validate_event(event, self.manifest, self.public_keys) for event in events]
        missing: list[dict[str, Any]] = []
        with self.connect() as db:
            staged: dict[str, tuple[int, str | None]] = {}
            for event in validated:
                existing = db.execute(
                    "SELECT content_hash FROM events WHERE event_id=?", (event["event_id"],)
                ).fetchone()
                if existing is not None:
                    if existing["content_hash"] != event["content_hash"]:
                        raise WeaveError("event_id_equivocation")
                    continue
                incarnation = event["origin"]["incarnation_id"]
                if incarnation not in staged:
                    head = self._head(db, incarnation)
                    staged[incarnation] = (0, None) if head is None else (int(head["sequence"]), str(head["event_id"]))
                last_sequence, last_id = staged[incarnation]
                if event["sequence"] != last_sequence + 1 or event["previous_event_id"] != last_id:
                    conflict = db.execute(
                        "SELECT content_hash FROM events WHERE incarnation_id=? AND sequence=?",
                        (incarnation, event["sequence"]),
                    ).fetchone()
                    if conflict is not None and conflict["content_hash"] != event["content_hash"]:
                        raise WeaveError("origin_sequence_equivocation")
                    raise WeaveError("origin_sequence_gap")
                staged[incarnation] = (event["sequence"], event["event_id"])
                missing.append(event)
        return {
            "manifest_hash": self.manifest.digest,
            "received": len(events),
            "missing": len(missing),
            "events": missing,
        }

    def ingest(self, events: list[dict[str, Any]], *, source: str) -> dict[str, Any]:
        try:
            preview = self.preview(events)
        except WeaveError as exc:
            state = "gap" if str(exc) == "origin_sequence_gap" else "quarantined"
            self._set_peer_sync_state(source, state, str(exc))
            raise
        except ProtocolError as exc:
            self._set_peer_sync_state(source, "quarantined", str(exc))
            raise
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for event in preview["events"]:
                self._insert(db, event, source)
                db.execute(
                    """INSERT INTO peer_cursors(peer_id, incarnation_id, sequence, tip_hash)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(peer_id, incarnation_id) DO UPDATE SET
                         sequence=excluded.sequence, tip_hash=excluded.tip_hash
                       WHERE excluded.sequence > peer_cursors.sequence""",
                    (source, event["origin"]["incarnation_id"], event["sequence"], event["content_hash"]),
                )
        self._set_peer_sync_state(source, "coherent", None)
        return {key: value for key, value in preview.items() if key != "events"}

    def _set_peer_sync_state(self, peer_id: str, state: str, error: str | None) -> None:
        self.initialize()
        with self.connect() as db:
            db.execute(
                """INSERT INTO peer_sync_state(peer_id, state, error, updated_at_ms)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(peer_id) DO UPDATE SET
                     state=excluded.state, error=excluded.error,
                     updated_at_ms=excluded.updated_at_ms""",
                (peer_id, state, error, int(time.time() * 1000)),
            )

    def peer_sync_states(self) -> list[dict[str, Any]]:
        """Last fail-closed transport result for each peer.

        A later valid pull clears a previous gap/quarantine. This is transport
        health only; unapplied semantic novelty is reported separately.
        """
        self.initialize()
        with self.connect() as db:
            rows = db.execute(
                "SELECT peer_id, state, error, updated_at_ms "
                "FROM peer_sync_state ORDER BY peer_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def novelty_summary(self) -> dict[str, Any]:
        """Aggregate unapplied peer-origin differences without payloads."""
        incoming = [
            item for item in self.diff()
            if item["origin"]["embodiment_id"]
            != self.local_origin["embodiment_id"]
        ]

        def counts(field: str) -> dict[str, int]:
            result: dict[str, int] = {}
            for item in incoming:
                if field == "origin":
                    key = item["origin"]["principal_id"]
                else:
                    key = str(item[field])
                result[key] = result.get(key, 0) + 1
            return dict(sorted(result.items()))

        return {
            "total": len(incoming),
            "by_kind": counts("kind"),
            "by_origin": counts("origin"),
            "by_state": counts("state"),
        }

    def peer_cursors(self, peer_id: str | None = None) -> list[dict[str, Any]]:
        self.initialize()
        query = "SELECT peer_id, incarnation_id, sequence, tip_hash FROM peer_cursors"
        parameters: tuple[Any, ...] = ()
        if peer_id is not None:
            query += " WHERE peer_id=?"
            parameters = (peer_id,)
        query += " ORDER BY peer_id, incarnation_id"
        with self.connect() as db:
            rows = db.execute(query, parameters).fetchall()
        return [dict(row) for row in rows]

    def events(self) -> list[dict[str, Any]]:
        self.initialize()
        with self.connect() as db:
            rows = db.execute(
                "SELECT event_json FROM events ORDER BY inserted_at_ms, incarnation_id, sequence"
            ).fetchall()
        return [json.loads(bytes(row["event_json"])) for row in rows]

    def heads(self) -> list[dict[str, Any]]:
        self.initialize()
        with self.connect() as db:
            rows = db.execute(
                """SELECT e.incarnation_id, e.sequence, e.event_id, e.content_hash
                   FROM events e JOIN (
                     SELECT incarnation_id, MAX(sequence) AS seq FROM events GROUP BY incarnation_id
                   ) h ON e.incarnation_id=h.incarnation_id AND e.sequence=h.seq
                   ORDER BY e.incarnation_id"""
            ).fetchall()
        return [
            {
                "incarnation_id": row["incarnation_id"],
                "max_sequence": row["sequence"],
                "tip_event_id": row["event_id"],
                "tip_hash": row["content_hash"],
            }
            for row in rows
        ]

    def delta(self, remote_heads: Mapping[str, int], limit: int = MAX_PAGE_EVENTS) -> list[dict[str, Any]]:
        if not 1 <= limit <= MAX_PAGE_EVENTS:
            raise WeaveError("invalid_delta_limit")
        result: list[dict[str, Any]] = []
        for event in self.events():
            if event["sequence"] > int(remote_heads.get(event["origin"]["incarnation_id"], 0)):
                candidate = result + [event]
                if len(canonical_json({"events": candidate})) > MAX_PAGE_BYTES:
                    break
                result.append(event)
                if len(result) == limit:
                    break
        return result

    def diff(self, *, kind: str | None = None, subject: str | None = None) -> list[dict[str, Any]]:
        all_events = self.events()
        decisions: dict[str, dict[str, Any]] = {}
        for event in all_events:
            if event["kind"] == "adoption.decided" and event["origin"]["embodiment_id"] == self.local_origin["embodiment_id"]:
                decisions[event["payload"]["target_event_id"]] = event
        result = []
        for event in all_events:
            if event["kind"] in {"adoption.decided", "projection.receipted", "lifecycle.announced"}:
                continue
            if kind is not None and event["kind"] != kind:
                continue
            if subject is not None and event["subject"] != subject:
                continue
            decision_event = decisions.get(event["event_id"])
            decision = None if decision_event is None else decision_event["payload"]["decision"]
            state = {None: "pending", "adopt": "adopted", "reject": "rejected", "defer": "deferred", "revert": "reverted"}[decision]
            result.append(
                {
                    "event_id": event["event_id"], "kind": event["kind"],
                    "subject": event["subject"], "origin": event["origin"],
                    "state": state, "decision_event_id": None if decision_event is None else decision_event["event_id"],
                }
            )
        return result
