"""Production resource fences: authenticated holder operations and SQLite CAS.

The database is the sole mutable authority.  A position row, its monotonic
high-water, the last signed evidence and release tombstones commit together.
Legacy JSON fences are never read on the live path.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .fences import (
    Ed25519Signer,
    FenceConflict,
    FenceError,
    FenceNotFound,
    InvalidSignature,
    Signer,
    _canonical,
    now_ms,
)

AUTHORIZATION_SCHEMA = "resource-fence-holder-authorization/v1"
SUPPORT_SCHEMA = "resource-fence-support/v1"
DATABASE_SCHEMA = "resource-fence-sqlite/v1"
PRODUCTION_FENCE_SCHEMA = "resource-fence/v2"
_OPERATIONS = frozenset({"acquire", "renew", "release"})


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _proof_ref(value: dict[str, Any]) -> str:
    return "cluster:fence-proof:v1:" + hashlib.sha256(
        _json(value).encode("utf-8")
    ).hexdigest()


def _public_fingerprint(public_key: str) -> str:
    try:
        algorithm, encoded = public_key.split()[:2]
        if algorithm != "ssh-ed25519":
            raise ValueError
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise FenceError("holder public key must be OpenSSH Ed25519") from exc
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + digest


def create_holder_authorization(
    signer: Ed25519Signer,
    *,
    operation: str,
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    resource_ref: str,
    expected_epoch: int,
    expected_proof: str | None,
    issued_ms: int | None = None,
    ttl_s: int = 60,
    nonce: str,
) -> dict[str, Any]:
    """Create one short-lived, position-bound holder authorization."""

    if operation not in _OPERATIONS:
        raise FenceError("invalid holder operation")
    timestamp = now_ms() if issued_ms is None else issued_ms
    if ttl_s <= 0:
        raise FenceError("holder authorization TTL must be positive")
    value: dict[str, Any] = {
        "schema": AUTHORIZATION_SCHEMA,
        "operation": operation,
        "body_ref": body_ref,
        "embodiment_id": embodiment_id,
        "incarnation_id": incarnation_id,
        "resource_ref": resource_ref,
        "holder_key_id": signer.key_id,
        "holder_pubkey": signer.public_key,
        "expected_epoch": expected_epoch,
        "expected_proof": expected_proof,
        "issued_ms": timestamp,
        "expires_at_ms": timestamp + ttl_s * 1000,
        "nonce": nonce,
    }
    value["signature"] = signer.sign(_canonical(value))
    return value


class ProductionFenceStore:
    """One transactional, signed fence authority for a Cluster state root."""

    FENCE_SCHEMA = PRODUCTION_FENCE_SCHEMA
    LEASE_SCHEMA = PRODUCTION_FENCE_SCHEMA

    def __init__(
        self,
        state_dir: str | Path,
        *,
        signer: Signer | None,
        key_id: str | None,
        database_path: str | Path | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ):
        if not isinstance(signer, Ed25519Signer):
            raise FenceError("production resource fences require an Ed25519 signer")
        if key_id is None or signer.key_id != key_id:
            raise FenceError("production signing key id mismatch")
        self._state_dir = Path(state_dir)
        self._database_path = (
            Path(database_path)
            if database_path is not None
            else self._state_dir / "resource-fences.sqlite3"
        )
        self._signer = signer
        self._key_id = key_id
        self._fault_hook = fault_hook
        self._initialize()

    def _hook(self, boundary: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(boundary)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _read_connection(self) -> sqlite3.Connection:
        connection = self._connect()
        connection.execute("PRAGMA query_only = ON")
        return connection

    def _initialize(self) -> None:
        self._database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            connection = self._connect()
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS signing_keys (
                    key_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active','retired','revoked')),
                    created_ms INTEGER NOT NULL,
                    revoked_ms INTEGER
                ) STRICT;
                CREATE TABLE IF NOT EXISTS holder_keys (
                    key_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active','revoked')),
                    created_ms INTEGER NOT NULL,
                    revoked_ms INTEGER
                ) STRICT;
                CREATE TABLE IF NOT EXISTS positions (
                    resource_ref TEXT PRIMARY KEY,
                    high_water INTEGER NOT NULL CHECK (high_water >= 0),
                    last_proof TEXT NOT NULL,
                    current_json TEXT,
                    last_evidence_json TEXT NOT NULL,
                    updated_ms INTEGER NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS events (
                    resource_ref TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    operation TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    proof TEXT NOT NULL,
                    committed_ms INTEGER NOT NULL,
                    PRIMARY KEY (resource_ref, epoch)
                ) STRICT;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO metadata(name,value) VALUES('schema',?)",
                (DATABASE_SCHEMA,),
            )
            schema = connection.execute(
                "SELECT value FROM metadata WHERE name='schema'"
            ).fetchone()
            if schema is None or schema["value"] != DATABASE_SCHEMA:
                raise FenceError("unsupported production fence database schema")
            existing = connection.execute(
                "SELECT public_key,state FROM signing_keys WHERE key_id=?",
                (self._key_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO signing_keys VALUES(?,?,?,?,NULL)",
                    (self._key_id, self._signer.public_key, "active", now_ms()),
                )
            elif (
                existing["public_key"] != self._signer.public_key
                or existing["state"] != "active"
            ):
                raise FenceError("production signing key is mismatched or inactive")
        except sqlite3.Error as exc:
            raise FenceError("cannot initialize production fence database") from exc
        finally:
            if "connection" in locals():
                connection.close()
        self._secure_database_files()

    def _secure_database_files(self) -> None:
        for path in (
            self._database_path,
            Path(str(self._database_path) + "-wal"),
            Path(str(self._database_path) + "-shm"),
        ):
            try:
                metadata = path.stat()
            except FileNotFoundError:
                continue
            if metadata.st_uid != os.geteuid() or not stat.S_ISREG(metadata.st_mode):
                raise FenceError("production fence database is not owner-controlled")
            try:
                path.chmod(0o600)
            except FileNotFoundError:
                continue

    @staticmethod
    def _position(connection: sqlite3.Connection, resource_ref: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM positions WHERE resource_ref=?", (resource_ref,)
        ).fetchone()

    @staticmethod
    def _validate_resource(resource_ref: str) -> None:
        if not resource_ref or len(resource_ref) > 512 or "\x00" in resource_ref:
            raise FenceError("invalid resource_ref")

    @staticmethod
    def _validate_expected(
        row: sqlite3.Row | None,
        expected_epoch: int | None,
        expected_proof: str | None,
    ) -> tuple[int, str | None]:
        if expected_epoch is None or isinstance(expected_epoch, bool) or expected_epoch < -1:
            raise FenceError("an exact expected fence epoch is required")
        actual_epoch = -1 if row is None else int(row["high_water"])
        actual_proof = None if row is None else str(row["last_proof"])
        if expected_epoch != actual_epoch or expected_proof != actual_proof:
            raise FenceConflict("resource fence expected position is stale")
        return actual_epoch, actual_proof

    def _key_for_record(
        self, connection: sqlite3.Connection, record: dict[str, Any]
    ) -> str:
        key_id = record.get("signing_key_id")
        if not isinstance(key_id, str):
            raise InvalidSignature("resource fence has no signing key id")
        key = connection.execute(
            "SELECT public_key,state FROM signing_keys WHERE key_id=?", (key_id,)
        ).fetchone()
        if key is None or key["state"] == "revoked":
            raise InvalidSignature("resource fence signing key is unknown or revoked")
        return str(key["public_key"])

    def _verify_record(
        self, connection: sqlite3.Connection, record: dict[str, Any]
    ) -> None:
        signature = record.get("signature")
        public_key = self._key_for_record(connection, record)
        if not isinstance(signature, str) or not self._signer.verify(
            _canonical(record), signature, public_key
        ):
            raise InvalidSignature("invalid production resource fence signature")

    def _verify_position(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> dict[str, Any]:
        try:
            evidence = json.loads(row["last_evidence_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise FenceError("unreadable production fence position") from exc
        self._verify_record(connection, evidence)
        if (
            evidence.get("resource_ref") != row["resource_ref"]
            or evidence.get("epoch") != row["high_water"]
            or _proof_ref(evidence) != row["last_proof"]
        ):
            raise FenceError("production fence position is inconsistent")
        current_json = row["current_json"]
        if current_json is None:
            if evidence.get("state") == "held":
                raise FenceError("production fence tombstone is inconsistent")
            return evidence
        try:
            current = json.loads(current_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise FenceError("unreadable production current fence") from exc
        if current != evidence or current.get("state") != "held":
            raise FenceError("production current fence is inconsistent")
        holder = connection.execute(
            "SELECT public_key,state FROM holder_keys WHERE key_id=?",
            (current.get("holder_key_id"),),
        ).fetchone()
        if (
            holder is None
            or holder["state"] == "revoked"
            or holder["public_key"] != current.get("holder_pubkey")
        ):
            raise InvalidSignature("current holder key is unknown or revoked")
        return current

    def _verify_authorization(
        self,
        connection: sqlite3.Connection,
        authorization: dict[str, Any] | None,
        *,
        operation: str,
        body_ref: str,
        embodiment_id: str,
        incarnation_id: str,
        resource_ref: str,
        holder_key_id: str,
        holder_pubkey: str,
        expected_epoch: int,
        expected_proof: str | None,
        observed_at_ms: int,
        allow_register: bool,
    ) -> None:
        if not isinstance(authorization, dict):
            raise InvalidSignature("holder authorization is required")
        expected = {
            "schema": AUTHORIZATION_SCHEMA,
            "operation": operation,
            "body_ref": body_ref,
            "embodiment_id": embodiment_id,
            "incarnation_id": incarnation_id,
            "resource_ref": resource_ref,
            "holder_key_id": holder_key_id,
            "holder_pubkey": holder_pubkey,
            "expected_epoch": expected_epoch,
            "expected_proof": expected_proof,
        }
        if any(authorization.get(key) != value for key, value in expected.items()):
            raise InvalidSignature("holder authorization binding mismatch")
        issued_ms = authorization.get("issued_ms")
        expires_at_ms = authorization.get("expires_at_ms")
        nonce = authorization.get("nonce")
        if (
            isinstance(issued_ms, bool)
            or not isinstance(issued_ms, int)
            or isinstance(expires_at_ms, bool)
            or not isinstance(expires_at_ms, int)
            or not isinstance(nonce, str)
            or not nonce
            or issued_ms > observed_at_ms
            or expires_at_ms <= observed_at_ms
            or expires_at_ms <= issued_ms
        ):
            raise InvalidSignature("holder authorization time or nonce is invalid")
        signature = authorization.get("signature")
        if not isinstance(signature, str) or not self._signer.verify(
            _canonical(authorization), signature, holder_pubkey
        ):
            raise InvalidSignature("holder authorization signature is invalid")
        holder = connection.execute(
            "SELECT public_key,state FROM holder_keys WHERE key_id=?", (holder_key_id,)
        ).fetchone()
        if holder is None:
            if not allow_register:
                raise InvalidSignature("holder key is unknown")
            connection.execute(
                "INSERT INTO holder_keys VALUES(?,?,?,?,NULL)",
                (holder_key_id, holder_pubkey, "active", observed_at_ms),
            )
        elif holder["public_key"] != holder_pubkey or holder["state"] == "revoked":
            raise InvalidSignature("holder key is mismatched or revoked")

    def _signed_evidence(self, fields: dict[str, Any]) -> dict[str, Any]:
        value = {
            "schema": PRODUCTION_FENCE_SCHEMA,
            **fields,
            "signing_key_id": self._key_id,
        }
        value["signature"] = self._signer.sign(_canonical(value))
        return value

    def _assert_active_signer(self, connection: sqlite3.Connection) -> None:
        key = connection.execute(
            "SELECT public_key,state FROM signing_keys WHERE key_id=?",
            (self._key_id,),
        ).fetchone()
        if (
            key is None
            or key["state"] != "active"
            or key["public_key"] != self._signer.public_key
        ):
            raise FenceError("production signing key is not active")

    def _commit_position(
        self,
        connection: sqlite3.Connection,
        evidence: dict[str, Any],
        *,
        current: bool,
    ) -> None:
        encoded = _json(evidence)
        proof = _proof_ref(evidence)
        connection.execute(
            """
            INSERT INTO positions(
                resource_ref,high_water,last_proof,current_json,
                last_evidence_json,updated_ms
            ) VALUES(?,?,?,?,?,?)
            ON CONFLICT(resource_ref) DO UPDATE SET
                high_water=excluded.high_water,
                last_proof=excluded.last_proof,
                current_json=excluded.current_json,
                last_evidence_json=excluded.last_evidence_json,
                updated_ms=excluded.updated_ms
            """,
            (
                evidence["resource_ref"],
                evidence["epoch"],
                proof,
                encoded if current else None,
                encoded,
                evidence["created_ms"],
            ),
        )
        connection.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?)",
            (
                evidence["resource_ref"],
                evidence["epoch"],
                evidence["operation"],
                encoded,
                proof,
                evidence["created_ms"],
            ),
        )

    def _mutate(self, callback: Callable[[sqlite3.Connection], dict[str, Any]]) -> dict[str, Any]:
        self._hook("before-begin")
        try:
            connection = self._connect()
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            self._hook("after-begin")
            self._assert_active_signer(connection)
            evidence = callback(connection)
            self._hook("before-commit")
            connection.commit()
            self._hook("after-commit")
            return copy.deepcopy(evidence)
        except sqlite3.Error as exc:
            if "connection" in locals():
                connection.rollback()
            raise FenceError("production fence transaction failed") from exc
        except Exception:
            if "connection" in locals():
                connection.rollback()
            raise
        finally:
            if "connection" in locals():
                connection.close()
            self._secure_database_files()

    def acquire(
        self,
        resource_ref: str,
        pubkey: str,
        fingerprint: str,
        ttl_s: int = 3600,
        renewer: str = "self",
        *,
        holder_embodiment_id: str | None = None,
        body_ref: str | None = None,
        holder_incarnation_id: str | None = None,
        holder_key_id: str | None = None,
        expected_epoch: int | None = None,
        expected_proof: str | None = None,
        authorization: dict[str, Any] | None = None,
        observed_at_ms: int | None = None,
    ) -> dict[str, Any]:
        self._validate_resource(resource_ref)
        if ttl_s <= 0:
            raise FenceError("production fence TTL must be positive")
        if not all(
            isinstance(value, str) and value
            for value in (body_ref, holder_embodiment_id, holder_incarnation_id, holder_key_id)
        ):
            raise FenceError("exact holder coordinates are required")
        if fingerprint != _public_fingerprint(pubkey):
            raise InvalidSignature("holder key fingerprint mismatch")
        timestamp = now_ms() if observed_at_ms is None else observed_at_ms

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = self._position(connection, resource_ref)
            actual_epoch, actual_proof = self._validate_expected(
                row, expected_epoch, expected_proof
            )
            if row is not None:
                current = self._verify_position(connection, row)
                if row["current_json"] is not None and not self._is_expired(
                    current, timestamp
                ):
                    raise FenceConflict("resource already has a current holder")
            self._verify_authorization(
                connection,
                authorization,
                operation="acquire",
                body_ref=str(body_ref),
                embodiment_id=str(holder_embodiment_id),
                incarnation_id=str(holder_incarnation_id),
                resource_ref=resource_ref,
                holder_key_id=str(holder_key_id),
                holder_pubkey=pubkey,
                expected_epoch=actual_epoch,
                expected_proof=actual_proof,
                observed_at_ms=timestamp,
                allow_register=True,
            )
            evidence = self._signed_evidence(
                {
                    "state": "held",
                    "operation": "acquire",
                    "resource_ref": resource_ref,
                    "body_ref": body_ref,
                    "holder_embodiment_id": holder_embodiment_id,
                    "holder_incarnation_id": holder_incarnation_id,
                    "holder_key_id": holder_key_id,
                    "holder_pubkey": pubkey,
                    "fingerprint": fingerprint,
                    "epoch": actual_epoch + 1,
                    "created_ms": timestamp,
                    "acquired_ms": timestamp,
                    "ttl_s": ttl_s,
                    "renewer": renewer,
                    "authorization_ref": _proof_ref(authorization or {}),
                }
            )
            self._commit_position(connection, evidence, current=True)
            return evidence

        return self._mutate(mutation)

    def renew(
        self,
        resource_ref: str,
        privkey_path: str = "",
        new_ttl_s: int | None = None,
        *,
        expected_epoch: int | None = None,
        expected_proof: str | None = None,
        authorization: dict[str, Any] | None = None,
        observed_at_ms: int | None = None,
    ) -> dict[str, Any] | None:
        del privkey_path
        self._validate_resource(resource_ref)
        timestamp = now_ms() if observed_at_ms is None else observed_at_ms

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = self._position(connection, resource_ref)
            actual_epoch, actual_proof = self._validate_expected(
                row, expected_epoch, expected_proof
            )
            if row is None or row["current_json"] is None:
                raise FenceNotFound("resource has no current holder")
            current = self._verify_position(connection, row)
            if self._is_expired(current, timestamp):
                raise FenceConflict("expired resource fence cannot be renewed")
            self._verify_authorization(
                connection,
                authorization,
                operation="renew",
                body_ref=current["body_ref"],
                embodiment_id=current["holder_embodiment_id"],
                incarnation_id=current["holder_incarnation_id"],
                resource_ref=resource_ref,
                holder_key_id=current["holder_key_id"],
                holder_pubkey=current["holder_pubkey"],
                expected_epoch=actual_epoch,
                expected_proof=actual_proof,
                observed_at_ms=timestamp,
                allow_register=False,
            )
            ttl_s = current["ttl_s"] if new_ttl_s is None else new_ttl_s
            if isinstance(ttl_s, bool) or not isinstance(ttl_s, int) or ttl_s <= 0:
                raise FenceError("production fence TTL must be positive")
            evidence = self._signed_evidence(
                {
                    **{
                        key: value
                        for key, value in current.items()
                        if key not in {"signature", "signing_key_id", "authorization_ref"}
                    },
                    "operation": "renew",
                    "epoch": actual_epoch + 1,
                    "created_ms": timestamp,
                    "ttl_s": ttl_s,
                    "authorization_ref": _proof_ref(authorization or {}),
                }
            )
            self._commit_position(connection, evidence, current=True)
            return evidence

        return self._mutate(mutation)

    def release(
        self,
        resource_ref: str,
        *,
        expected_epoch: int | None = None,
        expected_proof: str | None = None,
        authorization: dict[str, Any] | None = None,
        observed_at_ms: int | None = None,
    ) -> dict[str, Any]:
        self._validate_resource(resource_ref)
        timestamp = now_ms() if observed_at_ms is None else observed_at_ms

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = self._position(connection, resource_ref)
            actual_epoch, actual_proof = self._validate_expected(
                row, expected_epoch, expected_proof
            )
            if row is None or row["current_json"] is None:
                raise FenceNotFound("resource has no current holder")
            current = self._verify_position(connection, row)
            if self._is_expired(current, timestamp):
                raise FenceConflict("expired resource fence cannot be released by its holder")
            self._verify_authorization(
                connection,
                authorization,
                operation="release",
                body_ref=current["body_ref"],
                embodiment_id=current["holder_embodiment_id"],
                incarnation_id=current["holder_incarnation_id"],
                resource_ref=resource_ref,
                holder_key_id=current["holder_key_id"],
                holder_pubkey=current["holder_pubkey"],
                expected_epoch=actual_epoch,
                expected_proof=actual_proof,
                observed_at_ms=timestamp,
                allow_register=False,
            )
            evidence = self._signed_evidence(
                {
                    "state": "released",
                    "operation": "release",
                    "resource_ref": resource_ref,
                    "body_ref": current["body_ref"],
                    "holder_embodiment_id": current["holder_embodiment_id"],
                    "holder_incarnation_id": current["holder_incarnation_id"],
                    "holder_key_id": current["holder_key_id"],
                    "holder_pubkey": current["holder_pubkey"],
                    "fingerprint": current["fingerprint"],
                    "epoch": actual_epoch + 1,
                    "created_ms": timestamp,
                    "acquired_ms": current["acquired_ms"],
                    "ttl_s": 0,
                    "renewer": current["renewer"],
                    "authorization_ref": _proof_ref(authorization or {}),
                }
            )
            self._commit_position(connection, evidence, current=False)
            return evidence

        return self._mutate(mutation)

    @staticmethod
    def _is_expired(value: dict[str, Any], at_ms: int) -> bool:
        created = value.get("created_ms")
        ttl_s = value.get("ttl_s")
        if (
            isinstance(created, bool)
            or not isinstance(created, int)
            or isinstance(ttl_s, bool)
            or not isinstance(ttl_s, int)
            or ttl_s <= 0
        ):
            raise FenceError("invalid production fence time boundary")
        if at_ms < created:
            raise FenceError("fence observation precedes its signed creation")
        return at_ms >= created + ttl_s * 1000

    def get(self, resource_ref: str) -> dict[str, Any] | None:
        self._validate_resource(resource_ref)
        try:
            connection = self._read_connection()
            row = self._position(connection, resource_ref)
            if row is None or row["current_json"] is None:
                return None
            return copy.deepcopy(self._verify_position(connection, row))
        finally:
            if "connection" in locals():
                connection.close()

    @staticmethod
    def proof_ref(value: dict[str, Any]) -> str:
        return _proof_ref(value)

    def position(self, resource_ref: str) -> dict[str, Any]:
        self._validate_resource(resource_ref)
        try:
            connection = self._read_connection()
            row = self._position(connection, resource_ref)
            if row is None:
                return {"resource_ref": resource_ref, "epoch": -1, "proof": None, "current": False}
            self._verify_position(connection, row)
            return {
                "resource_ref": resource_ref,
                "epoch": row["high_water"],
                "proof": row["last_proof"],
                "current": row["current_json"] is not None,
            }
        finally:
            if "connection" in locals():
                connection.close()

    def verify_current(
        self, resource_ref: str, *, at_ms: int | None = None
    ) -> dict[str, Any] | None:
        self._validate_resource(resource_ref)
        observed = now_ms() if at_ms is None else at_ms
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
            raise FenceError("invalid fence observation time")
        try:
            connection = self._read_connection()
            row = self._position(connection, resource_ref)
            if row is None or row["current_json"] is None:
                return None
            current = self._verify_position(connection, row)
            if self._is_expired(current, observed):
                return None
            return copy.deepcopy(current)
        finally:
            if "connection" in locals():
                connection.close()

    def current_for_holder(
        self, holder_embodiment_id: str, *, at_ms: int | None = None
    ) -> list[dict[str, Any]]:
        observed = now_ms() if at_ms is None else at_ms
        try:
            connection = self._read_connection()
            rows = connection.execute(
                "SELECT * FROM positions WHERE current_json IS NOT NULL ORDER BY resource_ref"
            ).fetchall()
            result = []
            for row in rows:
                current = self._verify_position(connection, row)
                if (
                    current.get("holder_embodiment_id") == holder_embodiment_id
                    and not self._is_expired(current, observed)
                ):
                    result.append(copy.deepcopy(current))
            return result
        finally:
            if "connection" in locals():
                connection.close()

    def status(self, resource_ref: str) -> dict[str, Any]:
        position = self.position(resource_ref)
        current = self.get(resource_ref)
        if current is None:
            return {
                "resource_ref": resource_ref,
                "present": position["epoch"] >= 0,
                "expires_in_ms": 0,
                "expired": True,
                "renewer": None,
                "last_epoch": None if position["epoch"] < 0 else position["epoch"],
                "acquired_ms": None,
                "holder_embodiment_id": None,
            }
        remaining = max(0, current["created_ms"] + current["ttl_s"] * 1000 - now_ms())
        return {
            "resource_ref": resource_ref,
            "present": True,
            "expires_in_ms": remaining,
            "expired": remaining == 0,
            "renewer": current["renewer"],
            "last_epoch": current["epoch"],
            "acquired_ms": current["acquired_ms"],
            "holder_embodiment_id": current["holder_embodiment_id"],
        }

    def list_all(self) -> list[dict[str, Any]]:
        try:
            connection = self._read_connection()
            resources = [
                row["resource_ref"]
                for row in connection.execute(
                    "SELECT resource_ref FROM positions ORDER BY resource_ref"
                )
            ]
        finally:
            if "connection" in locals():
                connection.close()
        return [self.status(resource) for resource in resources]

    def collect_garbage(self) -> int:
        """Production history/tombstones are authoritative and never garbage."""

        return 0

    def restore(self, resource_ref: str, value: dict[str, Any]) -> None:
        del resource_ref, value
        raise FenceError("production fence bytes cannot be restored")

    def rotate_signer(self, signer: Ed25519Signer) -> None:
        if signer.key_id == self._key_id:
            raise FenceError("replacement signing key id must be new")

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            existing = connection.execute(
                "SELECT public_key,state FROM signing_keys WHERE key_id=?",
                (signer.key_id,),
            ).fetchone()
            if existing is not None and (
                existing["public_key"] != signer.public_key or existing["state"] == "revoked"
            ):
                raise FenceError("replacement signing key is mismatched or revoked")
            connection.execute(
                "UPDATE signing_keys SET state='retired' WHERE key_id=? AND state='active'",
                (self._key_id,),
            )
            connection.execute(
                "INSERT INTO signing_keys VALUES(?,?,?,?,NULL) "
                "ON CONFLICT(key_id) DO UPDATE SET state='active'",
                (signer.key_id, signer.public_key, "active", now_ms()),
            )
            return {"rotated": True}

        self._mutate(mutation)
        self._signer = signer
        self._key_id = signer.key_id

    def revoke_signing_key(self, key_id: str) -> None:
        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            changed = connection.execute(
                "UPDATE signing_keys SET state='revoked',revoked_ms=? "
                "WHERE key_id=? AND state!='revoked'",
                (now_ms(), key_id),
            ).rowcount
            if changed != 1:
                raise FenceNotFound("signing key is absent or already revoked")
            return {"revoked": True}

        self._mutate(mutation)

    def revoke_holder_key(self, key_id: str) -> None:
        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            holder = connection.execute(
                "SELECT public_key,state FROM holder_keys WHERE key_id=?", (key_id,)
            ).fetchone()
            if holder is None or holder["state"] == "revoked":
                raise FenceNotFound("holder key is absent or already revoked")
            rows = connection.execute(
                "SELECT * FROM positions WHERE current_json IS NOT NULL "
                "AND json_extract(current_json,'$.holder_key_id')=?",
                (key_id,),
            ).fetchall()
            retired = 0
            for row in rows:
                current = self._verify_position(connection, row)
                timestamp = now_ms()
                evidence = self._signed_evidence(
                    {
                        "state": "holder-key-revoked",
                        "operation": "revoke-holder-key",
                        "resource_ref": current["resource_ref"],
                        "body_ref": current["body_ref"],
                        "holder_embodiment_id": current["holder_embodiment_id"],
                        "holder_incarnation_id": current["holder_incarnation_id"],
                        "holder_key_id": key_id,
                        "holder_pubkey": current["holder_pubkey"],
                        "fingerprint": current["fingerprint"],
                        "epoch": int(row["high_water"]) + 1,
                        "created_ms": timestamp,
                        "acquired_ms": current["acquired_ms"],
                        "ttl_s": 0,
                        "renewer": current["renewer"],
                    }
                )
                self._commit_position(connection, evidence, current=False)
                retired += 1
            changed = connection.execute(
                "UPDATE holder_keys SET state='revoked',revoked_ms=? "
                "WHERE key_id=? AND state!='revoked'",
                (now_ms(), key_id),
            ).rowcount
            if changed != 1:
                raise FenceNotFound("holder key is absent or already revoked")
            return {"revoked": True, "retired_positions": retired}

        self._mutate(mutation)

    def support_status(self) -> dict[str, Any]:
        try:
            connection = self._read_connection()
            signing = connection.execute(
                "SELECT state FROM signing_keys WHERE key_id=?", (self._key_id,)
            ).fetchone()
            migration = connection.execute(
                "SELECT value FROM metadata WHERE name='legacy_migration'"
            ).fetchone()
        finally:
            if "connection" in locals():
                connection.close()
        ready = signing is not None and signing["state"] == "active"
        return {
            "schema": SUPPORT_SCHEMA,
            "mode": "production-sqlite-ed25519",
            "backend": DATABASE_SCHEMA,
            "signer": "ed25519",
            "signing_key_id": self._key_id,
            "signer_ready": ready,
            "verifier_ready": ready,
            "production_ready": ready,
            "interprocess_cas": True,
            "cas_mode": "sqlite-begin-immediate-full-sync",
            "migration_state": "not-run" if migration is None else migration["value"],
        }

    def migrate_synthetic_v1(self, *, offline: bool) -> int:
        """Retire expired V1 fixtures into signed tombstones while offline.

        Active or malformed legacy records are refused.  Their signatures are
        never treated as authentic; only resource names and monotonic epochs
        are carried forward into a new owner-signed retirement event.
        """

        if not offline:
            raise FenceError("synthetic fence migration requires explicit offline mode")
        legacy_dir = self._state_dir / "leases"
        high_waters_path = self._state_dir / "resource-fence-high-waters.json"
        high_waters: dict[str, int] = {}
        if high_waters_path.is_file():
            try:
                raw_high_waters = json.loads(high_waters_path.read_text(encoding="utf-8"))
                if not isinstance(raw_high_waters, dict):
                    raise ValueError
                high_waters = {str(key): int(value) for key, value in raw_high_waters.items()}
            except (OSError, ValueError, TypeError) as exc:
                raise FenceError("invalid synthetic high-water fixture") from exc
        candidates: dict[str, int] = dict(high_waters)
        if legacy_dir.is_dir():
            for path in sorted(legacy_dir.glob("*.json")):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    resource_ref = value["resource_ref"]
                    epoch = value["epoch"]
                    created_ms = value["created_ms"]
                    ttl_s = value["ttl_s"]
                except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                    raise FenceError("invalid synthetic fence fixture") from exc
                if (
                    not isinstance(resource_ref, str)
                    or isinstance(epoch, bool)
                    or not isinstance(epoch, int)
                    or epoch < 0
                    or not isinstance(created_ms, int)
                    or not isinstance(ttl_s, int)
                ):
                    raise FenceError("invalid synthetic fence fixture")
                if now_ms() < created_ms + ttl_s * 1000:
                    raise FenceError("active synthetic fence cannot be migrated")
                candidates[resource_ref] = max(candidates.get(resource_ref, -1), epoch)

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            if connection.execute("SELECT 1 FROM positions LIMIT 1").fetchone() is not None:
                raise FenceConflict("production fence database is not empty")
            migrated = 0
            for resource_ref, old_epoch in sorted(candidates.items()):
                self._validate_resource(resource_ref)
                timestamp = now_ms()
                evidence = self._signed_evidence(
                    {
                        "state": "migration-retired",
                        "operation": "migrate-synthetic-v1",
                        "resource_ref": resource_ref,
                        "epoch": old_epoch + 1,
                        "created_ms": timestamp,
                        "ttl_s": 0,
                    }
                )
                self._commit_position(connection, evidence, current=False)
                migrated += 1
            connection.execute(
                "INSERT INTO metadata(name,value) VALUES('legacy_migration','retired') "
                "ON CONFLICT(name) DO UPDATE SET value='retired'"
            )
            return {"migrated": migrated}

        result = self._mutate(mutation)
        return int(result["migrated"])
