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
from collections.abc import Callable, Mapping
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
HOLDER_ENROLLMENT_SCHEMA = "resource-fence-holder-enrollment/v1"
SUPPORT_SCHEMA = "resource-fence-support/v1"
DATABASE_SCHEMA = "resource-fence-sqlite/v2"
PRODUCTION_FENCE_SCHEMA = "resource-fence/v2"
_OPERATIONS = frozenset({"acquire", "renew", "release"})
MAX_AUTHORIZATION_TTL_S = 300
MAX_FENCE_TTL_S = 3600
MAX_CLOCK_SKEW_MS = 5_000


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _proof_ref(value: dict[str, Any]) -> str:
    return (
        "cluster:fence-proof:v1:"
        + hashlib.sha256(_json(value).encode("utf-8")).hexdigest()
    )


def ed25519_fingerprint(public_key: str) -> str:
    try:
        algorithm, encoded = public_key.split()[:2]
        if algorithm != "ssh-ed25519":
            raise ValueError
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise FenceError("holder public key must be OpenSSH Ed25519") from exc
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + digest


def _verify_ed25519(data: bytes, signature: str, public_key: str) -> bool:
    from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not signature.startswith(Ed25519Signer.PREFIX):
        return False
    try:
        decoded = base64.b64decode(
            signature[len(Ed25519Signer.PREFIX) :], validate=True
        )
        verifier = serialization.load_ssh_public_key(public_key.encode("ascii"))
        if not isinstance(verifier, Ed25519PublicKey):
            return False
        verifier.verify(decoded, data)
    except (ValueError, TypeError, CryptoInvalidSignature, UnicodeError):
        return False
    return True


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
    if (
        isinstance(ttl_s, bool)
        or not isinstance(ttl_s, int)
        or not 1 <= ttl_s <= MAX_AUTHORIZATION_TTL_S
    ):
        raise FenceError("holder authorization TTL is out of bounds")
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


def create_holder_enrollment(
    registrar: Ed25519Signer,
    *,
    holder_key_id: str,
    holder_pubkey: str,
    being_ref: str,
    body_ref: str,
    embodiment_id: str,
    incarnation_id: str,
    activation_id: str,
    credential_id: str,
    manifest_hash: str,
    issued_ms: int | None = None,
    ttl_s: int = 300,
    nonce: str,
) -> dict[str, Any]:
    """Create one registrar-signed binding from Matrix authority to a holder key."""

    timestamp = now_ms() if issued_ms is None else issued_ms
    if (
        isinstance(ttl_s, bool)
        or not isinstance(ttl_s, int)
        or not 1 <= ttl_s <= MAX_AUTHORIZATION_TTL_S
    ):
        raise FenceError("holder enrollment TTL is out of bounds")
    value: dict[str, Any] = {
        "schema": HOLDER_ENROLLMENT_SCHEMA,
        "registrar_key_id": registrar.key_id,
        "holder_key_id": holder_key_id,
        "holder_pubkey": holder_pubkey,
        "being_ref": being_ref,
        "body_ref": body_ref,
        "embodiment_id": embodiment_id,
        "incarnation_id": incarnation_id,
        "activation_id": activation_id,
        "credential_id": credential_id,
        "manifest_hash": manifest_hash,
        "issued_ms": timestamp,
        "expires_at_ms": timestamp + ttl_s * 1000,
        "nonce": nonce,
    }
    value["signature"] = registrar.sign(_canonical(value))
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
        clock: Callable[[], int] = now_ms,
        holder_registrars: Mapping[str, str] | None = None,
        verifier_only: bool = False,
    ):
        self._state_dir = Path(os.path.abspath(state_dir))
        self._database_path = (
            Path(os.path.abspath(database_path))
            if database_path is not None
            else self._state_dir / "resource-fences.sqlite3"
        )
        self._prepare_storage(verifier_only=verifier_only)
        self._signer: Ed25519Signer | None
        self._key_id: str | None
        if verifier_only:
            if signer is not None or key_id is not None:
                raise FenceError("verifier-only fences cannot receive signing custody")
            self._signer = None
            self._key_id = None
        else:
            if not isinstance(signer, Ed25519Signer):
                raise FenceError("production resource fences require an Ed25519 signer")
            if key_id is None or signer.key_id != key_id:
                raise FenceError("production signing key id mismatch")
            self._signer = signer
            self._key_id = key_id
        self._fault_hook = fault_hook
        self._clock = clock
        self._holder_registrars = dict(holder_registrars or {})
        if verifier_only and self._holder_registrars:
            raise FenceError("verifier-only fences cannot configure registrars")
        if verifier_only:
            self._open_verifier()
        else:
            self._initialize()

    def _hook(self, boundary: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(boundary)

    def _clock_now(self) -> int:
        observed = self._clock()
        if isinstance(observed, bool) or not isinstance(observed, int) or observed < 0:
            raise FenceError("production fence clock is invalid")
        return observed

    def _trusted_time(self, connection: sqlite3.Connection) -> int:
        observed = self._clock_now()
        row = connection.execute(
            "SELECT value FROM metadata WHERE name='clock_high_water_ms'"
        ).fetchone()
        if row is not None and observed < int(row["value"]):
            raise FenceError("production fence clock rolled back")
        connection.execute(
            "INSERT INTO metadata(name,value) VALUES('clock_high_water_ms',?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            (str(observed),),
        )
        return observed

    def _connect(self) -> sqlite3.Connection:
        self._validate_database_path(require_exists=True)
        connection = sqlite3.connect(
            self._database_path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        self._verify_connected_database(connection)
        return connection

    def _prepare_storage(self, *, verifier_only: bool) -> None:
        root = self._database_path.parent
        if verifier_only:
            self._validate_owner_directory(root)
            self._validate_database_path(require_exists=True)
            return
        if not root.exists():
            root.mkdir(mode=0o700)
        self._validate_owner_directory(root)
        if not self._database_path.exists():
            descriptor = os.open(
                self._database_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        self._validate_database_path(require_exists=True)

    @staticmethod
    def _validate_owner_directory(path: Path) -> None:
        try:
            info = path.lstat()
        except OSError as exc:
            raise FenceError("production fence directory is unavailable") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise FenceError("production fence directory is not owner-only")

    def _validate_database_path(self, *, require_exists: bool) -> os.stat_result | None:
        try:
            info = self._database_path.lstat()
        except FileNotFoundError:
            if not require_exists:
                return None
            raise FenceError("production fence database is unavailable")
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise FenceError("production fence database is not owner-controlled")
        return info

    def _verify_connected_database(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute("PRAGMA database_list").fetchall()
        main = next((row for row in rows if row[1] == "main"), None)
        if main is None or Path(main[2]).resolve() != self._database_path.resolve():
            connection.close()
            raise FenceError("production fence database binding changed")
        expected = self._validate_database_path(require_exists=True)
        proc = Path("/proc/self/fd")
        if proc.is_dir() and expected is not None:
            matched = False
            for entry in proc.iterdir():
                try:
                    target = os.readlink(entry)
                    info = entry.stat()
                except OSError:
                    continue
                if target == str(self._database_path) and (
                    info.st_dev,
                    info.st_ino,
                ) == (expected.st_dev, expected.st_ino):
                    matched = True
                    break
            if not matched:
                connection.close()
                raise FenceError("production fence database inode is unbound")

    def _read_connection(self) -> sqlite3.Connection:
        connection = self._connect()
        connection.execute("PRAGMA query_only = ON")
        return connection

    def _initialize(self) -> None:
        assert self._signer is not None and self._key_id is not None
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
                    being_ref TEXT NOT NULL,
                    body_ref TEXT NOT NULL,
                    embodiment_id TEXT NOT NULL,
                    incarnation_id TEXT NOT NULL,
                    activation_id TEXT NOT NULL,
                    credential_id TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    enrollment_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('active','revoked')),
                    created_ms INTEGER NOT NULL,
                    revoked_ms INTEGER
                ) STRICT;
                CREATE TABLE IF NOT EXISTS holder_registrars (
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
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO metadata(name,value) VALUES('schema',?)",
                (DATABASE_SCHEMA,),
            )
            schema = connection.execute(
                "SELECT value FROM metadata WHERE name='schema'"
            ).fetchone()
            if schema is None or schema["value"] != DATABASE_SCHEMA:
                raise FenceError("unsupported production fence database schema")
            created_ms = self._trusted_time(connection)
            existing = connection.execute(
                "SELECT public_key,state FROM signing_keys WHERE key_id=?",
                (self._key_id,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO signing_keys VALUES(?,?,?,?,NULL)",
                    (self._key_id, self._signer.public_key, "active", created_ms),
                )
            elif (
                existing["public_key"] != self._signer.public_key
                or existing["state"] != "active"
            ):
                raise FenceError("production signing key is mismatched or inactive")
            configured_registrars = sorted(self._holder_registrars.items())
            for registrar_id, public_key in configured_registrars:
                if (
                    not registrar_id
                    or not public_key
                    or ed25519_fingerprint(public_key) == ""
                ):
                    raise FenceError("invalid holder registrar")
                existing_registrar = connection.execute(
                    "SELECT public_key,state FROM holder_registrars WHERE key_id=?",
                    (registrar_id,),
                ).fetchone()
                if existing_registrar is None:
                    connection.execute(
                        "INSERT INTO holder_registrars VALUES(?,?,?,?,NULL)",
                        (registrar_id, public_key, "active", created_ms),
                    )
                elif (
                    existing_registrar["public_key"] != public_key
                    or existing_registrar["state"] != "active"
                ):
                    raise FenceError("holder registrar is mismatched or inactive")
            active_registrars = [
                (str(row["key_id"]), str(row["public_key"]))
                for row in connection.execute(
                    "SELECT key_id,public_key FROM holder_registrars "
                    "WHERE state='active' ORDER BY key_id"
                ).fetchall()
            ]
            # Configuration is an exact desired set, never an additive hint.
            # Omission therefore cannot silently preserve an old authority.
            if active_registrars != configured_registrars:
                raise FenceError("holder registrar configuration mismatch")
            registrar_hash = hashlib.sha256(
                _json({"active": active_registrars}).encode("utf-8")
            ).hexdigest()
            stored_hash = connection.execute(
                "SELECT value FROM metadata WHERE name='holder_registrar_config_hash'"
            ).fetchone()
            if stored_hash is None:
                connection.execute(
                    "INSERT INTO metadata(name,value) VALUES"
                    "('holder_registrar_generation','1'),"
                    "('holder_registrar_config_hash',?)",
                    (registrar_hash,),
                )
            elif stored_hash["value"] != registrar_hash:
                raise FenceError("holder registrar configuration changed without transition")
            connection.commit()
        except sqlite3.Error as exc:
            if "connection" in locals():
                connection.rollback()
            raise FenceError("cannot initialize production fence database") from exc
        except Exception:
            if "connection" in locals():
                connection.rollback()
            raise
        finally:
            if "connection" in locals():
                connection.close()
        self._secure_database_files()

    def _open_verifier(self) -> None:
        if not self._database_path.is_file():
            raise FenceError("production fence database is unavailable")
        self._secure_database_files()
        try:
            connection = self._read_connection()
            schema = connection.execute(
                "SELECT value FROM metadata WHERE name='schema'"
            ).fetchone()
            if schema is None or schema["value"] != DATABASE_SCHEMA:
                raise FenceError("unsupported production fence database schema")
        except sqlite3.Error as exc:
            raise FenceError("cannot open production fence verifier") from exc
        finally:
            if "connection" in locals():
                connection.close()

    def _secure_database_files(self) -> None:
        for path in (
            self._database_path,
            Path(str(self._database_path) + "-wal"),
            Path(str(self._database_path) + "-shm"),
        ):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if (
                stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise FenceError("production fence database is not owner-controlled")
            try:
                path.chmod(0o600)
            except FileNotFoundError:
                continue

    @staticmethod
    def _position(
        connection: sqlite3.Connection, resource_ref: str
    ) -> sqlite3.Row | None:
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
        if (
            expected_epoch is None
            or isinstance(expected_epoch, bool)
            or expected_epoch < -1
        ):
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
        if not isinstance(signature, str) or not _verify_ed25519(
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
            "SELECT * FROM holder_keys WHERE key_id=?",
            (current.get("holder_key_id"),),
        ).fetchone()
        if (
            holder is None
            or holder["state"] == "revoked"
            or holder["public_key"] != current.get("holder_pubkey")
            or holder["body_ref"] != current.get("body_ref")
            or holder["embodiment_id"] != current.get("holder_embodiment_id")
            or holder["incarnation_id"] != current.get("holder_incarnation_id")
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
    ) -> sqlite3.Row:
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
            or issued_ms > observed_at_ms + MAX_CLOCK_SKEW_MS
            or observed_at_ms - issued_ms > MAX_AUTHORIZATION_TTL_S * 1000
            or expires_at_ms <= observed_at_ms
            or expires_at_ms <= issued_ms
            or expires_at_ms - issued_ms > MAX_AUTHORIZATION_TTL_S * 1000
        ):
            raise InvalidSignature("holder authorization time or nonce is invalid")
        signature = authorization.get("signature")
        if not isinstance(signature, str) or not _verify_ed25519(
            _canonical(authorization), signature, holder_pubkey
        ):
            raise InvalidSignature("holder authorization signature is invalid")
        holder = connection.execute(
            "SELECT * FROM holder_keys WHERE key_id=?", (holder_key_id,)
        ).fetchone()
        if holder is None:
            raise InvalidSignature("holder key is unknown")
        if (
            holder["public_key"] != holder_pubkey
            or holder["state"] == "revoked"
            or holder["body_ref"] != body_ref
            or holder["embodiment_id"] != embodiment_id
            or holder["incarnation_id"] != incarnation_id
        ):
            raise InvalidSignature("holder key is mismatched or revoked")
        return holder

    def _signed_evidence(self, fields: dict[str, Any]) -> dict[str, Any]:
        if self._signer is None or self._key_id is None:
            raise FenceError("verifier-only fence store cannot mutate")
        value = {
            "schema": PRODUCTION_FENCE_SCHEMA,
            **fields,
            "signing_key_id": self._key_id,
        }
        value["signature"] = self._signer.sign(_canonical(value))
        return value

    def _assert_active_signer(self, connection: sqlite3.Connection) -> None:
        if self._signer is None or self._key_id is None:
            raise FenceError("verifier-only fence store cannot mutate")
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

    def _mutate(
        self, callback: Callable[[sqlite3.Connection], dict[str, Any]]
    ) -> dict[str, Any]:
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

    def admit_holder(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        """Register a Matrix-bound holder only through a trusted registrar."""

        required = {
            "schema",
            "registrar_key_id",
            "holder_key_id",
            "holder_pubkey",
            "being_ref",
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "activation_id",
            "credential_id",
            "manifest_hash",
            "issued_ms",
            "expires_at_ms",
            "nonce",
            "signature",
        }
        if not isinstance(enrollment, dict) or set(enrollment) != required:
            raise InvalidSignature("holder enrollment is malformed")
        if enrollment["schema"] != HOLDER_ENROLLMENT_SCHEMA:
            raise InvalidSignature("holder enrollment schema is unsupported")
        coordinates = (
            "registrar_key_id",
            "holder_key_id",
            "holder_pubkey",
            "being_ref",
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "activation_id",
            "credential_id",
            "manifest_hash",
            "nonce",
        )
        if not all(
            isinstance(enrollment.get(field), str) and enrollment[field]
            for field in coordinates
        ):
            raise InvalidSignature("holder enrollment coordinates are invalid")
        if ed25519_fingerprint(enrollment["holder_pubkey"]) == "":
            raise InvalidSignature("holder enrollment key is invalid")

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
            issued_ms = enrollment["issued_ms"]
            expires_at_ms = enrollment["expires_at_ms"]
            if (
                isinstance(issued_ms, bool)
                or not isinstance(issued_ms, int)
                or isinstance(expires_at_ms, bool)
                or not isinstance(expires_at_ms, int)
                or issued_ms > timestamp + MAX_CLOCK_SKEW_MS
                or timestamp - issued_ms > MAX_AUTHORIZATION_TTL_S * 1000
                or expires_at_ms <= timestamp
                or expires_at_ms <= issued_ms
                or expires_at_ms - issued_ms > MAX_AUTHORIZATION_TTL_S * 1000
            ):
                raise InvalidSignature("holder enrollment time is invalid")
            registrar = connection.execute(
                "SELECT public_key,state FROM holder_registrars WHERE key_id=?",
                (enrollment["registrar_key_id"],),
            ).fetchone()
            if (
                registrar is None
                or registrar["state"] != "active"
                or not _verify_ed25519(
                    _canonical(enrollment),
                    enrollment["signature"],
                    registrar["public_key"],
                )
            ):
                raise InvalidSignature("holder enrollment registrar is unauthorized")
            encoded = _json(enrollment)
            existing = connection.execute(
                "SELECT * FROM holder_keys WHERE key_id=?",
                (enrollment["holder_key_id"],),
            ).fetchone()
            if existing is not None:
                if (
                    existing["state"] == "active"
                    and existing["enrollment_json"] == encoded
                ):
                    return {
                        "admitted": True,
                        "idempotent": True,
                        "holder_key_id": enrollment["holder_key_id"],
                    }
                raise FenceConflict("holder key enrollment conflicts")
            connection.execute(
                "INSERT INTO holder_keys VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    enrollment["holder_key_id"],
                    enrollment["holder_pubkey"],
                    enrollment["being_ref"],
                    enrollment["body_ref"],
                    enrollment["embodiment_id"],
                    enrollment["incarnation_id"],
                    enrollment["activation_id"],
                    enrollment["credential_id"],
                    enrollment["manifest_hash"],
                    encoded,
                    "active",
                    timestamp,
                ),
            )
            return {
                "admitted": True,
                "idempotent": False,
                "holder_key_id": enrollment["holder_key_id"],
            }

        return self._mutate(mutation)

    def holder_registrar_position(self) -> dict[str, Any]:
        """Return the explicit registrar-set high-water and content hash."""

        try:
            connection = self._read_connection()
            rows = connection.execute(
                "SELECT key_id,public_key,state FROM holder_registrars ORDER BY key_id"
            ).fetchall()
            generation = connection.execute(
                "SELECT value FROM metadata WHERE name='holder_registrar_generation'"
            ).fetchone()
            config_hash = connection.execute(
                "SELECT value FROM metadata WHERE name='holder_registrar_config_hash'"
            ).fetchone()
            if generation is None or config_hash is None:
                raise FenceError("holder registrar lifecycle metadata is absent")
            return {
                "generation": int(generation["value"]),
                "config_hash": str(config_hash["value"]),
                "registrars": [dict(row) for row in rows],
            }
        finally:
            if "connection" in locals():
                connection.close()

    def revoke_holder_registrar(
        self, key_id: str, *, expected_generation: int
    ) -> dict[str, Any]:
        """Explicitly revoke a registrar and advance the durable high-water."""

        if not key_id:
            raise FenceError("holder registrar key id is invalid")

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
            generation_row = connection.execute(
                "SELECT value FROM metadata WHERE name='holder_registrar_generation'"
            ).fetchone()
            if (
                generation_row is None
                or isinstance(expected_generation, bool)
                or int(generation_row["value"]) != expected_generation
            ):
                raise FenceConflict("holder registrar generation is stale")
            updated = connection.execute(
                "UPDATE holder_registrars SET state='revoked',revoked_ms=? "
                "WHERE key_id=? AND state='active'",
                (timestamp, key_id),
            )
            if updated.rowcount != 1:
                raise FenceNotFound("holder registrar is absent or already revoked")
            active = [
                (str(row["key_id"]), str(row["public_key"]))
                for row in connection.execute(
                    "SELECT key_id,public_key FROM holder_registrars "
                    "WHERE state='active' ORDER BY key_id"
                ).fetchall()
            ]
            config_hash = hashlib.sha256(
                _json({"active": active}).encode("utf-8")
            ).hexdigest()
            generation = expected_generation + 1
            connection.execute(
                "UPDATE metadata SET value=? WHERE name='holder_registrar_generation'",
                (str(generation),),
            )
            connection.execute(
                "UPDATE metadata SET value=? WHERE name='holder_registrar_config_hash'",
                (config_hash,),
            )
            return {
                "revoked": True,
                "key_id": key_id,
                "generation": generation,
                "config_hash": config_hash,
            }

        return self._mutate(mutation)

    def transition_holder_registrars(
        self,
        desired: Mapping[str, str],
        *,
        expected_generation: int,
    ) -> dict[str, Any]:
        """CAS-transition the exact registrar set without implicit persistence."""

        requested = dict(desired)
        for key_id, public_key in requested.items():
            if not key_id or not public_key or ed25519_fingerprint(public_key) == "":
                raise FenceError("invalid holder registrar")

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
            generation_row = connection.execute(
                "SELECT value FROM metadata WHERE name='holder_registrar_generation'"
            ).fetchone()
            if (
                generation_row is None
                or isinstance(expected_generation, bool)
                or int(generation_row["value"]) != expected_generation
            ):
                raise FenceConflict("holder registrar generation is stale")
            existing = {
                str(row["key_id"]): row
                for row in connection.execute(
                    "SELECT * FROM holder_registrars"
                ).fetchall()
            }
            for key_id, public_key in sorted(requested.items()):
                row = existing.get(key_id)
                if row is None:
                    connection.execute(
                        "INSERT INTO holder_registrars VALUES(?,?,?,?,NULL)",
                        (key_id, public_key, "active", timestamp),
                    )
                elif row["state"] != "active" or row["public_key"] != public_key:
                    raise FenceError("holder registrar transition conflicts")
            for key_id, row in existing.items():
                if row["state"] == "active" and key_id not in requested:
                    connection.execute(
                        "UPDATE holder_registrars SET state='revoked',revoked_ms=? "
                        "WHERE key_id=?",
                        (timestamp, key_id),
                    )
            active = sorted(requested.items())
            config_hash = hashlib.sha256(
                _json({"active": active}).encode("utf-8")
            ).hexdigest()
            generation = expected_generation + 1
            connection.execute(
                "UPDATE metadata SET value=? WHERE name='holder_registrar_generation'",
                (str(generation),),
            )
            connection.execute(
                "UPDATE metadata SET value=? WHERE name='holder_registrar_config_hash'",
                (config_hash,),
            )
            return {
                "transitioned": True,
                "generation": generation,
                "config_hash": config_hash,
                "active_registrar_ids": sorted(requested),
            }

        result = self._mutate(mutation)
        self._holder_registrars = requested
        return result

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
    ) -> dict[str, Any]:
        self._validate_resource(resource_ref)
        if (
            isinstance(ttl_s, bool)
            or not isinstance(ttl_s, int)
            or not 1 <= ttl_s <= MAX_FENCE_TTL_S
        ):
            raise FenceError("production fence TTL is out of bounds")
        if not all(
            isinstance(value, str) and value
            for value in (
                body_ref,
                holder_embodiment_id,
                holder_incarnation_id,
                holder_key_id,
            )
        ):
            raise FenceError("exact holder coordinates are required")
        if fingerprint != ed25519_fingerprint(pubkey):
            raise InvalidSignature("holder key fingerprint mismatch")

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
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
    ) -> dict[str, Any] | None:
        del privkey_path
        self._validate_resource(resource_ref)

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
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
            )
            ttl_s = current["ttl_s"] if new_ttl_s is None else new_ttl_s
            if (
                isinstance(ttl_s, bool)
                or not isinstance(ttl_s, int)
                or not 1 <= ttl_s <= MAX_FENCE_TTL_S
            ):
                raise FenceError("production fence TTL is out of bounds")
            evidence = self._signed_evidence(
                {
                    **{
                        key: value
                        for key, value in current.items()
                        if key
                        not in {"signature", "signing_key_id", "authorization_ref"}
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
    ) -> dict[str, Any]:
        self._validate_resource(resource_ref)

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
            row = self._position(connection, resource_ref)
            actual_epoch, actual_proof = self._validate_expected(
                row, expected_epoch, expected_proof
            )
            if row is None or row["current_json"] is None:
                raise FenceNotFound("resource has no current holder")
            current = self._verify_position(connection, row)
            if self._is_expired(current, timestamp):
                raise FenceConflict(
                    "expired resource fence cannot be released by its holder"
                )
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
                return {
                    "resource_ref": resource_ref,
                    "epoch": -1,
                    "proof": None,
                    "current": False,
                }
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
        observed = self._clock_now() if at_ms is None else at_ms
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
        observed = self._clock_now() if at_ms is None else at_ms
        try:
            connection = self._read_connection()
            rows = connection.execute(
                "SELECT * FROM positions WHERE current_json IS NOT NULL ORDER BY resource_ref"
            ).fetchall()
            result = []
            for row in rows:
                current = self._verify_position(connection, row)
                if current.get(
                    "holder_embodiment_id"
                ) == holder_embodiment_id and not self._is_expired(current, observed):
                    result.append(copy.deepcopy(current))
            return result
        finally:
            if "connection" in locals():
                connection.close()

    def holder_binding(self, key_id: str) -> dict[str, Any]:
        if not isinstance(key_id, str) or not key_id:
            raise FenceError("holder key id is invalid")
        try:
            connection = self._read_connection()
            row = connection.execute(
                "SELECT * FROM holder_keys WHERE key_id=?", (key_id,)
            ).fetchone()
            if row is None or row["state"] != "active":
                raise FenceNotFound("holder key is absent or revoked")
            return {
                "holder_key_id": row["key_id"],
                "holder_pubkey": row["public_key"],
                "being_ref": row["being_ref"],
                "body_ref": row["body_ref"],
                "embodiment_id": row["embodiment_id"],
                "incarnation_id": row["incarnation_id"],
                "activation_id": row["activation_id"],
                "credential_id": row["credential_id"],
                "manifest_hash": row["manifest_hash"],
            }
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
        remaining = max(
            0,
            current["created_ms"] + current["ttl_s"] * 1000 - self._clock_now(),
        )
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
        if self._key_id is None:
            raise FenceError("verifier-only fence store cannot rotate custody")
        if signer.key_id == self._key_id:
            raise FenceError("replacement signing key id must be new")

        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
            existing = connection.execute(
                "SELECT public_key,state FROM signing_keys WHERE key_id=?",
                (signer.key_id,),
            ).fetchone()
            if existing is not None and (
                existing["public_key"] != signer.public_key
                or existing["state"] == "revoked"
            ):
                raise FenceError("replacement signing key is mismatched or revoked")
            connection.execute(
                "UPDATE signing_keys SET state='retired' WHERE key_id=? AND state='active'",
                (self._key_id,),
            )
            connection.execute(
                "INSERT INTO signing_keys VALUES(?,?,?,?,NULL) "
                "ON CONFLICT(key_id) DO UPDATE SET state='active'",
                (signer.key_id, signer.public_key, "active", timestamp),
            )
            return {"rotated": True}

        self._mutate(mutation)
        self._signer = signer
        self._key_id = signer.key_id

    def revoke_signing_key(self, key_id: str) -> None:
        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
            changed = connection.execute(
                "UPDATE signing_keys SET state='revoked',revoked_ms=? "
                "WHERE key_id=? AND state!='revoked'",
                (timestamp, key_id),
            ).rowcount
            if changed != 1:
                raise FenceNotFound("signing key is absent or already revoked")
            return {"revoked": True}

        self._mutate(mutation)

    def revoke_holder_key(self, key_id: str) -> None:
        def mutation(connection: sqlite3.Connection) -> dict[str, Any]:
            timestamp = self._trusted_time(connection)
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
                (timestamp, key_id),
            ).rowcount
            if changed != 1:
                raise FenceNotFound("holder key is absent or already revoked")
            return {"revoked": True, "retired_positions": retired}

        self._mutate(mutation)

    def support_status(self) -> dict[str, Any]:
        try:
            connection = self._read_connection()
            signing = (
                None
                if self._key_id is None
                else connection.execute(
                    "SELECT state FROM signing_keys WHERE key_id=?", (self._key_id,)
                ).fetchone()
            )
            verifier_count = connection.execute(
                "SELECT COUNT(*) AS count FROM signing_keys WHERE state!='revoked'"
            ).fetchone()["count"]
        finally:
            if "connection" in locals():
                connection.close()
        signer_ready = signing is not None and signing["state"] == "active"
        verifier_ready = int(verifier_count) > 0
        return {
            "schema": SUPPORT_SCHEMA,
            "mode": (
                "production-sqlite-ed25519-verifier"
                if self._signer is None
                else "production-sqlite-ed25519"
            ),
            "backend": DATABASE_SCHEMA,
            "signer": "ed25519",
            "signing_key_id": self._key_id,
            "signer_ready": signer_ready,
            "verifier_ready": verifier_ready,
            "production_ready": verifier_ready
            and (self._signer is None or signer_ready),
            "interprocess_cas": True,
            "cas_mode": "sqlite-begin-immediate-full-sync",
        }
