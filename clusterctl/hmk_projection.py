"""Cluster custody for the exact Matrix DM-034 -> pinned HMK effect lane.

Matrix remains authoritative for memory, policy, review and canonical result
history.  This module owns only a fixed physical HMK checkout/base, an
owner-local recovery journal, a production resource fence, and fresh effect
observation.  Nothing supplied by a curator item can select a process, path,
database, namespace, credential or transport operation.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol, cast

from .matrix_host import (
    EffectObserverRoute,
    MatrixHostAdapter,
    _matrix_api,
)

DM034_EXECUTOR_ADAPTER: Final = "cluster-dm034-hmk/v1"
DM034_WORK_KIND: Final = "memory-projection"
DM034_RESOURCE_NAMESPACE: Final = "hmk"
DM034_INTENT_SCHEMA: Final = "dm.cluster.dm034-execution-intent/v1"
DM034_REVIEW_SCHEMA: Final = "dm.cluster.dm034-source-review/v1"
DM034_POSTCONDITION_SCHEMA: Final = "dm.cluster.dm034-postcondition/v1"
DM034_SNAPSHOT_SCHEMA: Final = "dm.cluster.dm034-sqlite-snapshot/v1"
DM034_JOURNAL_SCHEMA_VERSION: Final = 1

_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_RESOURCE = re.compile(r"^hmk:[A-Za-z0-9._:@-]{1,220}$")
_MAX_RESULT_BYTES = 2 * 1024 * 1024
_MAX_DIAGNOSTIC_BYTES = 64 * 1024
_MAX_INTENT_BYTES = 64 * 1024
_MAX_DOCUMENT_BYTES = 18 * 1024 * 1024


class DM034ExecutorError(RuntimeError):
    """Stable disclosure-safe refusal at the physical projection boundary."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class ProjectionAdapter(Protocol):
    profile: Mapping[str, Any]

    def project(self, *, event_id: str, idempotency_key: str) -> Mapping[str, Any]: ...

    def inspect(self, *, memory_id: str) -> Mapping[str, Any]: ...

    def verify(self) -> Mapping[str, Any]: ...

    def reconcile(self, receipt: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def rebuild_plan(
        self, *, request_id: str, idempotency_key: str
    ) -> Mapping[str, Any]: ...

    def rebuild_apply(self, value: Any) -> Mapping[str, Any]: ...


IntentResolver = Callable[[Mapping[str, Any]], Mapping[str, Any]]
AdapterResolver = Callable[[Mapping[str, Any], Mapping[str, Any]], ProjectionAdapter]
FaultInjector = Callable[[str], None]


def _no_fault(_stage: str) -> None:
    return None


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = cast(bytes, _matrix_api()["canonical"].canonical_bytes(value))
    except Exception as exception:
        if isinstance(exception, DM034ExecutorError):
            raise
        raise DM034ExecutorError(code) from exception
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise DM034ExecutorError(code)
    return raw


def _digest(value: Any, code: str) -> str:
    return hashlib.sha256(_canonical(value, code)).hexdigest()


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise DM034ExecutorError(code)
    return value


def _token(value: Any, code: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise DM034ExecutorError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise DM034ExecutorError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise DM034ExecutorError(code) from exception
    if str(parsed) != value:
        raise DM034ExecutorError(code)
    return value


def _resource(value: Any) -> str:
    if not isinstance(value, str) or _RESOURCE.fullmatch(value) is None:
        raise DM034ExecutorError("dm034_resource_ref_rejected")
    return value


def _owner_directory(path: str | Path, *, create: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        absolute.mkdir(parents=True, mode=0o700, exist_ok=True)
        absolute.chmod(0o700)
    try:
        info = absolute.lstat()
    except FileNotFoundError as exception:
        raise DM034ExecutorError("dm034_owner_root_missing") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DM034ExecutorError("dm034_owner_root_rejected")
    return absolute


def dm034_executor_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return the fixed owner-local executor root for one embodiment."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise DM034ExecutorError("invalid_embodiment_id")
    key = hashlib.sha256(embodiment_id.encode("utf-8")).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "dm034-executors" / key


def profile_hash(profile: Mapping[str, Any]) -> str:
    """Validate and hash the exact pinned Matrix DM-034 profile."""

    projection = _matrix_api()["memory_projection"]
    try:
        normalized = projection.validate_projection_profile(profile)
    except Exception as exception:
        raise DM034ExecutorError("dm034_profile_rejected") from exception
    return _digest(normalized, "dm034_profile_rejected")


def _preview_core(intent: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(intent[key])
        for key in (
            "schema",
            "operation",
            "target_event_id",
            "decision_event_id",
            "source_event_id",
            "source_event_hash",
            "rebuild_request_id",
            "idempotency_key",
            "resource_ref",
            "profile_hash",
            "plan_hash",
        )
    }


def validate_dm034_intent(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "operation",
        "target_event_id",
        "decision_event_id",
        "source_event_id",
        "source_event_hash",
        "rebuild_request_id",
        "idempotency_key",
        "resource_ref",
        "profile_hash",
        "plan_hash",
        "preview_hash",
        "actor",
        "authority",
        "source_review",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DM034ExecutorError("invalid_dm034_execution_intent")
    row = copy.deepcopy(dict(value))
    if row["schema"] != DM034_INTENT_SCHEMA or row["operation"] not in {
        "project",
        "rebuild",
    }:
        raise DM034ExecutorError("unsupported_dm034_execution_intent")
    _uuid(row["target_event_id"], "invalid_dm034_execution_intent")
    _uuid(row["decision_event_id"], "invalid_dm034_execution_intent")
    _token(row["idempotency_key"], "invalid_dm034_execution_intent")
    _resource(row["resource_ref"])
    _hash(row["profile_hash"], "invalid_dm034_execution_intent")
    _token(row["actor"], "invalid_dm034_execution_intent")
    # Projection is an automated physical consequence of an already accepted
    # Matrix event.  A prior human review may be bound below, but it never turns
    # the Cluster worker into a human actor (and DM-031 forbids completing a
    # human-authority queue item directly).
    if row["authority"] != "daimon":
        raise DM034ExecutorError("invalid_dm034_execution_intent")
    if row["operation"] == "project":
        _uuid(row["source_event_id"], "invalid_dm034_execution_intent")
        _hash(row["source_event_hash"], "invalid_dm034_execution_intent")
        if (
            row["target_event_id"] != row["source_event_id"]
            or row["rebuild_request_id"] is not None
            or row["plan_hash"] is not None
        ):
            raise DM034ExecutorError("invalid_dm034_execution_intent")
    else:
        _uuid(row["rebuild_request_id"], "invalid_dm034_execution_intent")
        _hash(row["plan_hash"], "invalid_dm034_execution_intent")
        if row["source_event_id"] is not None or row["source_event_hash"] is not None:
            raise DM034ExecutorError("invalid_dm034_execution_intent")
    preview = _hash(row["preview_hash"], "invalid_dm034_execution_intent")
    if preview != _digest(_preview_core(row), "invalid_dm034_execution_intent"):
        raise DM034ExecutorError("dm034_preview_hash_mismatch")
    review = row["source_review"]
    if review is not None:
        review_fields = {
            "schema",
            "review_event_id",
            "review_hash",
            "reviewed_decision_event_id",
            "status",
            "independent",
        }
        if not isinstance(review, Mapping) or set(review) != review_fields:
            raise DM034ExecutorError("dm034_review_rejected")
        if (
            review["schema"] != DM034_REVIEW_SCHEMA
            or review["status"] != "approved"
            or review["independent"] is not True
            or review["reviewed_decision_event_id"] != row["decision_event_id"]
        ):
            raise DM034ExecutorError("dm034_review_rejected")
        _uuid(review["review_event_id"], "dm034_review_rejected")
        _hash(review["review_hash"], "dm034_review_rejected")
    if len(_canonical(row, "invalid_dm034_execution_intent")) > _MAX_INTENT_BYTES:
        raise DM034ExecutorError("invalid_dm034_execution_intent")
    return row


def create_dm034_intent(
    *,
    operation: str,
    target_event_id: str,
    decision_event_id: str,
    source_event_id: str | None,
    source_event_hash: str | None,
    rebuild_request_id: str | None,
    idempotency_key: str,
    resource_ref: str,
    profile_hash_value: str,
    plan_hash: str | None,
    actor: str,
    authority: str,
    source_review: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Create the closed, payload-free current intent queued by Matrix."""

    core = {
        "schema": DM034_INTENT_SCHEMA,
        "operation": operation,
        "target_event_id": target_event_id,
        "decision_event_id": decision_event_id,
        "source_event_id": source_event_id,
        "source_event_hash": source_event_hash,
        "rebuild_request_id": rebuild_request_id,
        "idempotency_key": idempotency_key,
        "resource_ref": resource_ref,
        "profile_hash": profile_hash_value,
        "plan_hash": plan_hash,
    }
    return validate_dm034_intent(
        {
            **core,
            "preview_hash": _digest(core, "invalid_dm034_execution_intent"),
            "actor": actor,
            "authority": authority,
            "source_review": copy.deepcopy(source_review),
        }
    )


class PinnedHMKTransport:
    """Closed subprocess transport to one constructor-fixed exact HMK checkout."""

    def __init__(
        self,
        checkout: str | Path,
        base: str | Path,
        *,
        instance_id: str,
        timeout_seconds: int = 300,
        python_executable: str | Path = sys.executable,
    ) -> None:
        self.checkout = Path(os.path.abspath(checkout))
        self.base = _owner_directory(base, create=True)
        self.instance_id = _token(instance_id, "hmk_instance_rejected")
        self.timeout_seconds = timeout_seconds
        self.python_executable = str(Path(python_executable).resolve())
        if not 1 <= timeout_seconds <= 300:
            raise DM034ExecutorError("hmk_timeout_rejected")
        self._verify_checkout()

    def _verify_checkout(self) -> None:
        projection = _matrix_api()["memory_projection"]
        script = self.checkout / "scripts" / "daimon_projection.py"
        try:
            root_info = self.checkout.lstat()
            script_info = script.lstat()
            completed = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.checkout,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            dirty = subprocess.run(
                [
                    "git",
                    "diff-index",
                    "--quiet",
                    "HEAD",
                    "--",
                    "scripts/daimon_projection.py",
                    "scripts/memoryctl.py",
                ],
                cwd=self.checkout,
                check=False,
                capture_output=True,
                timeout=10,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError) as exception:
            raise DM034ExecutorError("hmk_checkout_unverifiable") from exception
        if (
            stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode)
            or stat.S_ISLNK(script_info.st_mode)
            or not stat.S_ISREG(script_info.st_mode)
            or completed.returncode != 0
            or completed.stdout.strip() != projection.HMK_COMMIT
            or dirty.returncode != 0
        ):
            raise DM034ExecutorError("hmk_contract_mismatch")

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if operation not in {
            "apply",
            "inspect",
            "verify",
            "rebuild-plan",
            "rebuild-apply",
        }:
            raise DM034ExecutorError("hmk_operation_rejected")
        _owner_directory(self.base)
        self._verify_checkout()
        raw = _canonical(document, "hmk_request_rejected") + b"\n"
        environment = {
            "HMK_AGENT_MEMORY_BASE": str(self.base),
            "HMK_INSTANCE_ID": self.instance_id,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONNOUSERSITE": "1",
        }
        try:
            completed = subprocess.run(
                [
                    self.python_executable,
                    str(self.checkout / "scripts" / "daimon_projection.py"),
                    "--instance-id",
                    self.instance_id,
                    operation,
                ],
                input=raw,
                capture_output=True,
                check=False,
                env=environment,
                timeout=self.timeout_seconds,
                umask=0o077,
            )
        except subprocess.TimeoutExpired as exception:
            raise DM034ExecutorError(
                "hmk_transport_unavailable", retryable=True
            ) from exception
        if (
            len(completed.stdout) > _MAX_RESULT_BYTES
            or len(completed.stderr) > _MAX_DIAGNOSTIC_BYTES
        ):
            raise DM034ExecutorError("hmk_response_too_large")
        if completed.returncode != 0:
            try:
                diagnostic = json.loads(completed.stderr)
                code = diagnostic["code"]
            except (json.JSONDecodeError, KeyError, TypeError):
                code = "hmk_transport_failed"
            if not isinstance(code, str) or _TOKEN.fullmatch(code) is None:
                code = "hmk_transport_failed"
            projection = _matrix_api()["memory_projection"]
            raise projection.MemoryProjectionError(code)
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exception:
            raise DM034ExecutorError("hmk_response_rejected") from exception
        if not isinstance(result, Mapping):
            raise DM034ExecutorError("hmk_response_rejected")
        return copy.deepcopy(dict(result))


@dataclass(frozen=True)
class _ExecutionRow:
    item_hash: str
    claim_hash: str
    intent_hash: str
    intent: dict[str, Any]
    state: str
    effect_id: str
    started_at_ms: int
    completed_at_ms: int | None
    inner_receipt: dict[str, Any] | None
    postcondition: dict[str, Any] | None
    outer_receipt: dict[str, Any] | None


class DM034ExecutionJournal:
    """Owner-only crash journal; never a memory or canonical-result store."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(os.path.abspath(path))
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def initialize(self) -> None:
        parent = _owner_directory(self.path.parent, create=True)
        if parent != self.path.parent:
            raise DM034ExecutorError("dm034_journal_root_rejected")
        descriptor = os.open(
            self.lock_path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            os.close(descriptor)
            raise DM034ExecutorError("dm034_journal_lock_rejected")
        os.close(descriptor)
        self.lock_path.chmod(0o600)
        with self._database() as database:
            database.execute(
                """CREATE TABLE IF NOT EXISTS dm034_executions (
                    item_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    item_hash TEXT NOT NULL,
                    claim_hash TEXT NOT NULL,
                    intent_hash TEXT NOT NULL,
                    intent_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN
                        ('pending','effect-applied','completed')),
                    effect_id TEXT NOT NULL,
                    started_at_ms INTEGER NOT NULL,
                    completed_at_ms INTEGER,
                    inner_json TEXT,
                    postcondition_json TEXT,
                    outer_json TEXT
                )"""
            )
            database.commit()
        self.path.chmod(0o600)

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        self.initialize()
        descriptor = os.open(self.lock_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise DM034ExecutorError("dm034_journal_lock_rejected")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    @contextmanager
    def _database(self) -> Iterator[sqlite3.Connection]:
        before: os.stat_result | None = None
        if self.path.exists() or self.path.is_symlink():
            try:
                before = self.path.lstat()
            except OSError as exception:
                raise DM034ExecutorError("dm034_journal_rejected") from exception
            if (
                stat.S_ISLNK(before.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o077
            ):
                raise DM034ExecutorError("dm034_journal_rejected")
        database = sqlite3.connect(self.path, timeout=30)
        try:
            after = self.path.lstat()
            if before is not None and (before.st_dev, before.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                raise DM034ExecutorError("dm034_journal_replaced")
            database.execute("PRAGMA journal_mode=DELETE")
            database.execute("PRAGMA synchronous=FULL")
            yield database
        finally:
            database.close()

    def lookup(self, item_id: str) -> _ExecutionRow | None:
        with self._database() as database:
            raw = database.execute(
                """SELECT item_hash,claim_hash,intent_hash,intent_json,state,
                   effect_id,started_at_ms,completed_at_ms,inner_json,
                   postcondition_json,outer_json FROM dm034_executions
                   WHERE item_id=?""",
                (item_id,),
            ).fetchone()
        if raw is None:
            return None
        decoded = [None if item is None else json.loads(item) for item in raw[8:]]
        return _ExecutionRow(
            item_hash=raw[0],
            claim_hash=raw[1],
            intent_hash=raw[2],
            intent=json.loads(raw[3]),
            state=raw[4],
            effect_id=raw[5],
            started_at_ms=raw[6],
            completed_at_ms=raw[7],
            inner_receipt=decoded[0],
            postcondition=decoded[1],
            outer_receipt=decoded[2],
        )

    def reserve(
        self,
        *,
        item_id: str,
        item_hash: str,
        claim_hash: str,
        intent_hash: str,
        intent: Mapping[str, Any],
        effect_id: str,
        started_at_ms: int,
    ) -> _ExecutionRow:
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                """INSERT OR IGNORE INTO dm034_executions VALUES
                   (?,?,?,?,?,?,'pending',?,?,NULL,NULL,NULL,NULL)""",
                (
                    item_id,
                    DM034_JOURNAL_SCHEMA_VERSION,
                    item_hash,
                    claim_hash,
                    intent_hash,
                    _canonical(intent, "invalid_dm034_execution_intent").decode(),
                    effect_id,
                    started_at_ms,
                ),
            )
            database.commit()
        row = self.lookup(item_id)
        assert row is not None
        return row

    def stage_effect(
        self,
        item_id: str,
        *,
        inner_receipt: Mapping[str, Any],
        postcondition: Mapping[str, Any],
        completed_at_ms: int,
    ) -> _ExecutionRow:
        inner = _canonical(inner_receipt, "dm034_inner_receipt_rejected").decode()
        post = _canonical(postcondition, "dm034_postcondition_rejected").decode()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            current = database.execute(
                "SELECT state,inner_json,postcondition_json,completed_at_ms "
                "FROM dm034_executions WHERE item_id=?",
                (item_id,),
            ).fetchone()
            if current is None:
                raise DM034ExecutorError("dm034_execution_not_reserved")
            if current[0] == "pending":
                database.execute(
                    """UPDATE dm034_executions SET state='effect-applied',
                       inner_json=?,postcondition_json=?,completed_at_ms=?
                       WHERE item_id=? AND state='pending'""",
                    (inner, post, completed_at_ms, item_id),
                )
            elif (current[1], current[2], current[3]) != (
                inner,
                post,
                completed_at_ms,
            ):
                raise DM034ExecutorError("dm034_historical_effect_changed")
            database.commit()
        row = self.lookup(item_id)
        assert row is not None
        return row

    def complete(self, item_id: str, outer_receipt: Mapping[str, Any]) -> _ExecutionRow:
        outer = _canonical(outer_receipt, "dm034_outer_receipt_rejected").decode()
        with self._database() as database:
            database.execute("BEGIN IMMEDIATE")
            current = database.execute(
                "SELECT state,outer_json FROM dm034_executions WHERE item_id=?",
                (item_id,),
            ).fetchone()
            if current is None or current[0] == "pending":
                raise DM034ExecutorError("dm034_effect_not_staged")
            if current[0] == "effect-applied":
                database.execute(
                    "UPDATE dm034_executions SET state='completed',outer_json=? "
                    "WHERE item_id=? AND state='effect-applied'",
                    (outer, item_id),
                )
            elif current[1] != outer:
                raise DM034ExecutorError("dm034_historical_receipt_changed")
            database.commit()
        row = self.lookup(item_id)
        assert row is not None
        return row


def _project_postcondition(
    adapter: ProjectionAdapter, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    projection = _matrix_api()["memory_projection"]
    normalized = projection.validate_projection_receipt(receipt)
    reconciliation = adapter.reconcile(normalized)
    if reconciliation != {
        "schema": projection.RECONCILIATION_SCHEMA,
        "receipt_id": normalized["receipt_id"],
        "status": "verified",
        "reason": "effect-truth-matches",
    }:
        raise DM034ExecutorError("dm034_effect_truth_discrepancy")
    source = cast(Mapping[str, Any], normalized["source_event"])
    inspected = adapter.inspect(memory_id=cast(str, source["memory_id"]))
    current = cast(Mapping[str, Any], inspected["projection"])
    statement = cast(Mapping[str, Any], current["statement"])
    head = cast(Mapping[str, Any], current["head"])
    return {
        "schema": DM034_POSTCONDITION_SCHEMA,
        "kind": "projection",
        "namespace_id": current["namespace_id"],
        "projection_id": current["projection_id"],
        "memory_id": current["memory_id"],
        "head_event_id": head["event_id"],
        "head_event_hash": head["event_hash"],
        "statement_sha256": statement["sha256"],
        "active": current["active"],
    }


def _rebuild_postcondition(
    adapter: ProjectionAdapter, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    projection = _matrix_api()["memory_projection"]
    normalized = projection.validate_rebuild_receipt(receipt)
    verified = adapter.verify()
    if (
        verified["namespace_id"] != normalized["namespace_id"]
        or verified["generation"] != normalized["generation"]
        or verified["manifest_hash"] != normalized["matrix_manifest_hash"]
    ):
        raise DM034ExecutorError("dm034_rebuild_postcondition_mismatch")
    return {
        "schema": DM034_POSTCONDITION_SCHEMA,
        "kind": "namespace-rebuild",
        "namespace_id": normalized["namespace_id"],
        "generation": normalized["generation"],
        "manifest_hash": normalized["matrix_manifest_hash"],
        "matrix_checkpoint_hash": normalized["matrix_checkpoint"]["hash"],
    }


class DM034ProjectionExecutor:
    """One exact fenced execution and observation lane for one embodiment."""

    def __init__(
        self,
        host: MatrixHostAdapter,
        *,
        resource_ref: str,
        current_intent: IntentResolver,
        adapter_resolver: AdapterResolver,
        journal: DM034ExecutionJournal,
        clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
        fault: FaultInjector = _no_fault,
    ) -> None:
        self.host = host
        self.resource_ref = _resource(resource_ref)
        self.current_intent = current_intent
        self.adapter_resolver = adapter_resolver
        self.journal = journal
        self.clock = clock
        self.fault = fault
        self.journal.initialize()

    @property
    def route(self) -> EffectObserverRoute:
        return EffectObserverRoute(
            adapter=DM034_EXECUTOR_ADAPTER,
            work_kind=DM034_WORK_KIND,
            resource_namespace=DM034_RESOURCE_NAMESPACE,
            observer=self.observe,
        )

    def _inputs(
        self, item_value: Mapping[str, Any], claim_value: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, str]:
        api = _matrix_api()
        try:
            item = api["curator"].validate_curator_item(item_value)
            claim = api["curator"].validate_curator_claim(claim_value)
        except Exception as exception:
            raise DM034ExecutorError("dm034_curator_artifact_rejected") from exception
        if (
            claim["item_id"] != item["item_id"]
            or claim["resource_ref"] != item["resource_ref"]
            or item["work_kind"] != DM034_WORK_KIND
            or item["resource_ref"] != self.resource_ref
            or item["coordination_mode"] != "resource-fence"
            or claim["resource_fence"] is None
        ):
            raise DM034ExecutorError("dm034_route_rejected")
        intent = self._resolve_current(item)
        intent_hash = _digest(intent, "invalid_dm034_execution_intent")
        expected_input = (
            f"matrix-event:{intent['source_event_id']}"
            if intent["operation"] == "project"
            else f"matrix-rebuild:{intent['rebuild_request_id']}"
        )
        if (
            intent["resource_ref"] != self.resource_ref
            or intent["actor"] != claim["actor_origin"]["principal_id"]
            or intent["authority"] != item["required_authority"]
            or item["input_ref"] != expected_input
            or item["input_hash"] != intent["preview_hash"]
            or item["effect_intent_hash"] != intent_hash
        ):
            raise DM034ExecutorError("dm034_current_intent_mismatch")
        item_hash = _digest(item, "dm034_curator_artifact_rejected")
        claim_hash = _digest(claim, "dm034_curator_artifact_rejected")
        return item, claim, intent, item_hash, claim_hash

    def _resolve_current(self, item: Mapping[str, Any]) -> dict[str, Any]:
        try:
            raw = self.current_intent(copy.deepcopy(item))
        except Exception as exception:
            raise DM034ExecutorError(
                "dm034_current_intent_unavailable", retryable=True
            ) from exception
        return validate_dm034_intent(raw)

    def _adapter(
        self, item: Mapping[str, Any], intent: Mapping[str, Any]
    ) -> ProjectionAdapter:
        try:
            return self.adapter_resolver(copy.deepcopy(item), copy.deepcopy(intent))
        except Exception as exception:
            raise DM034ExecutorError(
                "dm034_projection_adapter_unavailable", retryable=True
            ) from exception

    def _fence(
        self, claim: Mapping[str, Any], at_ms: int
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        evidence = self.host.fence_evidence(self.resource_ref)
        if evidence is None:
            raise DM034ExecutorError("dm034_production_fence_absent")
        api = _matrix_api()["cluster"]
        try:
            verified = api.verify_resource_fence_evidence(
                evidence,
                at_ms=at_ms,
                verifier=self.host.verify_fence,
                holder_embodiment_id=self.host.embodiment_id,
                resource_ref=self.resource_ref,
            )
            position = api.resource_fence_position(verified)
        except Exception as exception:
            raise DM034ExecutorError(
                "dm034_production_fence_unverifiable"
            ) from exception
        if position != claim["resource_fence"]:
            raise DM034ExecutorError("dm034_production_fence_changed")
        return verified, position

    @staticmethod
    def _row_matches(
        row: _ExecutionRow,
        *,
        item_hash: str,
        claim_hash: str,
        intent_hash: str,
        intent: Mapping[str, Any],
    ) -> None:
        if (
            row.item_hash != item_hash
            or row.claim_hash != claim_hash
            or row.intent_hash != intent_hash
            or row.intent != intent
        ):
            raise DM034ExecutorError("dm034_historical_execution_changed")

    def _observe_inner(
        self,
        adapter: ProjectionAdapter,
        intent: Mapping[str, Any],
        inner: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            if profile_hash(adapter.profile) != intent["profile_hash"]:
                raise DM034ExecutorError("dm034_profile_changed")
            if intent["operation"] == "project":
                normalized = _matrix_api()[
                    "memory_projection"
                ].validate_projection_receipt(inner)
                source = normalized["source_event"]
                if (
                    source["event_id"] != intent["source_event_id"]
                    or source["event_hash"] != intent["source_event_hash"]
                ):
                    raise DM034ExecutorError("dm034_source_event_changed")
                return _project_postcondition(adapter, normalized)
            return _rebuild_postcondition(adapter, inner)
        except DM034ExecutorError:
            raise
        except Exception as exception:
            raise DM034ExecutorError(
                "dm034_effect_truth_unverifiable",
                retryable=bool(getattr(exception, "retryable", True)),
            ) from exception

    def execute(
        self, item_value: Mapping[str, Any], claim_value: Mapping[str, Any]
    ) -> dict[str, Any]:
        with self.journal.exclusive():
            item, claim, intent, item_hash, claim_hash = self._inputs(
                item_value, claim_value
            )
            now = int(self.clock())
            if now >= claim["lease_until_ms"]:
                raise DM034ExecutorError("dm034_claim_expired", retryable=True)
            _evidence, fence_position = self._fence(claim, now)
            intent_hash = cast(str, item["effect_intent_hash"])
            row = self.journal.lookup(cast(str, item["item_id"]))
            if row is None:
                effect_id = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "dm034:" + item["item_id"] + ":" + claim_hash,
                    )
                )
                row = self.journal.reserve(
                    item_id=item["item_id"],
                    item_hash=item_hash,
                    claim_hash=claim_hash,
                    intent_hash=intent_hash,
                    intent=intent,
                    effect_id=effect_id,
                    started_at_ms=now,
                )
            self._row_matches(
                row,
                item_hash=item_hash,
                claim_hash=claim_hash,
                intent_hash=intent_hash,
                intent=intent,
            )
            adapter = self._adapter(item, intent)
            if profile_hash(adapter.profile) != intent["profile_hash"]:
                raise DM034ExecutorError("dm034_profile_changed")
            if row.state == "pending":
                if intent["operation"] == "project":
                    try:
                        inner = adapter.project(
                            event_id=cast(str, intent["source_event_id"]),
                            idempotency_key=cast(str, intent["idempotency_key"]),
                        )
                        projection = _matrix_api()["memory_projection"]
                        inner = projection.validate_projection_receipt(inner)
                    except Exception as exception:
                        raise DM034ExecutorError(
                            "dm034_inner_effect_unverifiable",
                            retryable=bool(getattr(exception, "retryable", True)),
                        ) from exception
                else:
                    try:
                        plan = adapter.rebuild_plan(
                            request_id=cast(str, intent["rebuild_request_id"]),
                            idempotency_key=cast(str, intent["idempotency_key"]),
                        )
                    except Exception as exception:
                        raise DM034ExecutorError(
                            "dm034_rebuild_preview_unverifiable",
                            retryable=bool(getattr(exception, "retryable", True)),
                        ) from exception
                    if (
                        _digest(plan, "dm034_rebuild_plan_rejected")
                        != intent["plan_hash"]
                    ):
                        raise DM034ExecutorError("dm034_rebuild_preview_changed")
                    try:
                        inner = adapter.rebuild_apply(plan)
                        projection = _matrix_api()["memory_projection"]
                        inner = projection.validate_rebuild_receipt(inner)
                    except Exception as exception:
                        raise DM034ExecutorError(
                            "dm034_inner_effect_unverifiable",
                            retryable=bool(getattr(exception, "retryable", True)),
                        ) from exception
                self.fault("after-inner-effect")
                postcondition = self._observe_inner(adapter, intent, inner)
                current = self._resolve_current(item)
                if current != intent:
                    raise DM034ExecutorError("dm034_current_intent_changed")
                completed_at = int(self.clock())
                if completed_at >= claim["lease_until_ms"]:
                    raise DM034ExecutorError("dm034_claim_expired", retryable=True)
                self._fence(claim, completed_at)
                row = self.journal.stage_effect(
                    item["item_id"],
                    inner_receipt=inner,
                    postcondition=postcondition,
                    completed_at_ms=completed_at,
                )
                self.fault("after-effect-stage")
            assert row.inner_receipt is not None
            assert row.postcondition is not None
            assert row.completed_at_ms is not None
            observed = self._observe_inner(adapter, intent, row.inner_receipt)
            if observed != row.postcondition:
                raise DM034ExecutorError("dm034_postcondition_changed")
            current = self._resolve_current(item)
            if current != intent:
                raise DM034ExecutorError("dm034_current_intent_changed")
            self._fence(claim, int(self.clock()))
            if row.outer_receipt is None:
                outer = self.host.create_effect_receipt(
                    effect_id=row.effect_id,
                    target_event_id=intent["target_event_id"],
                    decision_event_id=intent["decision_event_id"],
                    adapter=DM034_EXECUTOR_ADAPTER,
                    preview_hash=intent["preview_hash"],
                    intent_hash=intent_hash,
                    actor=intent["actor"],
                    authority=intent["authority"],
                    resource_fence=fence_position,
                    result="applied",
                    observed_postcondition=row.postcondition,
                    started_at_ms=row.started_at_ms,
                    completed_at_ms=row.completed_at_ms,
                )
                row = self.journal.complete(item["item_id"], outer)
                self.fault("after-outer-complete")
            assert row.outer_receipt is not None
            reconciliation = self.host.reconcile_effect(
                row.outer_receipt,
                intent=current,
                observed_postcondition=observed,
                at_ms=int(self.clock()),
            )
            if reconciliation["status"] != "verified":
                raise DM034ExecutorError("dm034_outer_effect_unverified")
            return copy.deepcopy(row.outer_receipt)

    def observe(
        self,
        item_value: Mapping[str, Any],
        receipt_value: Mapping[str, Any],
        at_ms: int,
    ) -> Mapping[str, Any]:
        api = _matrix_api()
        try:
            item = api["curator"].validate_curator_item(item_value)
            receipt = api["cluster"].validate_effect_receipt(receipt_value)
        except Exception as exception:
            raise DM034ExecutorError("dm034_observation_rejected") from exception
        if (
            item["work_kind"] != DM034_WORK_KIND
            or item["resource_ref"] != self.resource_ref
            or receipt["adapter"] != DM034_EXECUTOR_ADAPTER
        ):
            raise DM034ExecutorError("dm034_route_rejected")
        intent = self._resolve_current(item)
        intent_hash = _digest(intent, "invalid_dm034_execution_intent")
        row = self.journal.lookup(item["item_id"])
        if (
            row is None
            or row.state != "completed"
            or row.outer_receipt != receipt
            or row.intent != intent
            or row.intent_hash != intent_hash
            or row.inner_receipt is None
            or row.postcondition is None
        ):
            raise DM034ExecutorError("dm034_effect_truth_unverifiable")
        adapter = self._adapter(item, intent)
        observed = self._observe_inner(adapter, intent, row.inner_receipt)
        if observed != row.postcondition:
            raise DM034ExecutorError("dm034_postcondition_changed")
        evidence = self.host.fence_evidence(self.resource_ref)
        if evidence is None:
            raise DM034ExecutorError("dm034_production_fence_absent")
        return {
            "intent": intent,
            "observed_postcondition": observed,
            "current_fence_evidence": evidence,
        }


def _safe_regular(path: Path, code: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exception:
        raise DM034ExecutorError(code) from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DM034ExecutorError(code)
    return info


def _sqlite_evidence(path: Path) -> dict[str, Any]:
    info = _safe_regular(path, "dm034_sqlite_snapshot_rejected")
    try:
        database = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        integrity = database.execute("PRAGMA integrity_check").fetchone()
        foreign = database.execute("PRAGMA foreign_key_check").fetchone()
        database.close()
    except sqlite3.DatabaseError as exception:
        raise DM034ExecutorError("dm034_sqlite_integrity_failed") from exception
    if integrity != ("ok",) or foreign is not None:
        raise DM034ExecutorError("dm034_sqlite_integrity_failed")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return {
        "schema": DM034_SNAPSHOT_SCHEMA,
        "byte_length": info.st_size,
        "sha256": digest.hexdigest(),
        "integrity_check": "ok",
        "foreign_key_violations": 0,
    }


def snapshot_hmk_database(base: str | Path, destination: str | Path) -> dict[str, Any]:
    """Create an integrity-checked SQLite backup and return payload-free evidence."""

    root = _owner_directory(base)
    source = root / "library.db"
    _safe_regular(source, "dm034_sqlite_source_rejected")
    target = Path(os.path.abspath(destination))
    _owner_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise DM034ExecutorError("dm034_sqlite_destination_exists")
    temporary = target.with_name(f".{target.name}.{uuid.uuid4()}.tmp")
    try:
        source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        target_db = sqlite3.connect(temporary)
        source_db.backup(target_db)
        target_db.close()
        source_db.close()
        temporary.chmod(0o600)
        os.replace(temporary, target)
        return _sqlite_evidence(target)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def restore_hmk_database(
    snapshot: str | Path, fresh_base: str | Path
) -> dict[str, Any]:
    """Restore a verified snapshot into a fresh owner-only HMK base."""

    source = Path(os.path.abspath(snapshot))
    expected = _sqlite_evidence(source)
    base = Path(os.path.abspath(fresh_base))
    if base.exists() or base.is_symlink():
        raise DM034ExecutorError("dm034_restore_destination_exists")
    base.mkdir(parents=True, mode=0o700)
    base.chmod(0o700)
    target = base / "library.db"
    try:
        source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        target_db = sqlite3.connect(target)
        source_db.backup(target_db)
        target_db.close()
        source_db.close()
        target.chmod(0o600)
        actual = _sqlite_evidence(target)
        if actual != expected:
            raise DM034ExecutorError("dm034_restore_digest_mismatch")
        return actual
    except BaseException:
        if target.exists():
            target.unlink()
        try:
            base.rmdir()
        except OSError:
            pass
        raise


__all__ = [
    "DM034ExecutionJournal",
    "DM034ExecutorError",
    "DM034ProjectionExecutor",
    "DM034_EXECUTOR_ADAPTER",
    "DM034_INTENT_SCHEMA",
    "DM034_POSTCONDITION_SCHEMA",
    "DM034_RESOURCE_NAMESPACE",
    "DM034_REVIEW_SCHEMA",
    "DM034_SNAPSHOT_SCHEMA",
    "DM034_WORK_KIND",
    "PinnedHMKTransport",
    "create_dm034_intent",
    "dm034_executor_root",
    "profile_hash",
    "restore_hmk_database",
    "snapshot_hmk_database",
    "validate_dm034_intent",
]
