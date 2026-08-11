"""Cluster custody for the exact Matrix DM-035 reviewed publication lane.

Matrix owns sources, consent, signed review, predecessor choice, queue state
and canonical acceptance history.  Cluster supplies one fixed provider,
production-fence truth and a fresh postcondition observer.  The queue cannot
select a checkout, path, repository, database, command, template or URL.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import re
import stat
import subprocess
import sys
import json
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any, Final, Protocol, cast

from .matrix_host import EffectObserverRoute, MatrixHostAdapter, _matrix_api

DM035_EXECUTOR_ADAPTER: Final = "cluster-dm035-publisher/v1"
DM035_WORK_KIND: Final = "publication"
DM035_RESOURCE_NAMESPACE: Final = "publication"
DM035_INTENT_SCHEMA: Final = "dm.cluster.dm035-execution-intent/v1"
DM035_POSTCONDITION_SCHEMA: Final = "dm.cluster.dm035-postcondition/v1"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_RESOURCE = re.compile(r"^publication:[A-Za-z0-9._:@-]{1,210}$")
_MAX_DOCUMENT_BYTES = 18 * 1024 * 1024


class DM035ExecutorError(RuntimeError):
    """Stable, disclosure-safe refusal at the publisher host boundary."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class PublicationCoordinator(Protocol):
    profile: Mapping[str, Any]
    policy: Mapping[str, Any]

    def execute(self, *, claim_id: str) -> Mapping[str, Any]: ...

    def reconcile(self, acceptance_event_id: str) -> Mapping[str, Any]: ...


IntentResolver = Callable[[Mapping[str, Any]], Mapping[str, Any]]
CoordinatorResolver = Callable[
    [Mapping[str, Any], Mapping[str, Any]], PublicationCoordinator
]


def _canonical(value: Any, code: str) -> bytes:
    try:
        raw = cast(bytes, _matrix_api()["canonical"].canonical_bytes(value))
    except Exception as exception:
        raise DM035ExecutorError(code) from exception
    if len(raw) > _MAX_DOCUMENT_BYTES:
        raise DM035ExecutorError(code)
    return raw


def _digest(value: Any, code: str) -> str:
    return hashlib.sha256(_canonical(value, code)).hexdigest()


def _hash(value: Any, code: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise DM035ExecutorError(code)
    return value


def _token(value: Any, code: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise DM035ExecutorError(code)
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise DM035ExecutorError(code)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exception:
        raise DM035ExecutorError(code) from exception
    if str(parsed) != value:
        raise DM035ExecutorError(code)
    return value


def _uint(value: Any, code: str, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= 2**53 - 1
    ):
        raise DM035ExecutorError(code)
    return value


def _resource(value: Any) -> str:
    if not isinstance(value, str) or _RESOURCE.fullmatch(value) is None:
        raise DM035ExecutorError("dm035_resource_ref_rejected")
    return value


def _owner_directory(
    path: str | Path, *, create: bool = False, owner_only: bool = True
) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        absolute.mkdir(parents=True, mode=0o700, exist_ok=True)
        if owner_only:
            absolute.chmod(0o700)
    try:
        info = absolute.lstat()
    except FileNotFoundError as exception:
        raise DM035ExecutorError("dm035_configured_root_missing") from exception
    forbidden = 0o077 if owner_only else 0o022
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & forbidden
    ):
        raise DM035ExecutorError("dm035_configured_root_rejected")
    return absolute


def dm035_publisher_root(state_dir: str | Path, embodiment_id: str) -> Path:
    """Return the fixed owner-local publisher custody root for an embodiment."""

    if not isinstance(embodiment_id, str) or not embodiment_id.startswith(
        "embodiment:"
    ):
        raise DM035ExecutorError("invalid_embodiment_id")
    key = hashlib.sha256(embodiment_id.encode()).hexdigest()[:32]
    return Path(os.path.abspath(state_dir)) / "dm035-publishers" / key


def publication_profile_hash(profile: Mapping[str, Any]) -> str:
    publication = _matrix_api()["publication"]
    try:
        normalized = publication.validate_publication_profile(profile)
    except Exception as exception:
        raise DM035ExecutorError("dm035_profile_rejected") from exception
    return _digest(normalized, "dm035_profile_rejected")


def publication_policy_hash(policy: Mapping[str, Any]) -> str:
    publication = _matrix_api()["publication"]
    try:
        normalized = publication.validate_publication_policy(policy)
    except Exception as exception:
        raise DM035ExecutorError("dm035_policy_rejected") from exception
    return _digest(normalized, "dm035_policy_rejected")


def _target_hash(value: Mapping[str, Any]) -> str:
    return _digest(value, "dm035_target_rejected")


def create_dm035_intent(
    *,
    request_event_id: str,
    request_event_hash: str,
    request: Mapping[str, Any],
    publication_claim: Mapping[str, Any],
    profile: Mapping[str, Any],
    resource_ref: str,
    predecessor_acceptance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project one canonical DM-035 request/claim into a payload-free intent."""

    publication = _matrix_api()["publication"]
    try:
        normalized_request = publication.validate_publication_request(request)
        normalized_claim = publication.validate_publication_claim(publication_claim)
        normalized_profile = publication.validate_publication_profile(profile)
    except Exception as exception:
        raise DM035ExecutorError("dm035_matrix_artifact_rejected") from exception
    event_id = _uuid(request_event_id, "dm035_request_event_rejected")
    event_hash = _hash(request_event_hash, "dm035_request_event_rejected")
    proposal = cast(Mapping[str, Any], normalized_request["proposal"])
    review = cast(Mapping[str, Any], normalized_request["review"])
    target = cast(Mapping[str, Any], proposal["target"])
    source = cast(Mapping[str, Any], proposal["source"])
    checkpoint = cast(Mapping[str, Any], source["checkpoint"])
    rendered = cast(Mapping[str, Any], proposal["rendered_ref"])
    governance = cast(Mapping[str, Any], proposal["governance"])
    if (
        normalized_claim["request_event_id"] != event_id
        or normalized_claim["request_event_hash"] != event_hash
        or normalized_claim["target"] != target
        or governance["consent"] != "explicit"
        or normalized_profile["provider_commit"] != publication.COMPAII_STATE_COMMIT
    ):
        raise DM035ExecutorError("dm035_matrix_artifact_mismatch")
    predecessor = cast(Mapping[str, Any] | None, proposal["predecessor"])
    prior = None
    before_target_hash = None
    if predecessor is None:
        if predecessor_acceptance is not None:
            raise DM035ExecutorError("dm035_unexpected_predecessor")
    else:
        if predecessor_acceptance is None:
            raise DM035ExecutorError("dm035_predecessor_required")
        try:
            previous = publication.validate_publication_acceptance(
                predecessor_acceptance
            )
        except Exception as exception:
            raise DM035ExecutorError("dm035_predecessor_rejected") from exception
        provider = cast(Mapping[str, Any], previous["provider_receipt"])
        if (
            previous["target"] != target
            or predecessor["acceptance_event_id"] is None
            or predecessor["provider_receipt_id"] != provider["receipt_id"]
            or predecessor["provider_receipt_hash"] != provider["receipt_hash"]
        ):
            raise DM035ExecutorError("dm035_predecessor_mismatch")
        prior = {
            "acceptance_event_id": predecessor["acceptance_event_id"],
            "acceptance_event_hash": predecessor["acceptance_event_hash"],
            "provider_receipt_id": provider["receipt_id"],
            "provider_receipt_hash": provider["receipt_hash"],
        }
        before_target_hash = provider["artifact_sha256"]
    fields = {
        "schema": DM035_INTENT_SCHEMA,
        "request_event_id": event_id,
        "request_event_hash": event_hash,
        "request_id": normalized_request["request_id"],
        "publication_claim_id": normalized_claim["claim_id"],
        "publication_claim_hash": normalized_claim["content_hash"],
        "publication_claim_generation": normalized_claim["generation"],
        "resource_ref": _resource(resource_ref),
        "target_kind": target["kind"],
        "target_hash": _target_hash(target),
        "operation": proposal["operation"],
        "artifact_sha256": rendered["sha256"],
        "before_target_sha256": before_target_hash,
        "source_set_hash": _digest(source["event_refs"], "dm035_source_rejected"),
        "source_checkpoint_hash": checkpoint["checkpoint_hash"],
        "consent": governance["consent"],
        "review": {
            "decision_id": review["decision_id"],
            "decision_hash": review["decision_hash"],
            "reviewer_key_id": review["reviewer"]["key_id"],
            "reviewer_principal": review["reviewer"]["principal"],
            "expires_at_ms": review["expires_at_ms"],
            "independent": review["reviewer"]["principal"]
            != normalized_profile["publisher_principal"],
        },
        "predecessor": prior,
        "profile_hash": publication_profile_hash(normalized_profile),
        "policy_hash": publication_policy_hash(normalized_request["policy"]),
        "actor": normalized_claim["actor_origin"]["principal_id"],
        "authority": "daimon",
        # The Matrix reviewer approved the exact deterministic final bytes.
        "preview_hash": rendered["sha256"],
    }
    return validate_dm035_intent(fields)


def validate_dm035_intent(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "request_event_id",
        "request_event_hash",
        "request_id",
        "publication_claim_id",
        "publication_claim_hash",
        "publication_claim_generation",
        "resource_ref",
        "target_kind",
        "target_hash",
        "operation",
        "artifact_sha256",
        "before_target_sha256",
        "source_set_hash",
        "source_checkpoint_hash",
        "consent",
        "review",
        "predecessor",
        "profile_hash",
        "policy_hash",
        "actor",
        "authority",
        "preview_hash",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DM035ExecutorError("invalid_dm035_execution_intent")
    row = copy.deepcopy(dict(value))
    if (
        row["schema"] != DM035_INTENT_SCHEMA
        or row["target_kind"] not in {"llm-wiki", "compaii-state"}
        or row["operation"] not in {"publish", "withdraw", "rollback"}
        or row["consent"] != "explicit"
        or row["authority"] != "daimon"
    ):
        raise DM035ExecutorError("unsupported_dm035_execution_intent")
    _uuid(row["request_event_id"], "invalid_dm035_execution_intent")
    _hash(row["request_event_hash"], "invalid_dm035_execution_intent")
    _token(row["request_id"], "invalid_dm035_execution_intent")
    _uuid(row["publication_claim_id"], "invalid_dm035_execution_intent")
    _hash(row["publication_claim_hash"], "invalid_dm035_execution_intent")
    _uint(
        row["publication_claim_generation"],
        "invalid_dm035_execution_intent",
        minimum=1,
    )
    _resource(row["resource_ref"])
    for name in (
        "target_hash",
        "artifact_sha256",
        "source_set_hash",
        "source_checkpoint_hash",
        "profile_hash",
        "policy_hash",
        "preview_hash",
    ):
        _hash(row[name], "invalid_dm035_execution_intent")
    if row["preview_hash"] != row["artifact_sha256"]:
        raise DM035ExecutorError("dm035_preview_hash_mismatch")
    before = row["before_target_sha256"]
    if before is not None:
        _hash(before, "invalid_dm035_execution_intent")
    _token(row["actor"], "invalid_dm035_execution_intent")
    review_fields = {
        "decision_id",
        "decision_hash",
        "reviewer_key_id",
        "reviewer_principal",
        "expires_at_ms",
        "independent",
    }
    review = row["review"]
    if (
        not isinstance(review, Mapping)
        or set(review) != review_fields
        or review["independent"] is not True
    ):
        raise DM035ExecutorError("dm035_review_rejected")
    _uuid(review["decision_id"], "dm035_review_rejected")
    _hash(review["decision_hash"], "dm035_review_rejected")
    _token(review["reviewer_key_id"], "dm035_review_rejected")
    _token(review["reviewer_principal"], "dm035_review_rejected")
    _uint(review["expires_at_ms"], "dm035_review_rejected", minimum=1)
    predecessor = row["predecessor"]
    if predecessor is None:
        if before is not None or row["operation"] != "publish":
            raise DM035ExecutorError("dm035_predecessor_rejected")
    else:
        prior_fields = {
            "acceptance_event_id",
            "acceptance_event_hash",
            "provider_receipt_id",
            "provider_receipt_hash",
        }
        if not isinstance(predecessor, Mapping) or set(predecessor) != prior_fields:
            raise DM035ExecutorError("dm035_predecessor_rejected")
        _uuid(predecessor["acceptance_event_id"], "dm035_predecessor_rejected")
        _hash(predecessor["acceptance_event_hash"], "dm035_predecessor_rejected")
        _token(predecessor["provider_receipt_id"], "dm035_predecessor_rejected")
        _token(predecessor["provider_receipt_hash"], "dm035_predecessor_rejected")
        if before is None:
            raise DM035ExecutorError("dm035_predecessor_rejected")
    _canonical(row, "invalid_dm035_execution_intent")
    return row


def _verify_git_checkout(
    root: Path, expected: str, tracked_paths: tuple[str, ...], code: str
) -> None:
    try:
        info = root.lstat()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        dirty = subprocess.run(
            ["git", "diff", "--quiet", "HEAD", "--", *tracked_paths],
            cwd=root,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exception:
        raise DM035ExecutorError(code) from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(info.st_mode) & 0o022
        or head.returncode != 0
        or head.stdout.strip() != expected
        or dirty.returncode != 0
    ):
        raise DM035ExecutorError(code)
    for relative in tracked_paths:
        try:
            tracked = (root / relative).lstat()
        except OSError as exception:
            raise DM035ExecutorError(code) from exception
        if (
            stat.S_ISLNK(tracked.st_mode)
            or not stat.S_ISREG(tracked.st_mode)
            or tracked.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(tracked.st_mode) & 0o022
        ):
            raise DM035ExecutorError(code)


def _load_provider(root: Path) -> ModuleType:
    name = "daimon_cluster_dm035_" + hashlib.sha256(str(root).encode()).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(name, root / "matrix_publisher.py")
    if spec is None or spec.loader is None:
        raise DM035ExecutorError("dm035_provider_unavailable")
    module = importlib.util.module_from_spec(spec)
    prior_state_safety = sys.modules.pop("state_safety", None)
    sys.path.insert(0, str(root))
    try:
        spec.loader.exec_module(module)
        loaded_state_safety = sys.modules.get("state_safety")
        loaded_path = getattr(loaded_state_safety, "__file__", None)
        if (
            loaded_path is None
            or Path(loaded_path).resolve() != (root / "state_safety.py").resolve()
        ):
            raise DM035ExecutorError("dm035_provider_dependency_mismatch")
    except Exception as exception:
        raise DM035ExecutorError("dm035_provider_unavailable") from exception
    finally:
        sys.path.remove(str(root))
        sys.modules.pop("state_safety", None)
        if prior_state_safety is not None:
            sys.modules["state_safety"] = prior_state_safety
    return module


def _provider_dispatch(
    module: ModuleType,
    api: Any,
    operation: str,
    document: Mapping[str, Any],
) -> Mapping[str, Any]:
    if operation == "manifest":
        return cast(Mapping[str, Any], module.manifest())
    if operation == "plan":
        return cast(Mapping[str, Any], api.plan(document["request"]))
    if operation == "acquire":
        return cast(Mapping[str, Any], api.acquire_lease(**document))
    if operation == "apply":
        return cast(Mapping[str, Any], api.apply(document["plan"], document["lease"]))
    if operation == "reconcile":
        return cast(Mapping[str, Any], api.reconcile(document["receipt"]))
    return cast(Mapping[str, Any], api.release_lease(document["lease"]))


class PinnedPublisherTransport:
    """Six-operation subprocess boundary to fixed exact provider/HMK roots."""

    OPERATIONS: Final = frozenset(
        {"manifest", "plan", "acquire", "apply", "reconcile", "release"}
    )

    def __init__(
        self,
        provider_checkout: str | Path,
        *,
        wiki_root: str | Path,
        projection_root: str | Path,
        runtime_root: str | Path,
        hmk_checkout: str | Path,
        hmk_base: str | Path,
        fixed_clock_ms: int | None = None,
        timeout_seconds: int = 300,
    ) -> None:
        self.provider_checkout = Path(os.path.abspath(provider_checkout))
        self.hmk_checkout = Path(os.path.abspath(hmk_checkout))
        self.wiki_root = _owner_directory(wiki_root, owner_only=False)
        self.projection_root = _owner_directory(projection_root, create=True)
        self.runtime_root = _owner_directory(runtime_root, create=True)
        self.hmk_base = _owner_directory(hmk_base, create=True)
        self.fixed_clock_ms = fixed_clock_ms
        self.timeout_seconds = timeout_seconds
        if fixed_clock_ms is not None:
            _uint(fixed_clock_ms, "dm035_fixed_clock_rejected")
        if not 1 <= timeout_seconds <= 300:
            raise DM035ExecutorError("dm035_timeout_rejected")
        self._verify()

    def _verify(self) -> None:
        publication = _matrix_api()["publication"]
        _verify_git_checkout(
            self.provider_checkout,
            publication.COMPAII_STATE_COMMIT,
            (
                "matrix_publisher.py",
                "state_safety.py",
                "policies/matrix-publisher-v1.json",
            ),
            "dm035_provider_contract_mismatch",
        )
        _verify_git_checkout(
            self.hmk_checkout,
            publication.HMK_COMMIT,
            ("scripts/memoryctl.py",),
            "dm035_hmk_contract_mismatch",
        )

    def __call__(
        self, operation: str, document: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if operation not in self.OPERATIONS:
            raise DM035ExecutorError("dm035_provider_operation_rejected")
        self._verify()
        _owner_directory(self.runtime_root)
        _owner_directory(self.hmk_base)
        request = {
            "schema": "dm.cluster.dm035-provider-call/v1",
            "operation": operation,
            "document": copy.deepcopy(dict(document)),
        }
        command = [
            sys.executable,
            "-m",
            "clusterctl.reviewed_publication_worker",
            "--provider-checkout",
            str(self.provider_checkout),
            "--wiki-root",
            str(self.wiki_root),
            "--projection-root",
            str(self.projection_root),
            "--runtime-root",
            str(self.runtime_root),
            "--hmk-checkout",
            str(self.hmk_checkout),
            "--hmk-base",
            str(self.hmk_base),
        ]
        if self.fixed_clock_ms is not None:
            command.extend(["--fixed-clock-ms", str(self.fixed_clock_ms)])
        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONNOUSERSITE": "1",
        }
        try:
            completed = subprocess.run(
                command,
                input=_canonical(request, "dm035_provider_request_rejected") + b"\n",
                capture_output=True,
                check=False,
                env=environment,
                timeout=self.timeout_seconds,
                umask=0o077,
            )
        except subprocess.TimeoutExpired as exception:
            raise DM035ExecutorError(
                "dm035_provider_unavailable", retryable=True
            ) from exception
        if len(completed.stdout) > 2 * 1024 * 1024 or len(completed.stderr) > 65536:
            raise DM035ExecutorError("dm035_provider_response_too_large")
        if completed.returncode:
            try:
                diagnostic = json.loads(completed.stderr)
                code = diagnostic["code"]
                retryable = diagnostic["retryable"]
            except (json.JSONDecodeError, KeyError, TypeError):
                code = "dm035_provider_failed"
                retryable = False
            if (
                not isinstance(code, str)
                or _TOKEN.fullmatch(code) is None
                or not isinstance(retryable, bool)
            ):
                code = "dm035_provider_failed"
                retryable = False
            raise DM035ExecutorError(code, retryable=retryable)
        try:
            result = json.loads(completed.stdout)
        except json.JSONDecodeError as exception:
            raise DM035ExecutorError("dm035_provider_response_rejected") from exception
        if not isinstance(result, Mapping):
            raise DM035ExecutorError("dm035_provider_response_rejected")
        _canonical(result, "dm035_provider_response_rejected")
        return copy.deepcopy(dict(result))


class DM035PublicationExecutor:
    """One exact fenced outer lane around Matrix's complete DM-035 coordinator."""

    def __init__(
        self,
        host: MatrixHostAdapter,
        *,
        resource_ref: str,
        current_intent: IntentResolver,
        coordinator_resolver: CoordinatorResolver,
        clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    ) -> None:
        self.host = host
        self.resource_ref = _resource(resource_ref)
        self.current_intent = current_intent
        self.coordinator_resolver = coordinator_resolver
        self.clock = clock

    @property
    def route(self) -> EffectObserverRoute:
        return EffectObserverRoute(
            adapter=DM035_EXECUTOR_ADAPTER,
            work_kind=DM035_WORK_KIND,
            resource_namespace=DM035_RESOURCE_NAMESPACE,
            observer=self.observe,
        )

    def _resolve_current(self, item: Mapping[str, Any]) -> dict[str, Any]:
        try:
            raw = self.current_intent(copy.deepcopy(item))
        except Exception as exception:
            raise DM035ExecutorError(
                "dm035_current_intent_unavailable", retryable=True
            ) from exception
        return validate_dm035_intent(raw)

    def _coordinator(
        self, item: Mapping[str, Any], intent: Mapping[str, Any]
    ) -> PublicationCoordinator:
        try:
            coordinator = self.coordinator_resolver(
                copy.deepcopy(item), copy.deepcopy(intent)
            )
        except Exception as exception:
            raise DM035ExecutorError(
                "dm035_coordinator_unavailable", retryable=True
            ) from exception
        if (
            publication_profile_hash(coordinator.profile) != intent["profile_hash"]
            or publication_policy_hash(coordinator.policy) != intent["policy_hash"]
        ):
            raise DM035ExecutorError("dm035_coordinator_contract_changed")
        return coordinator

    def _inputs(
        self, item_value: Mapping[str, Any], claim_value: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        api = _matrix_api()
        try:
            item = api["curator"].validate_curator_item(item_value)
            claim = api["curator"].validate_curator_claim(claim_value)
        except Exception as exception:
            raise DM035ExecutorError("dm035_curator_artifact_rejected") from exception
        if (
            claim["item_id"] != item["item_id"]
            or claim["resource_ref"] != item["resource_ref"]
            or item["work_kind"] != DM035_WORK_KIND
            or item["resource_ref"] != self.resource_ref
            or item["coordination_mode"] != "resource-fence"
            or item["required_authority"] != "daimon"
            or claim["resource_fence"] is None
        ):
            raise DM035ExecutorError("dm035_route_rejected")
        intent = self._resolve_current(item)
        intent_hash = _digest(intent, "invalid_dm035_execution_intent")
        if (
            intent["resource_ref"] != self.resource_ref
            or intent["actor"] != claim["actor_origin"]["principal_id"]
            or item["input_ref"] != f"matrix-publication:{intent['request_event_id']}"
            or item["input_hash"] != intent["preview_hash"]
            or item["effect_intent_hash"] != intent_hash
        ):
            raise DM035ExecutorError("dm035_current_intent_mismatch")
        return item, claim, intent

    def _fence(
        self, claim: Mapping[str, Any], at_ms: int
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        evidence = self.host.fence_evidence(self.resource_ref)
        if evidence is None:
            raise DM035ExecutorError("dm035_production_fence_absent")
        cluster = _matrix_api()["cluster"]
        try:
            verified = cluster.verify_resource_fence_evidence(
                evidence,
                at_ms=at_ms,
                verifier=self.host.verify_fence,
                holder_embodiment_id=self.host.embodiment_id,
                resource_ref=self.resource_ref,
            )
            position = cluster.resource_fence_position(verified)
        except Exception as exception:
            raise DM035ExecutorError(
                "dm035_production_fence_unverifiable"
            ) from exception
        if position != claim["resource_fence"]:
            raise DM035ExecutorError("dm035_production_fence_changed")
        return verified, position

    def _execute_inner(
        self,
        coordinator: PublicationCoordinator,
        intent: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        try:
            result = coordinator.execute(
                claim_id=cast(str, intent["publication_claim_id"])
            )
        except Exception as exception:
            raise DM035ExecutorError(
                "dm035_inner_effect_unverifiable",
                retryable=bool(getattr(exception, "retryable", True)),
            ) from exception
        if not isinstance(result, Mapping):
            raise DM035ExecutorError("dm035_inner_result_rejected")
        return result

    def _postcondition(
        self,
        coordinator: PublicationCoordinator,
        intent: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        publication = _matrix_api()["publication"]
        try:
            event = cast(Mapping[str, Any], result["event"])
            acceptance = publication.validate_publication_acceptance(
                result["acceptance"]
            )
            provider = cast(Mapping[str, Any], acceptance["provider_receipt"])
            target = cast(Mapping[str, Any], acceptance["target"])
            review = cast(Mapping[str, Any], provider["review"])
            reconciled = coordinator.reconcile(cast(str, event["event_id"]))
        except Exception as exception:
            raise DM035ExecutorError(
                "dm035_effect_truth_unverifiable",
                retryable=bool(getattr(exception, "retryable", True)),
            ) from exception
        predecessor = cast(Mapping[str, Any] | None, intent["predecessor"])
        if (
            reconciled
            != {
                "schema": publication.RECONCILIATION_SCHEMA,
                "acceptance_event_id": event["event_id"],
                "status": "verified",
            }
            or acceptance["request_event_id"] != intent["request_event_id"]
            or acceptance["request_event_hash"] != intent["request_event_hash"]
            or acceptance["claim_id"] != intent["publication_claim_id"]
            or acceptance["claim_generation"] != intent["publication_claim_generation"]
            or acceptance["operation"] != intent["operation"]
            or _target_hash(target) != intent["target_hash"]
            or provider["artifact_sha256"] != intent["artifact_sha256"]
            or _digest(provider["source_event_refs"], "dm035_source_rejected")
            != intent["source_set_hash"]
            or provider["source_checkpoint_hash"] != intent["source_checkpoint_hash"]
            or provider["governance"]["consent"] != intent["consent"]
            or review["decision_id"] != intent["review"]["decision_id"]
            or review["decision_hash"] != intent["review"]["decision_hash"]
            or review["reviewer_principal"] != intent["review"]["reviewer_principal"]
            or acceptance["provider_commit"] != publication.COMPAII_STATE_COMMIT
            or acceptance["predecessor_acceptance_event_id"]
            != (None if predecessor is None else predecessor["acceptance_event_id"])
            or provider["predecessor_receipt_id"]
            != (None if predecessor is None else predecessor["provider_receipt_id"])
        ):
            raise DM035ExecutorError("dm035_acceptance_binding_mismatch")
        return {
            "schema": DM035_POSTCONDITION_SCHEMA,
            "target_hash": intent["target_hash"],
            "operation": acceptance["operation"],
            "sequence": acceptance["sequence"],
            "outcome": provider["outcome"],
            "before_target_sha256": intent["before_target_sha256"],
            "after_target_sha256": provider["artifact_sha256"],
            "source_set_hash": intent["source_set_hash"],
            "source_checkpoint_hash": provider["source_checkpoint_hash"],
            "review_decision_hash": review["decision_hash"],
            "acceptance_event_id": event["event_id"],
            "acceptance_event_hash": event["content_hash"],
            "provider_receipt_id": provider["receipt_id"],
            "provider_receipt_hash": provider["receipt_hash"],
            "effects_hash": _digest(provider["effects"], "dm035_effects_rejected"),
        }

    def execute(
        self, item_value: Mapping[str, Any], claim_value: Mapping[str, Any]
    ) -> dict[str, Any]:
        item, claim, intent = self._inputs(item_value, claim_value)
        now = int(self.clock())
        if now >= claim["lease_until_ms"] or now >= intent["review"]["expires_at_ms"]:
            raise DM035ExecutorError("dm035_authority_expired", retryable=True)
        _evidence, fence_position = self._fence(claim, now)
        coordinator = self._coordinator(item, intent)
        result = self._execute_inner(coordinator, intent)
        postcondition = self._postcondition(coordinator, intent, result)
        current = self._resolve_current(item)
        if current != intent:
            raise DM035ExecutorError("dm035_current_intent_changed")
        completed_at = int(self.clock())
        if completed_at >= claim["lease_until_ms"]:
            raise DM035ExecutorError("dm035_claim_expired", retryable=True)
        self._fence(claim, completed_at)
        outer = self._outer_receipt(
            item=item,
            intent=intent,
            result=result,
            postcondition=postcondition,
            resource_fence=fence_position,
        )
        reconciliation = self.host.reconcile_effect(
            outer,
            intent=current,
            observed_postcondition=postcondition,
            at_ms=completed_at,
        )
        if reconciliation["status"] != "verified":
            raise DM035ExecutorError("dm035_outer_effect_unverified")
        return outer

    def _outer_receipt(
        self,
        *,
        item: Mapping[str, Any],
        intent: Mapping[str, Any],
        result: Mapping[str, Any],
        postcondition: Mapping[str, Any],
        resource_fence: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        acceptance = cast(Mapping[str, Any], result["acceptance"])
        effect_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "dm035:"
                + cast(str, item["item_id"])
                + ":"
                + acceptance["acceptance_id"],
            )
        )
        receipt_time = cast(int, acceptance["accepted_at_ms"])
        return self.host.create_effect_receipt(
            effect_id=effect_id,
            target_event_id=intent["request_event_id"],
            decision_event_id=intent["review"]["decision_id"],
            adapter=DM035_EXECUTOR_ADAPTER,
            preview_hash=intent["preview_hash"],
            intent_hash=cast(str, item["effect_intent_hash"]),
            actor=intent["actor"],
            authority="daimon",
            resource_fence=resource_fence,
            result="applied",
            observed_postcondition=postcondition,
            started_at_ms=receipt_time,
            completed_at_ms=receipt_time,
        )

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
            raise DM035ExecutorError("dm035_observation_rejected") from exception
        if (
            item["work_kind"] != DM035_WORK_KIND
            or item["resource_ref"] != self.resource_ref
            or receipt["adapter"] != DM035_EXECUTOR_ADAPTER
        ):
            raise DM035ExecutorError("dm035_route_rejected")
        intent = self._resolve_current(item)
        if receipt["intent_hash"] != _digest(intent, "invalid_dm035_execution_intent"):
            raise DM035ExecutorError("dm035_current_intent_mismatch")
        coordinator = self._coordinator(item, intent)
        result = self._execute_inner(coordinator, intent)
        observed = self._postcondition(coordinator, intent, result)
        if observed != receipt["observed_postcondition"]:
            raise DM035ExecutorError("dm035_postcondition_changed")
        expected = self._outer_receipt(
            item=item,
            intent=intent,
            result=result,
            postcondition=observed,
            resource_fence=receipt["resource_fence"],
        )
        if expected != receipt:
            raise DM035ExecutorError("dm035_historical_receipt_changed")
        evidence = self.host.fence_evidence(self.resource_ref)
        if evidence is None:
            raise DM035ExecutorError("dm035_production_fence_absent")
        return {
            "intent": intent,
            "observed_postcondition": observed,
            "current_fence_evidence": evidence,
        }


__all__ = [
    "DM035ExecutorError",
    "DM035PublicationExecutor",
    "DM035_EXECUTOR_ADAPTER",
    "DM035_INTENT_SCHEMA",
    "DM035_POSTCONDITION_SCHEMA",
    "DM035_RESOURCE_NAMESPACE",
    "DM035_WORK_KIND",
    "PinnedPublisherTransport",
    "create_dm035_intent",
    "dm035_publisher_root",
    "publication_policy_hash",
    "publication_profile_hash",
    "validate_dm035_intent",
]
