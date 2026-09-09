"""Owner-local status sidecar transition. No runtime/process lifecycle authority."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
from pathlib import Path

from daimon_matrix import operator_runtime_upgrade as upgrade
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.client import load_json_document


class TransitionError(ValueError):
    """Bounded refusal; retain evidence and keep ALL consumers externally fenced."""


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    value = load_json_document(raw)
    if canonical_bytes(value) != raw:
        raise TransitionError("status_noncanonical_document")
    return value


def _validate_pair(bundle, pair, origin, being, *, legacy=False, check_time=True):
    """Pure public-chain and capability verification; no runtime constructors."""
    import time
    from daimon_matrix import operator_capabilities as profiles
    from daimon_matrix import runtime as api
    from daimon_matrix.local_api import LocalCapability

    now = time.time_ns() // 1_000_000
    try:
        if (bundle["local_origin"] != origin or bundle["manifest"]["being_ref"] != being
                or bundle["binding"] is not None or bundle["binding_activation"] is not None
                or bundle["provisional_history"] is not None):
            raise TransitionError("status_unsupported_authority_history_or_origin")
        chain = api.ControlChain(bundle["control_artifacts"][0])
        for artifact in bundle["control_artifacts"][1:]:
            chain.add(artifact)
        state = chain.state
        if state.head != bundle["control_head"] or state.being_ref != being:
            raise TransitionError("status_control_binding_conflict")
        credentials = api._indexed(bundle["credentials"])
        incarnations = api._indexed(bundle["incarnations"])
        authority = api.RootAuthority(api.BeingManifest.from_value(bundle["manifest"]), state, credentials, incarnations)
        # Match Matrix's compact epoch construction, not its wider rekey/recovery
        # lane. Matrix alone verifies signatures, lineage and allowed deltas.
        history = bundle["authority_history"]
        if not isinstance(history, list) or len(history) > 256:
            raise TransitionError("status_unsupported_authority_history_or_origin")
        historical_reversed = []
        next_authority = authority
        for entry in reversed(history):
            if (not isinstance(entry, dict) or set(entry) != {"manifest", "successor"}
                    or not isinstance(entry["successor"], dict)
                    or entry["successor"].get("schema") != "dm.we.authority-epoch/v1"):
                raise TransitionError("status_unsupported_authority_history_or_origin")
            next_authority = api.RootAuthority(
                api.BeingManifest.from_value(entry["manifest"]), next_authority.state,
                next_authority.credentials, next_authority.incarnations)
            historical_reversed.append(next_authority)
        if history:
            authority = api.RootHistoryAuthority(authority, list(reversed(historical_reversed)),
                [entry["successor"] for entry in history])
        member = authority.validate_origin(origin, require_active=True)
        credential = credentials[member["embodiment_credential_id"]]
        body = api.verify_embodiment_credential(credential, state, at_ms=now)
        api.verify_incarnation_authorization(incarnations[member["incarnation_authorization_id"]], credential, state, at_ms=now)
        if set(pair) != {"client.json", "capability.key"} or len(pair["capability.key"]) != 32:
            raise TransitionError("status_exact_pair_required")
        config = _json(pair["client.json"])
        fields = {"schema", "capability", "expected_server"}
        if not legacy:
            fields |= {"runtime_id", "runtime_label"}
        # Pinned 915c56c ClientConfig: V1 has exactly these three fields.
        # V2 requires historical_servers; external-client history stays out of scope.
        if (set(config) != fields or config["schema"] != ("dm.local.client-config/v1" if legacy else "dm.local.client-config/v3")
                or config["expected_server"] != origin):
            raise TransitionError("status_client_binding_conflict")
        capability = LocalCapability.from_value(config["capability"], pair["capability.key"])
        descriptor = capability.descriptor
        if (frozenset(capability.methods) != profiles.HOST_CAPABILITY_PROFILES["status"]
                or descriptor["status"] != "active"
                or (check_time and not descriptor["not_before_ms"] <= now < descriptor["not_after_ms"])):
            raise TransitionError("status_authority_rejected")
        if not legacy:
            label, rid = bundle["runtime_label"], bundle["runtime_id"]
            if config["runtime_id"] != rid or config["runtime_label"] != label:
                raise TransitionError("status_runtime_binding_conflict")
            profiles.verify_operator_capability_binding(bundle["operator_capability_binding"], runtime_id=rid,
                runtime_label=label, being_ref=being, origin=origin, signing_key=body["signing_key"], capability_rows=bundle["capabilities"])
            rows = [row for row in bundle["capabilities"] if row.get("profile") == profiles.host_capability_profile("status")]
            if (len(rows) != 1 or rows[0] != dict(descriptor=dict(descriptor),
                    profile=profiles.host_capability_profile("status"), runtime_id=rid,
                    secret_slot=profiles.host_capability_slot(label, "status"))):
                raise TransitionError("status_signed_row_mismatch")
        else:
            rows = [row for row in bundle["capabilities"] if row["descriptor"] == descriptor and ":status:" in row["secret_slot"]]
            if len(rows) != 1:
                raise TransitionError("status_legacy_row_mismatch")
        return descriptor
    except TransitionError:
        raise
    except Exception:
        raise TransitionError("status_authority_verification_failed") from None


def stage(**request) -> dict:
    """Owner-request staging; continuous external fencing is a prerequisite."""
    runtime, target, transaction = (request[k] for k in ("runtime", "target", "transaction"))
    _locations(runtime, target, transaction, request["upgrade_transaction"], request["expected_origin"])
    with _status_lock(target.parent), upgrade._locks(runtime):
        return _stage(**request)


def _locations(runtime, target, transaction, upgrade_transaction, origin):
    from .matrix_host import matrix_client_root
    if (target != matrix_client_root(target.parent.parent, origin["embodiment_id"])
            or target.parent.name != "matrix-clients"
            or transaction.parent != target.parent or transaction == target
            or upgrade_transaction.parent != runtime.parent or upgrade_transaction == runtime
            or any(a == b or a in b.parents or b in a.parents
                   for a in (runtime, upgrade_transaction) for b in (target, transaction))):
        raise TransitionError("status_path_binding_conflict")
    for directory in (runtime, target, target.parent, transaction.parent, upgrade_transaction):
        upgrade._path(directory)


@contextmanager
def _status_lock(parent):
    import fcntl
    import os
    upgrade._path(parent)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def _stage(*, runtime: Path, upgrade_transaction: Path, transaction: Path,
          target: Path, expected_target_sha256: str, expected_upgrade_sha256: str,
          expected_origin: dict, expected_being_ref: str,
          externally_quiesced: bool) -> dict:
    """Stage exact status bytes without changing runtime or external client."""
    if not externally_quiesced:
        raise TransitionError("status_external_fencing_required")
    artifacts, forward = _forward_context(runtime, upgrade_transaction, expected_upgrade_sha256, expected_origin, expected_being_ref)
    parent_identity = _parent_identity(target.parent)
    previous = upgrade._snapshot(target)
    if upgrade._inventory(previous) != expected_target_sha256:
        raise TransitionError("status_target_conflict")
    candidate = upgrade._snapshot(runtime / "host-clients/status")
    _validate_pair(_json(upgrade._snapshot(runtime)["runtime.json"]), candidate, expected_origin, expected_being_ref)
    _validate_pair(_json(artifacts["checkpoint/runtime.json"]), previous, expected_origin, expected_being_ref, legacy=True)
    receipt = dict(schema="dm.cluster.status-transition/v1", state="stopped-staged",
                   runtime=str(runtime), upgrade_transaction=str(upgrade_transaction),
                   transaction=str(transaction), target=str(target),
                   expected_upgrade_sha256=expected_upgrade_sha256,
                   expected_origin=expected_origin, expected_being_ref=expected_being_ref,
                   old_sha256=expected_target_sha256,
                   new_sha256=upgrade._inventory(candidate),
                   parent_identity=parent_identity,
                   runtime_sha256=forward["successor_sha256"])
    _forward_context(runtime, upgrade_transaction, expected_upgrade_sha256, expected_origin, expected_being_ref)
    if (_parent_identity(target.parent) != parent_identity
            or upgrade.inventory_digest(target) != expected_target_sha256):
        raise TransitionError("status_target_conflict")
    if transaction.exists():
        saved = upgrade._snapshot(transaction)
        if (saved["ready.json"] != canonical_bytes(receipt)
                or upgrade.inventory_digest(transaction / "checkpoint") != expected_target_sha256
                or upgrade.inventory_digest(transaction / "candidate") != receipt["new_sha256"]):
            raise TransitionError("status_stage_retry_conflict")
        return receipt
    transaction.mkdir(mode=0o700)
    upgrade._sync(transaction.parent)
    upgrade._copy(previous, transaction / "checkpoint")
    upgrade._copy(candidate, transaction / "candidate")
    upgrade._write(transaction / "ready.json", canonical_bytes(receipt))
    return receipt


def _forward_context(runtime, upgrade_transaction, expected_upgrade_sha256, expected_origin, expected_being_ref, *, inventory_root=None):
    artifacts = upgrade._snapshot(upgrade_transaction)
    published_raw = artifacts["published.json"]
    published = _json(published_raw)
    forward = _json(artifacts["ready.json"])
    if (_sha(published_raw) != expected_upgrade_sha256
            or published["ready_sha256"] != _sha(artifacts["ready.json"])
            or published["source"] != str(runtime)
            or forward["source"] != str(runtime)
            or forward["transaction"] != str(upgrade_transaction)
            or forward["origin"] != expected_origin
            or forward["being_ref"] != expected_being_ref
            or published["successor_sha256"] != forward["successor_sha256"]
            or upgrade.inventory_digest(runtime if inventory_root is None else inventory_root) != forward["successor_sha256"]):
        raise TransitionError("status_upgrade_binding_conflict")
    expected_publication = dict(schema="dm.operator.runtime-upgrade-publication/v1", state="published",
        ready_sha256=_sha(artifacts["ready.json"]), source=str(runtime), successor_sha256=forward["successor_sha256"],
        checkpoint=str(upgrade_transaction / "checkpoint"), counter_after=forward["counter_after"])
    if (published != expected_publication
            or forward["schema"] != "dm.operator.runtime-upgrade/v1"
            or forward["legacy_revision"] != upgrade.LEGACY_REVISION
            or forward["legacy_sha256"] != upgrade.LEGACY_SOURCE_SHA256
            or type(forward["counter_before"]) is not int or type(forward["counter_after"]) is not int
            or forward["counter_after"] != forward["counter_before"] + 1
            or upgrade.inventory_digest(upgrade_transaction / "checkpoint") != forward["source_sha256"]
            or upgrade.inventory_digest(upgrade_transaction / "successor") != forward["source_sha256"]):
        raise TransitionError("status_not_exact_runtime_publication")
    return artifacts, forward


def publish(*, transaction: Path, expected_receipt_sha256: str, externally_quiesced: bool) -> dict:
    """Publish under the same owner-local runtime and sidecar writer locks."""
    ready = _json(upgrade._snapshot(transaction)["ready.json"])
    runtime, target = Path(ready["runtime"]), Path(ready["target"])
    _locations(runtime, target, transaction, Path(ready["upgrade_transaction"]), ready["expected_origin"])
    with _status_lock(target.parent), upgrade._locks(runtime):
        return _publish(transaction=transaction, expected_receipt_sha256=expected_receipt_sha256, externally_quiesced=externally_quiesced)


def _publish(*, transaction: Path, expected_receipt_sha256: str, externally_quiesced: bool) -> dict:
    """Atomically exchange the pair; success is stopped, NOT service readiness."""
    if not externally_quiesced:
        raise TransitionError("status_external_fencing_required")
    artifacts = upgrade._snapshot(transaction)
    raw = artifacts["ready.json"]
    if _sha(raw) != expected_receipt_sha256:
        raise TransitionError("status_receipt_conflict")
    ready = _json(raw)
    if ready["transaction"] != str(transaction):
        raise TransitionError("status_transaction_conflict")
    runtime, target = Path(ready["runtime"]), Path(ready["target"])
    _forward_context(runtime, Path(ready["upgrade_transaction"]), ready["expected_upgrade_sha256"], ready["expected_origin"], ready["expected_being_ref"])
    if upgrade.inventory_digest(runtime) != ready["runtime_sha256"]:
        raise TransitionError("status_runtime_conflict")
    candidate = transaction / "candidate"
    old, new = ready["old_sha256"], ready["new_sha256"]
    if upgrade.inventory_digest(transaction / "checkpoint") != old:
        raise TransitionError("status_checkpoint_conflict")
    pair = (upgrade.inventory_digest(target), upgrade.inventory_digest(candidate))
    if pair == (old, new):
        if "published.json" in artifacts:
            raise TransitionError("status_rewind_detected")
        descriptor = _validate_pair(_json(upgrade._snapshot(runtime)["runtime.json"]), upgrade._snapshot(candidate), ready["expected_origin"], ready["expected_being_ref"])
        _forward_context(runtime, Path(ready["upgrade_transaction"]), ready["expected_upgrade_sha256"], ready["expected_origin"], ready["expected_being_ref"])
        if (_parent_identity(target.parent) != ready["parent_identity"]
                or upgrade._snapshot(transaction)["ready.json"] != raw
                or (upgrade.inventory_digest(target), upgrade.inventory_digest(candidate)) != (old, new)):
            raise TransitionError("status_final_cas_conflict")
        _admit(descriptor)
        upgrade._exchange(target, candidate)
    elif pair != (new, old):
        raise TransitionError("status_ambiguous_state_preserved")
    upgrade._sync(target.parent)
    upgrade._sync(transaction)
    if (upgrade.inventory_digest(target), upgrade.inventory_digest(candidate)) != (new, old):
        raise TransitionError("status_ambiguous_state_preserved")
    _validate_pair(_json(upgrade._snapshot(runtime)["runtime.json"]), upgrade._snapshot(target), ready["expected_origin"], ready["expected_being_ref"], check_time=False)
    result = dict(schema="dm.cluster.status-publication/v1", state="stopped-published", ready_sha256=expected_receipt_sha256, runtime_sha256=ready["runtime_sha256"], target=str(target), client_sha256=new)
    encoded = canonical_bytes(result)
    if "published.json" in artifacts:
        if artifacts["published.json"] != encoded:
            raise TransitionError("status_publication_conflict")
    else:
        _record(transaction / "published.json", encoded)
    return result


def rollback(*, transaction: Path, expected_receipt_sha256: str,
             expected_rollback_sha256: str, password: bytes, externally_quiesced: bool) -> dict:
    """Restore only after digest-bound, independently loaded monotonic rollback.

    The legacy loader runs on a private copy, never the actual runtime. No
    runtime exchange, custody rotation, high-water restoration or enrollment.
    """
    if not externally_quiesced or not 1 <= len(password) <= 4096:
        raise TransitionError("status_external_fencing_and_password_required")
    artifacts = upgrade._snapshot(transaction)
    raw = artifacts["ready.json"]
    if _sha(raw) != expected_receipt_sha256:
        raise TransitionError("status_receipt_conflict")
    ready = _json(raw)
    runtime, target = Path(ready["runtime"]), Path(ready["target"])
    up = Path(ready["upgrade_transaction"])
    _locations(runtime, target, transaction, up, ready["expected_origin"])
    with _status_lock(target.parent), upgrade._locks(runtime):
        artifacts = upgrade._snapshot(transaction)
        if artifacts["ready.json"] != raw or ready["transaction"] != str(transaction):
            raise TransitionError("status_receipt_conflict")
        expected_publication = dict(schema="dm.cluster.status-publication/v1", state="stopped-published",
            ready_sha256=expected_receipt_sha256, runtime_sha256=ready["runtime_sha256"], target=str(target), client_sha256=ready["new_sha256"])
        if artifacts["published.json"] != canonical_bytes(expected_publication):
            raise TransitionError("status_forward_publication_required")
        reverse = _reverse_context(ready, expected_rollback_sha256)
        checkpoint = transaction / "checkpoint"
        old, new = ready["old_sha256"], ready["new_sha256"]
        if upgrade.inventory_digest(checkpoint) != old:
            raise TransitionError("status_checkpoint_conflict")
        intent = canonical_bytes(dict(schema="dm.cluster.status-rollback-intent/v1", ready_sha256=expected_receipt_sha256,
            rollback_publication_sha256=expected_rollback_sha256, runtime_sha256=reverse["successor_sha256"]))
        if "rollback-intent.json" in artifacts and artifacts["rollback-intent.json"] != intent:
            raise TransitionError("status_reverse_intent_conflict")
        # The original candidate is the old external directory after forward exchange.
        candidate = transaction / "candidate"
        pair = (upgrade.inventory_digest(target), upgrade.inventory_digest(candidate))
        if pair not in ((new, old), (old, new)):
            raise TransitionError("status_reverse_ambiguous_state_preserved")
        bundle = _json(upgrade._snapshot(runtime)["runtime.json"])
        descriptor = _validate_pair(bundle, upgrade._snapshot(checkpoint), ready["expected_origin"], ready["expected_being_ref"], legacy=True, check_time=(pair == (new, old)))
        validation = transaction / "rollback-validation"
        if not validation.exists():
            upgrade._copy(upgrade._snapshot(runtime), validation)
        if upgrade.inventory_digest(validation) != reverse["successor_sha256"]:
            raise TransitionError("status_reverse_validation_copy_conflict")
        # Canonical pinned legacy validator authenticates actual encrypted custody
        # and counter/high-water on the copy, including all legacy store contracts.
        upgrade._validate(validation, up / "legacy-code", password)
        if upgrade.inventory_digest(validation) != reverse["successor_sha256"]:
            raise TransitionError("status_reverse_validation_mutated_copy")
        if "rollback-intent.json" not in artifacts:
            _record(transaction / "rollback-intent.json", intent)
        _reverse_context(ready, expected_rollback_sha256)
        if (_parent_identity(target.parent) != ready["parent_identity"]
                or upgrade._snapshot(transaction)["ready.json"] != raw
                or upgrade.inventory_digest(checkpoint) != old
                or (upgrade.inventory_digest(target), upgrade.inventory_digest(candidate)) != pair):
            raise TransitionError("status_reverse_final_cas_conflict")
        if pair == (new, old):
            if "rolled-back.json" in artifacts:
                raise TransitionError("status_reverse_rewind_detected")
            _admit(descriptor)
            upgrade._exchange(target, candidate)
        elif "rollback-intent.json" not in artifacts:
            raise TransitionError("status_reverse_exchange_without_intent")
        upgrade._sync(target.parent)
        upgrade._sync(transaction)
        _reverse_context(ready, expected_rollback_sha256)
        if (upgrade.inventory_digest(target), upgrade.inventory_digest(candidate)) != (old, new):
            raise TransitionError("status_reverse_ambiguous_state_preserved")
        result = dict(schema="dm.cluster.status-rollback/v1", state="stopped-rolled-back",
            ready_sha256=expected_receipt_sha256, rollback_publication_sha256=expected_rollback_sha256,
            runtime_sha256=reverse["successor_sha256"], target=str(target), client_sha256=old)
        encoded = canonical_bytes(result)
        if "rolled-back.json" in artifacts:
            if artifacts["rolled-back.json"] != encoded:
                raise TransitionError("status_reverse_result_conflict")
        else:
            _record(transaction / "rolled-back.json", encoded)
        return result


def _reverse_context(ready, rollback_pin):
    runtime, up = Path(ready["runtime"]), Path(ready["upgrade_transaction"])
    artifacts, forward = _forward_context(runtime, up, ready["expected_upgrade_sha256"],
        ready["expected_origin"], ready["expected_being_ref"], inventory_root=up / "rollback")
    reverse_raw = artifacts["rollback-ready.json"]
    reverse = _json(reverse_raw)
    upgrade._check_reverse(reverse, forward, _sha(artifacts["ready.json"]), runtime, up)
    expected = dict(schema="dm.operator.runtime-rollback-publication/v1", state="rolled-back",
        ready_sha256=_sha(reverse_raw), source=str(runtime), successor_sha256=reverse["successor_sha256"], counter_after=reverse["counter_after"])
    snapshot = upgrade._snapshot(runtime)
    expected_bundle = _json(artifacts["checkpoint/runtime.json"])
    expected_bundle["keystore"]["counter"] = reverse["counter_after"]
    if (_sha(artifacts["rolled-back.json"]) != rollback_pin
            or artifacts["rolled-back.json"] != canonical_bytes(expected)
            or upgrade._inventory(snapshot) != reverse["successor_sha256"]
            or _json(snapshot["runtime.json"]) != expected_bundle
            or load_json_document(snapshot["custody.json"])["counter"] != reverse["counter_after"]
            or upgrade._inventory(upgrade._snapshot(up / "legacy-code", private=False)) != upgrade.LEGACY_SOURCE_SHA256):
        raise TransitionError("status_not_exact_monotonic_runtime_rollback")
    return reverse


def _admit(descriptor):
    import time
    now = time.time_ns() // 1_000_000
    if descriptor["status"] != "active" or not descriptor["not_before_ms"] <= now < descriptor["not_after_ms"]:
        raise TransitionError("status_authority_expired_at_exchange")


def _parent_identity(path):
    upgrade._path(path)
    info = path.stat()
    return [info.st_dev, info.st_ino]


def _record(path, raw):
    """Publish a complete receipt; retain interrupted private temporaries."""
    import os
    temporary = path.with_name("." + path.name + "-" + os.urandom(16).hex())
    upgrade._write(temporary, raw)
    os.rename(temporary, path)
    upgrade._sync(path.parent)


def main(argv=None) -> int:
    """Owner-only CLI. Request/receipt digests are review pins, not self-approval."""
    import argparse
    import os
    import sys
    from .matrix_host import _owner_file_bytes
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    staging = commands.add_parser("stage")
    staging.add_argument("--request", type=Path, required=True)
    staging.add_argument("--request-sha256", required=True)
    publication = commands.add_parser("publish")
    reverse = commands.add_parser("rollback")
    for command in (publication, reverse):
        command.add_argument("--transaction", type=Path, required=True)
        command.add_argument("--ready-sha256", required=True)
    reverse.add_argument("--rollback-publication-sha256", required=True)
    reverse.add_argument("--password-fd", type=int, required=True)
    for command in (staging, publication, reverse):
        command.add_argument("--externally-quiesced", action="store_true", required=True)
    args = parser.parse_args(argv)
    password = bytearray()
    try:
        if args.command == "stage":
            upgrade._path(args.request.parent)
            raw = _owner_file_bytes(args.request, "status_request_rejected", maximum_size=1024*1024)
            if _sha(raw) != args.request_sha256:
                raise TransitionError("status_request_digest_conflict")
            request = _json(raw)
            paths = {"runtime", "upgrade_transaction", "transaction", "target"}
            if set(request) != paths | {"expected_target_sha256", "expected_upgrade_sha256", "expected_origin", "expected_being_ref"}:
                raise TransitionError("status_request_schema_rejected")
            for field in paths:
                request[field] = Path(request[field])
            result = stage(**request, externally_quiesced=args.externally_quiesced)
        else:
            request = dict(transaction=args.transaction, expected_receipt_sha256=args.ready_sha256,
                           externally_quiesced=args.externally_quiesced)
            if args.command == "rollback":
                with os.fdopen(os.dup(args.password_fd), "rb") as stream:
                    password.extend(stream.read(4097))
                result = rollback(**request, expected_rollback_sha256=args.rollback_publication_sha256, password=bytes(password))
            else:
                result = publish(**request)
        print(canonical_bytes(result).decode())
        return 0
    except Exception:
        print("status_transition_rejected; keep ALL consumers externally fenced; retain evidence", file=sys.stderr)
        return 1
    finally:
        password[:] = b"\x00" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())
