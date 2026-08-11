"""Governed provisioning: prepare/confirm pair (issue #12).

Design: ``docs/design/provisioning-flow.md`` §2. ``provision prepare``
creates the container + durable volume, generates the tribe v1 identity
keys INSIDE the container (private material never leaves the volume,
never touches host fs/audit/spec/output), stages an optional curated
seed, writes the instance spec (state ``provisioned-pending-activation``)
and emits a single-use confirmation token (operation
``provision-activate``, TTL 900 s). ``provision confirm`` consumes the
token and flips the spec to ``active-pending-directory`` — the actual
directory activation is governance's act (design §2 step 8), NOT
clusterctl's.

Same contracts as ``clusterctl.lifecycle``: admission, idempotency,
locking, audit. Exit codes: 0 ok, 3 unknown token, 6 conflict
(duplicate name, sponsor==requester, seed checksum mismatch, expired
token), 10 internal (any post-creation failure -> full reversal).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import stat
import uuid
from pathlib import Path

import yaml

from . import audit, idempotency, operation_journal
from .inventory import SPEC_SCHEMA, load_specs
from .lifecycle import (
    EXIT_CONFLICT,
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    _audit_ok,
    _check_idempotency,
    _emit,
    _fail,
    _idem_key,
    _lock_or_fail,
    _record_idempotency,
    _request_id,
    _action_digest,
    _actor,
    _mutation_boundary,
    _observe_runtime,
    _stale_detail,
    _write_spec,
)

DEFAULT_IMAGE = "tribe-base/latest"
KEY_DIR = "/home/agent/.tribe-bridge/v1/keys"
SEED_PROVENANCE_PATH = "/home/agent/.hermes/agent-memory/state/SEED-PROVENANCE"

CONFIRMATION_SCHEMA = "confirmation/v1"
CONFIRM_OPERATION = "provision-activate"
TOKEN_TTL_S = 900
HOST_BROKER = "10.10.20.69:8685"

SEED_SCHEMA = "seed-manifest/v1"

STATE_PENDING = "provisioned-pending-activation"
STATE_FAILED = "creation-failed"
STATE_ACTIVE_PENDING = "active-pending-directory"

# Announcement recorded in the result + audit detail (never broadcast by
# clusterctl itself): provisioning creates a NEW incarnation, unlike
# wake/transfer (#29) which relocate the same embodiment.
ANNOUNCEMENT_CREATION = "incarnation-creation"

# Per-kind default target paths (design §4); kind "file" (or unknown
# kinds) must carry an explicit ``target`` in the manifest item.
KIND_TARGETS = {
    "soul": "/home/agent/.hermes/SOUL.md",
    "hmk": "/home/agent/.hermes/agent-memory/library.db",
}

# Key generation script run INSIDE the container (design §3: umask 077,
# private material written only into the durable volume). Prefers
# python3-cryptography; falls back to ssh-keygen (present in tribe-base).
_KEYGEN_SCRIPT = """set -eu
KEYDIR=/home/agent/.tribe-bridge/v1/keys
umask 077
mkdir -p "$KEYDIR"
if [ ! -f "$KEYDIR/identity" ]; then
  if python3 -c 'import cryptography' 2>/dev/null; then
    python3 -c 'import sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
k = Ed25519PrivateKey.generate()
open(sys.argv[1], "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()))
open(sys.argv[1] + ".pub", "wb").write(k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH) + b" " + sys.argv[2].encode() + b"\\n")' "$KEYDIR/identity" "__COMMENT__"
  else
    ssh-keygen -t ed25519 -N '' -f "$KEYDIR/identity" -C "__COMMENT__" >/dev/null
  fi
fi
"""


class SeedError(Exception):
    """Raised when a seed manifest is invalid or checksums mismatch."""


class ProvisionError(Exception):
    """Raised when an in-container provisioning step fails."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _confirmations_dir(state_dir) -> Path:
    path = Path(state_dir) / "confirmations"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
    ):
        raise ProvisionError("confirmation directory is not owner-controlled")
    path.chmod(0o700)
    return path


def _write_confirmation(path: Path, value: dict) -> None:
    if path.is_symlink():
        raise ProvisionError("confirmation symlink is forbidden")
    temporary = path.with_suffix(".json.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _generate_identity(adapter, name: str) -> tuple[str, str]:
    """Generate keys in-container; return (pubkey_line, sha256 fingerprint).

    Only PUBLIC material crosses the adapter boundary: the private key is
    written by a process inside the container into the durable volume and
    is never read back.
    """
    comment = f"{name}@daimonmatrix"
    adapter.exec(name, ["sh", "-c", _KEYGEN_SCRIPT.replace("__COMMENT__", comment)])
    out = adapter.exec(name, ["cat", f"{KEY_DIR}/identity.pub"])
    line = out.strip().splitlines()[0].strip() if out.strip() else ""
    parts = line.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ProvisionError(f"cannot parse identity.pub from {name!r}: {line!r}")
    try:
        blob = base64.b64decode(parts[1])
    except Exception as exc:
        raise ProvisionError(f"invalid base64 in identity.pub for {name!r}") from exc
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return line, fingerprint


def _load_seed_manifest(path: str) -> dict:
    """Parse a seed-manifest/v1 YAML and verify all file checksums.

    Runs BEFORE any container effect so a bad manifest never leaves
    debris. Returns ``{"curated_by", "target", "staged", "provenance"}``.
    """
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SeedError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema") != SEED_SCHEMA:
        raise SeedError(f"schema must be {SEED_SCHEMA!r}")

    items = raw.get("items") or []
    if not isinstance(items, list):
        raise SeedError("items must be a list")
    staged, provenance = [], []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise SeedError(f"item {i}: must be a mapping")
        kind, source = item.get("kind"), item.get("source")
        if not kind or not source:
            raise SeedError(f"item {i}: kind and source are required")
        entry = {"kind": str(kind), "source": str(source)}
        if item.get("sha256"):
            try:
                content = Path(str(source)).read_bytes()
            except OSError as exc:
                raise SeedError(f"item {i} ({kind}): cannot read {source}: {exc}") from exc
            digest = hashlib.sha256(content).hexdigest()
            if digest.lower() != str(item["sha256"]).lower():
                raise SeedError(
                    f"item {i} ({kind}): sha256 mismatch for {source} "
                    f"(manifest {item['sha256']}, actual {digest})"
                )
            target = KIND_TARGETS.get(str(kind)) or item.get("target")
            if not target:
                raise SeedError(f"item {i} ({kind}): no target path known; add 'target'")
            staged.append({"kind": str(kind), "target": str(target),
                           "content": content, "sha256": digest})
            entry["sha256"] = digest
        elif item.get("ref"):
            # git-sourced items: provenance recorded; network staging is a
            # TODO (v1 stages file items only).
            entry["ref"] = str(item["ref"])
            entry["staged"] = False
        else:
            raise SeedError(f"item {i} ({kind}): needs sha256 or ref")
        provenance.append(entry)
    return {
        "curated_by": raw.get("curated_by"),
        "target": raw.get("target"),
        "staged": staged,
        "provenance": provenance,
    }


def _stage_seed(adapter, name: str, seed: dict) -> None:
    """Stage verified file items into the container and record provenance."""
    for item in seed["staged"]:
        b64 = base64.b64encode(item["content"]).decode()
        target = item["target"]
        script = (
            f"mkdir -p {shlex.quote(os.path.dirname(target))} && "
            f"echo {shlex.quote(b64)} | base64 -d > {shlex.quote(target)}"
        )
        adapter.exec(name, ["sh", "-c", script])
    lines = [
        json.dumps({**p, "curated_by": seed.get("curated_by"),
                    "staged_ms": audit.now_ms()}, sort_keys=True)
        for p in seed["provenance"]
    ]
    b64 = base64.b64encode(("\n".join(lines) + "\n").encode()).decode()
    script = (
        f"mkdir -p {shlex.quote(os.path.dirname(SEED_PROVENANCE_PATH))} && "
        f"echo {shlex.quote(b64)} | base64 -d > {shlex.quote(SEED_PROVENANCE_PATH)}"
    )
    adapter.exec(name, ["sh", "-c", script])


def _reverse_and_fail(args, cfg, adapter, name, spec, stale, exc, created) -> int:
    """Full rollback per design §5: stop+delete container, delete volume,
    spec marked creation-failed, audit error, exit 10."""
    cleanup_errors = []
    if created:
        for fn in (
            lambda: adapter.stop(name, 30),
            lambda: adapter.delete(name),
            lambda: adapter.delete_volume(name),
        ):
            try:
                fn()
            except Exception as cleanup_exc:  # best-effort reversal
                cleanup_errors.append(str(cleanup_exc))
    spec["state"] = STATE_FAILED
    spec["state_reason"] = str(exc)
    _write_spec(cfg.instances_dir, spec)
    detail = {"reversed": created, **stale}
    if cleanup_errors:
        detail["cleanup_errors"] = cleanup_errors
    return _fail(
        args, cfg, "provision-prepare", name,
        f"provision failed ({exc}); container+volume reversed, "
        f"spec marked creation-failed",
        EXIT_INTERNAL, audit_result="error", detail=detail,
    )


# --------------------------------------------------------------------------
# provision prepare
# --------------------------------------------------------------------------

def cmd_provision_prepare(args, cfg, adapter) -> int:
    name, operation = args.name, "provision-prepare"
    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        journal = operation_journal.OperationJournal(cfg.state_dir)
        pending = journal.open_for_target(name)
        seed = None
        seed_digest = None
        if getattr(args, "seed_manifest", None):
            try:
                seed = _load_seed_manifest(args.seed_manifest)
                seed_digest = hashlib.sha256(
                    Path(args.seed_manifest).read_bytes()
                ).hexdigest()
            except (SeedError, OSError) as exc:
                return _fail(
                    args,
                    cfg,
                    operation,
                    name,
                    f"seed manifest rejected: {exc}",
                    EXIT_CONFLICT,
                    detail=stale,
                )
        exact_call = {
            "method": "provision-prepare",
            "name": name,
            "species": args.species,
            "requested_by": args.requested_by,
            "sponsor": args.sponsor,
            "seed_manifest_sha256": seed_digest,
            "image": DEFAULT_IMAGE,
            "profile": cfg.profile,
        }
        if pending is None:
            store = idempotency.load_store(cfg.state_dir)
            rc = _check_idempotency(args, cfg, operation, name, store, adapter)
            if rc is not None:
                return rc
            specs = load_specs(cfg.instances_dir)
            actual_names = {inst["name"] for inst in adapter.list_instances()}
            if name in specs or name in actual_names:
                where = "declared in state_dir" if name in specs else "present in incus"
                return _fail(
                    args,
                    cfg,
                    operation,
                    name,
                    f"instance {name!r} already exists ({where})",
                    EXIT_CONFLICT,
                    detail=stale,
                )
            if args.requested_by == args.sponsor:
                return _fail(
                    args,
                    cfg,
                    operation,
                    name,
                    "sponsor must differ from requester (ADR D8)",
                    EXIT_CONFLICT,
                    detail={
                        "requested_by": args.requested_by,
                        "sponsor": args.sponsor,
                        **stale,
                    },
                )
            image_version = adapter.resolve_image(DEFAULT_IMAGE)
            budgets = adapter.profile_budgets(cfg.profile)
            spec = {
                "schema": SPEC_SCHEMA,
                "name": name,
                "species": args.species,
                "image_version": image_version,
                "budgets": budgets,
                "created_ms": audit.now_ms(),
                "created_by": args.requested_by,
                "governance": {
                    "requested_by": args.requested_by,
                    "sponsor": args.sponsor,
                },
                "idempotency_key": _idem_key(args),
            }
            token = str(uuid.uuid4())
            transition = {
                "spec": spec,
                "confirmation_token": token,
                "confirmation_created_ms": audit.now_ms(),
            }
            expected = {
                "runtime": {"present": False},
                "spec_present": False,
                "volume_present": False,
            }
        else:
            if pending["operation"] != operation:
                return _fail(
                    args,
                    cfg,
                    operation,
                    name,
                    "target has an unresolved operation",
                    EXIT_CONFLICT,
                    detail={"operation_id": pending["operation_id"]},
                )
            if pending["intent"].get("runtime_call") != exact_call:
                return _fail(
                    args,
                    cfg,
                    operation,
                    name,
                    "pending provision has different exact bytes",
                    EXIT_CONFLICT,
                    detail={"operation_id": pending["operation_id"]},
                )
            transition = pending["intended_transition"]
            expected = pending["expected_precondition"]
            spec = transition["spec"]
            token = transition["confirmation_token"]
            image_version = spec["image_version"]
            budgets = spec["budgets"]
        intent = {
            "operation": operation,
            "target": name,
            "runtime_call": exact_call,
            "expected_precondition": expected,
            "intended_transition": transition,
        }
        try:
            record = journal.plan(
                operation=operation,
                target=name,
                idempotency_key=_idem_key(args),
                intent=intent,
                expected_precondition=expected,
                intended_transition=transition,
                audit_identity={
                    "actor": _actor(args),
                    "request_id": _request_id(args),
                    "action_digest": _action_digest(args),
                    "context": stale,
                },
            )
        except operation_journal.JournalConflict as exc:
            return _fail(args, cfg, operation, name, str(exc), EXIT_CONFLICT)
        _mutation_boundary("after-plan", record)
        try:
            if record["state"] == "planned":
                record = journal.advance(
                    record["operation_id"],
                    "runtime-dispatching",
                    runtime_observation={"before_dispatch": _observe_runtime(adapter, name)},
                )
                _mutation_boundary("after-runtime-dispatch-persist", record)
            if record["state"] == "runtime-dispatching":
                observed = _observe_runtime(adapter, name)
                if not observed["present"]:
                    adapter.create_instance(name, image_version, cfg.profile)
                _mutation_boundary("after-provision-create", record)
                observed = _observe_runtime(adapter, name)
                if observed["state"] != "running":
                    adapter.start(name)
                _mutation_boundary("after-provision-start", record)
                adapter.ensure_volume(name)
                _mutation_boundary("after-provision-volume", record)
                pubkey, fingerprint = _generate_identity(adapter, name)
                _mutation_boundary("after-provision-identity", record)
                if seed is not None:
                    _stage_seed(adapter, name, seed)
                _mutation_boundary("after-provision-seed", record)
                observed = _observe_runtime(adapter, name)
                if observed["state"] != "running":
                    raise ProvisionError("provisioned runtime is not running")
                record = journal.advance(
                    record["operation_id"],
                    "runtime-applied",
                    runtime_observation={
                        "runtime": observed,
                        "identity_pubkey": pubkey,
                        "key_fingerprint": fingerprint,
                        "volume": f"{name}-home",
                    },
                )
                _mutation_boundary("after-runtime-observation", record)
            if record["state"] == "runtime-applied":
                pubkey = record["runtime_observation"]["identity_pubkey"]
                fingerprint = record["runtime_observation"]["key_fingerprint"]
                final_spec = {
                    **spec,
                    "state": STATE_PENDING,
                    "identity_pubkey": pubkey,
                    "key_fingerprint": fingerprint,
                }
                _write_spec(cfg.instances_dir, final_spec)
                _mutation_boundary("after-spec", record)
                directory_entry = {
                    "identity": f"{name}@daimonmatrix",
                    "pubkey": pubkey,
                    "fingerprint": fingerprint,
                    "host_broker": HOST_BROKER,
                }
                confirmation = {
                    "schema": CONFIRMATION_SCHEMA,
                    "token": token,
                    "operation": CONFIRM_OPERATION,
                    "target": name,
                    "created_ms": transition["confirmation_created_ms"],
                    "ttl_s": TOKEN_TTL_S,
                    "used": False,
                    "artifacts": {"directory_entry": directory_entry},
                }
                token_path = _confirmations_dir(cfg.state_dir) / f"{token}.json"
                _write_confirmation(token_path, confirmation)
                _mutation_boundary("after-confirmation", record)
                record = journal.advance(
                    record["operation_id"],
                    "logical-committed",
                    logical_observation={
                        "spec_state": STATE_PENDING,
                        "confirmation_token": token,
                        "directory_entry": directory_entry,
                    },
                )
                _mutation_boundary("after-logical-commit", record)
        except Exception as exc:
            cleanup_errors = []
            for action in (
                lambda: adapter.stop(name, 30),
                lambda: adapter.delete(name),
                lambda: adapter.delete_volume(name),
            ):
                try:
                    action()
                except Exception as cleanup_exc:
                    cleanup_errors.append(str(cleanup_exc))
            failed_spec = {**spec, "state": STATE_FAILED, "state_reason": str(exc)}
            _write_spec(cfg.instances_dir, failed_spec)
            try:
                after_cleanup = _observe_runtime(adapter, name)
            except operation_journal.JournalError:
                after_cleanup = {"present": None, "state": None}
            terminal = not after_cleanup.get("present") and not cleanup_errors
            record = journal.advance(
                record["operation_id"],
                "compensated" if terminal else "degraded",
                runtime_observation={"after_cleanup": after_cleanup},
                result={"result": "error", "reversed": terminal},
                last_error=str(exc),
            )
            return _fail(
                args,
                cfg,
                operation,
                name,
                f"provision failed ({exc}); "
                + (
                    "container+volume reversed"
                    if terminal
                    else "cleanup unresolved; follow-on blocked"
                ),
                EXIT_INTERNAL,
                audit_result="error",
                detail={
                    "reversed": terminal,
                    "cleanup_errors": cleanup_errors,
                    "operation_id": record["operation_id"],
                    **stale,
                },
                event_id=record["audit_event_id"],
            )

        pubkey = record["runtime_observation"]["identity_pubkey"]
        fingerprint = record["runtime_observation"]["key_fingerprint"]
        directory_entry = record["logical_observation"]["directory_entry"]

        result = {
            "operation": operation,
            "name": name,
            "result": "ok",
            "species": args.species,
            "image_version": image_version,
            "budgets": budgets,
            "state": STATE_PENDING,
            "token": token,
            "token_ttl_s": TOKEN_TTL_S,
            "directory_entry": directory_entry,
            "seed_staged": len(seed["staged"]) if seed else 0,
            "announcement": ANNOUNCEMENT_CREATION,
            "idempotency_key": _idem_key(args),
            "operation_id": record["operation_id"],
        }
        if record["state"] == "logical-committed":
            store = idempotency.load_store(cfg.state_dir)
            _record_idempotency(args, cfg, operation, name, store, result)
            _mutation_boundary("after-idempotency", record)
            record = journal.advance(
                record["operation_id"], "idempotency-persisted", result=result
            )
        if record["state"] == "idempotency-persisted":
            identity = record["audit_identity"]
            audit.append_event(
                cfg.state_dir,
                actor=identity["actor"],
                action=operation,
                target=name,
                result="ok",
                detail={
                    "image_version": image_version,
                    "key_fingerprint": fingerprint,
                    "requested_by": args.requested_by,
                    "sponsor": args.sponsor,
                    "seed_staged": result["seed_staged"],
                    "announcement": ANNOUNCEMENT_CREATION,
                    "operation_id": record["operation_id"],
                    **identity.get("context", {}),
                },
                idempotency_key=record["idempotency_key"],
                request_id=identity.get("request_id"),
                action_digest=identity.get("action_digest"),
                event_id=record["audit_event_id"],
            )
            _mutation_boundary("after-audit", record)
            record = journal.advance(record["operation_id"], "audited")
        if record["state"] == "audited":
            record = journal.advance(record["operation_id"], "completed", result=result)
            _mutation_boundary("after-completed", record)
        _emit(args, result,
              f"provisioned {name} (state {STATE_PENDING}); confirmation "
              f"token {token} (ttl {TOKEN_TTL_S}s) — HALT until "
              f"`provision confirm --token {token}`")
        return EXIT_OK


# --------------------------------------------------------------------------
# provision confirm
# --------------------------------------------------------------------------

def cmd_provision_confirm(args, cfg, adapter) -> int:
    operation = "provision-confirm"
    token = args.token
    path = _confirmations_dir(cfg.state_dir) / f"{token}.json"
    if not path.is_file():
        return _fail(args, cfg, operation, token,
                     f"unknown confirmation token {token!r}", EXIT_NOT_FOUND)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _fail(args, cfg, operation, token,
                     f"corrupt confirmation token file: {exc}",
                     EXIT_INTERNAL, audit_result="error")

    target = str(data.get("target") or "?")
    artifact = (data.get("artifacts") or {}).get("directory_entry") or {}

    # Retry-safe: an already-used token replays its artifact (the
    # directory CAS downstream makes duplicates impossible).
    if data.get("used"):
        _audit_ok(args, cfg, operation, target,
                  {"idempotent_replay": True, "token": token})
        payload = {"operation": operation, "token": token, "target": target,
                   "result": "ok", "already_confirmed": True,
                   "directory_entry": artifact}
        _emit(args, payload,
              f"already confirmed: {target} (token {token}) — no-op")
        return EXIT_OK

    age_ms = audit.now_ms() - int(data.get("created_ms", 0))
    ttl_s = int(data.get("ttl_s", TOKEN_TTL_S))
    if age_ms > ttl_s * 1000:
        return _fail(args, cfg, operation, target, "confirmation expired",
                     EXIT_CONFLICT,
                     detail={"token": token, "ttl_s": ttl_s, "age_s": age_ms // 1000})

    # Consume the token durably (fsynced tmp + rename + directory fsync).
    data["used"] = True
    _write_confirmation(path, data)

    # Directory activation is governance's act (design §2 step 8):
    # clusterctl only flips the spec and hands the artifact to the
    # governance operator.
    spec_path = cfg.instances_dir / f"{target}.yaml"
    if spec_path.is_file():
        spec = yaml.safe_load(spec_path.read_text(encoding="utf-8")) or {}
        spec["state"] = STATE_ACTIVE_PENDING
        _write_spec(cfg.instances_dir, spec)

    _audit_ok(args, cfg, operation, target,
              {"token": token, "state": STATE_ACTIVE_PENDING})
    payload = {
        "operation": operation,
        "token": token,
        "target": target,
        "result": "ok",
        "state": STATE_ACTIVE_PENDING,
        "directory_entry": artifact,
        "note": "directory activation is governance's act — hand "
                "directory_entry to the governance operator",
    }
    _emit(args, payload,
          f"confirmed {target}: state {STATE_ACTIVE_PENDING}\n"
          f"directory_entry (hand to governance operator):\n"
          f"{json.dumps(artifact, indent=2)}")
    return EXIT_OK
