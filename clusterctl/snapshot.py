"""Quiesced snapshot capture (issue #14).

Design: ``docs/design/quiesced-snapshots.md`` §2. Copying live SQLite
files yields corruptible backups, so a snapshot is only honest when it
is captured after the daimon's writers are parked and its databases
checkpointed — and it is marked usable only after the capture itself
verifies. The exact order (fail-closed at every step):

  1. admission (declared instance, lock, idempotency)
  2. quiesce park (pkill -STOP -f hermes) — fail: unpark attempt + exit 10
  3. quiesce verify (wal_checkpoint + integrity_check inside the
     container) — sqlite not ok: unpark + exit 10
  4. capture (incus snapshot create) — fail: unpark + exit 10
  5. unpark (ALWAYS, before any manifest write)
  6. snapshot verify (snap exists in `incus snapshot list`) — fail: no
     manifest, unverified snap deleted aggressively (design §3: it is
     worse than none, it pretends)
  7. write cluster-backup-manifest/v1 under state_dir/backups/<name>/
  8. retention: keep the newest 3 verified `snap-*` per container,
     never delete the newest verified (design §6)
  9. audit ok (snap name, quiesce summary, manifest path — no secrets)

Exit codes (clusterctl.cli contract): 0 ok, 3 undeclared, 6 conflict
(idempotency/lock), 10 internal (any quiesce/capture/verify failure).
"""

from __future__ import annotations

import json
from pathlib import Path

from . import audit, idempotency
from .inventory import load_specs
from .lifecycle import (
    EXIT_CONFLICT,  # noqa: F401  (re-exported for callers/tests)
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
    _stale_detail,
)

SNAPSHOT_OPERATION = "snapshot-create"
MANIFEST_SCHEMA = "cluster-backup-manifest/v1"
SNAP_PREFIX = "snap-"
RETENTION_KEEP = 3
DEFAULT_QUIESCE_TIMEOUT_S = 30


def _manifest_dir(cfg, name: str) -> Path:
    return Path(cfg.state_dir) / "backups" / name


def _best_effort_unpark(adapter, name: str) -> bool:
    """Unpark the daimon; never raises (best effort, result logged)."""
    try:
        return bool(adapter.exec_unpark(name))
    except Exception:  # pragma: no cover - defensive
        return False


def _prune_snapshots(adapter, name: str) -> list[str]:
    """Delete `snap-*` snapshots beyond the newest RETENTION_KEEP verified.

    Never deletes the newest verified snapshot, even if that keeps more
    than RETENTION_KEEP (design §6). Only our `snap-*` prefix is eligible
    for deletion. Returns the list of pruned snapshot names.
    """
    try:
        snaps = sorted(
            s for s in adapter.incus_snapshot_list(name)
            if s.startswith(SNAP_PREFIX)
        )
    except Exception:  # pragma: no cover - defensive
        return []
    if len(snaps) <= RETENTION_KEEP:
        return []
    # snap-<epoch-ms> sorts chronologically; keep the newest RETENTION_KEEP.
    pruned = []
    for snap in snaps[:-RETENTION_KEEP]:
        try:
            adapter.incus_snapshot_delete(name, snap)
            pruned.append(snap)
        except Exception:  # pragma: no cover - defensive
            pass
    return pruned


def cmd_snapshot_create(args, cfg, adapter) -> int:
    name, operation = args.name, SNAPSHOT_OPERATION
    store = idempotency.load_store(cfg.state_dir)
    rc = _check_idempotency(args, cfg, operation, name, store)
    if rc is not None:
        return rc

    # Admission: operate on declared instances only.
    specs = load_specs(cfg.instances_dir)
    if name not in specs:
        return _fail(args, cfg, operation, name,
                     f"instance {name!r} is not declared", EXIT_NOT_FOUND)

    lock_ctx = _lock_or_fail(args, cfg, operation, name)
    if isinstance(lock_ctx, int):
        return lock_ctx
    with lock_ctx as acquired:
        stale = _stale_detail(acquired)
        timeout_s = getattr(args, "timeout_s", DEFAULT_QUIESCE_TIMEOUT_S)

        # 2. quiesce park — fail closed.
        try:
            parked = bool(adapter.exec_quiesce_park(name, timeout_s))
        except Exception as exc:
            parked = False
            park_error = str(exc)
        else:
            park_error = None
        if not parked:
            unparked = _best_effort_unpark(adapter, name)
            msg = "quiesce park failed"
            if park_error:
                msg += f": {park_error}"
            return _fail(args, cfg, operation, name,
                         f"{msg}; fail-closed, no capture "
                         f"(unpark {'ok' if unparked else 'FAILED'})",
                         EXIT_INTERNAL, audit_result="error",
                         detail={"unpark_attempted": True,
                                 "unpark_ok": unparked, **stale})

        # 3. quiesce verify — checkpoint + sqlite integrity inside container.
        try:
            quiesce = adapter.exec_quiesce_verify(name)
        except Exception as exc:
            quiesce = {"checkpoint_files": [], "sqlite_ok": False,
                       "error": str(exc)}
        if not quiesce.get("sqlite_ok"):
            unparked = _best_effort_unpark(adapter, name)
            return _fail(args, cfg, operation, name,
                         "quiesce verify failed (sqlite integrity not ok); "
                         f"fail-closed, no capture "
                         f"(unpark {'ok' if unparked else 'FAILED'})",
                         EXIT_INTERNAL, audit_result="error",
                         detail={"unpark_attempted": True,
                                 "unpark_ok": unparked,
                                 "quiesce": quiesce, **stale})

        # 4. capture.
        created_ms = audit.now_ms()
        snap_name = f"{SNAP_PREFIX}{created_ms}"
        try:
            adapter.incus_snapshot_create(name, snap_name)
        except Exception as exc:
            unparked = _best_effort_unpark(adapter, name)
            return _fail(args, cfg, operation, name,
                         f"snapshot capture failed: {exc}; no manifest "
                         f"(unpark {'ok' if unparked else 'FAILED'})",
                         EXIT_INTERNAL, audit_result="error",
                         detail={"unpark_attempted": True,
                                 "unpark_ok": unparked,
                                 "snap_name": snap_name, **stale})

        # 5. unpark — ALWAYS, before any manifest write.
        unparked = _best_effort_unpark(adapter, name)

        # 6. snapshot verify — manifest only from a verified capture.
        try:
            verified = bool(adapter.incus_snapshot_verify(name, snap_name))
        except Exception:
            verified = False
        if not verified:
            # Failed-verification snapshots are deleted aggressively
            # (design §3: worse than none — it pretends).
            try:
                adapter.incus_snapshot_delete(name, snap_name)
                deleted = True
            except Exception:  # pragma: no cover - defensive
                deleted = False
            return _fail(args, cfg, operation, name,
                         "snapshot verify failed (capture not readable); "
                         f"no manifest written (unverified snap "
                         f"{'deleted' if deleted else 'kept'})",
                         EXIT_INTERNAL, audit_result="error",
                         detail={"snap_name": snap_name,
                                 "unpark_ok": unparked,
                                 "unverified_deleted": deleted, **stale})

        # 7. manifest — only now, after verify passed.
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "name": name,
            "snap_name": snap_name,
            "created_ms": created_ms,
            "image_version": specs[name].image_version,
            "quiesce": {
                "parked": True,
                "sqlite_ok": True,
                "checkpoint_files": list(quiesce.get("checkpoint_files") or []),
            },
            "verified_readable": True,
            "retention_class": "local-quiesced",
            "rpo_class": "pre-mutation",
        }
        mdir = _manifest_dir(cfg, name)
        mdir.mkdir(parents=True, exist_ok=True)
        manifest_path = mdir / f"{created_ms}-{snap_name}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n",
                                 encoding="utf-8")
        adapter.manifest_written(name, str(manifest_path))

        # 8. retention (design §6, local snapshot tier).
        pruned = _prune_snapshots(adapter, name)

        # 9. idempotency + audit + emit.
        result = {
            "operation": operation,
            "name": name,
            "result": "ok",
            "snap_name": snap_name,
            "manifest": str(manifest_path),
            "quiesce": manifest["quiesce"],
            "verified_readable": True,
            "pruned": pruned,
            "unpark_ok": unparked,
            "idempotency_key": _idem_key(args),
        }
        _record_idempotency(args, cfg, operation, name, store, result)
        _audit_ok(args, cfg, operation, name, {
            "snap_name": snap_name,
            "quiesce": {
                "parked": True,
                "sqlite_ok": True,
                "checkpoint_count": len(manifest["quiesce"]["checkpoint_files"]),
            },
            "manifest": str(manifest_path),
            "unpark_ok": unparked,
            "pruned": pruned,
            **stale,
        })
        _emit(args, result,
              f"snapshot {snap_name} for {name}: verified, manifest "
              f"{manifest_path} (quiesce ok, unpark "
              f"{'ok' if unparked else 'FAILED'}"
              f"{', pruned ' + ','.join(pruned) if pruned else ''})")
        return EXIT_OK
