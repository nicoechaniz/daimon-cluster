# clusterctl CLI reference (v0.1.0)

`clusterctl` is the sole business-logic entry point for daimon-cluster
fleet state (issue #10). v0.1.0 is **read-only**: no command writes to
the state dir or mutates incus.

Config: `configs/clusterctl.yaml` (schema `clusterctl-config/v1`):
`host_id`, `incus_project`, `managed_prefix`, `profile`, `state_dir`
(default `/var/lib/daimon-cluster`). Global flags: `--config <path>`,
`--state-dir <path>` (override; used by tests).

Declared state: `<state_dir>/instances/<name>.yaml` (schema
`instance-spec/v1`: `name`, `species`, `image_version`,
`budgets {cpu, memory_mib, disk_gib}`, `created_ms`, `created_by`).
Actual state: incus instances using the configured profile.

Classification: `running` · `stopped` · `missing` (declared, absent in
incus) · `undeclared` (in incus, not declared) · `drifted` (declared
budgets or image differ from actual incus config).

## Commands

### `clusterctl list [--json]`

Plain aligned table (default) or a JSON array of `instance-status/v2`
records.

```
NAME    SPECIES  STATE       IMAGE_VERSION  CPU  MEM_MIB  DISK_GIB  UPTIME_S
iso-a   unknown  undeclared  debian-trixie-amd64-default-20260731_05:24  1  1536  8  3600
```

### `clusterctl status <name> [--json]`

Single instance status. Exit 3 when the name is neither declared nor
present in incus. When drifted, the record includes a `drift` array of
`{field, declared, actual}` entries.

### `clusterctl config-show [--json]`

Resolved configuration (YAML by default, JSON with `--json`).

## JSON schema: `instance-status/v2`

Example (`clusterctl status iso-a --json`):

```json
{
  "schema": "instance-status/v2",
  "name": "iso-a",
  "species": "unknown",
  "host": "daimonmatrix",
  "state": "undeclared",
  "resource_fence_state": "unknown",
  "image_version": "debian-trixie-amd64-default-20260731_05:24",
  "budgets": {
    "cpu": 1,
    "memory_mib": 1536,
    "disk_gib": 8
  },
  "durable_bytes": null,
  "hmk_integrity": "unknown",
  "uptime_s": 3600,
  "last_audit_event": null,
  "observed_at_ms": 1786412400000,
  "observations": {
    "declared": {"state": "absent", "observed_at_ms": 1786412400000, "created_by": null},
    "runtime": {"state": "running", "present": true, "observed_at_ms": 1786412400000},
    "embodiment": {"state": "unavailable", "observed_at_ms": 1786412400000, "reason": "registry-not-observed-by-inventory"},
    "incarnation": {"state": "unavailable", "observed_at_ms": 1786412400000, "reason": "registry-not-observed-by-inventory"},
    "matrix_process": {"state": "unavailable", "observed_at_ms": 1786412400000, "reason": "matrix-process-not-observed-by-inventory"}
  }
}
```

The aggregate `state` remains the CLI reconciliation classification. It is
not evidence of embodiment identity, incarnation continuity, Matrix process
availability, fence ownership, or peer convergence. Those are distinct
observations and may honestly disagree.

Notes for v0.1.0: `resource_fence_state` and `hmk_integrity` are pinned to
`"unknown"`; `durable_bytes` and `last_audit_event` are `null` until the
audit log (issue #19) lands. Consumers must ignore unknown fields.

Drifted example (fragment):

```json
{
  "state": "drifted",
  "drift": [
    {"field": "cpu", "declared": 2, "actual": 1},
    {"field": "image_version", "declared": "daimon-base-2026-08-01.1", "actual": "debian-trixie-amd64-default-20260731_05:24"}
  ]
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | usage error (argparse) |
| 3 | not found (`status` of an unknown name) |
| 6 | conflict (reserved; unused at v0.1.0) |
| 10 | internal error (config/spec/incus failure, bug) |

## Snapshot (issue #14; design: `docs/design/quiesced-snapshots.md` §2)

```
clusterctl snapshot create <name> [--timeout-s 30] \
    --idempotency-key <uuid> [--json]
```

Captures a **quiesced** local snapshot of a declared daimon. Order is
fail-closed at every step:

1. admission (declared instance, per-instance lock, idempotency key)
2. quiesce park — `pkill -STOP -f hermes` inside the container
3. quiesce verify — `wal_checkpoint(TRUNCATE)` + `integrity_check` on
   every `library.db` under `/home/agent/.hermes/agent-memory`
4. capture — `incus snapshot create <name> snap-<created_ms>`
5. unpark — ALWAYS, before any manifest write
6. snapshot verify — snap present in `incus snapshot list`
7. manifest written to
   `<state_dir>/backups/<name>/<created_ms>-<snap>.json`
   (`cluster-backup-manifest/v1`: `name`, `snap_name`, `created_ms`,
   `image_version`, `quiesce {parked, sqlite_ok, checkpoint_files}`,
   `verified_readable: true`, `retention_class: "local-quiesced"`,
   `rpo_class: "pre-mutation"`)
8. retention — prune `snap-*` snapshots beyond the newest 3 verified;
   the newest verified is never deleted; non-`snap-*` snapshots are
   never touched

Any failure in steps 2–6 exits 10 with an audit `error` event, attempts
unpark, and writes **no** manifest (design §3: never mark an unverified
capture usable; failed-verification snapshots are deleted aggressively).
Undeclared name exits 3; idempotency-key conflict / held lock exits 6.
Audit detail carries the snap name, a quiesce summary, and the manifest
path — never file contents.

## Invocation

`scripts/clusterctl` is a thin wrapper that execs the repo venv
(`repo/.venv/bin/python -m clusterctl.cli "$@"`). Runtime deps: Python
3.13 stdlib + PyYAML only.

## Mutation recovery (issue #65)

Create, power and handoff mutations persist an exact
operation intent before their first substrate call. `clusterctl reconcile
--json` reports `counts.open_operations` plus pending/degraded findings.
Clusterd health reports an `operation_journal` object and degrades while a
record needs attention.

```console
clusterctl repair --operation-id operation:<uuid> --json
```

Repair accepts only a journaled start, stop or restart with a bounded,
observable runtime state. It never clears arbitrary create, handoff or future
destroy ambiguity. The full state and rollback contract is
`docs/design/operation-journal.md`.
