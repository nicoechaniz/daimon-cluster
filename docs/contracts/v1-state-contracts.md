# daimon-cluster v1 state contracts and acceptance matrix

Status: ACTIVE, ontology rectified 2026-08-02. Evidence for issue #4 and R1-R7.
Author: compaii@daimonmatrix; rectification integrated by Codex. The
embodiment and resource-fence sections supersede ADR-001 D1 lease semantics.

One shared vocabulary for clusterctl, clusterd, the dashboard, the steward,
backup jobs, and handoff. **The CLI is the API** (PLAN principle 4): these
contracts bind clusterctl output first; clusterd mirrors them 1:1.

## 0. Common rules

- Every schema carries `"schema": "<name>/<version>"` (e.g.
  `cluster-instance/v1`). Consumers must ignore unknown fields
  (forward-compatible reads); producers never remove fields within a major
  version — only add, or bump the version.
- All mutation commands accept `--idempotency-key <uuid>`; a retried call
  with the same key returns the original result without re-executing
  (byte-identical retry semantics, as in tribe-bridge v1 broker).
- All machine output is JSON to stdout (`--json` default for clusterctl when
  not a TTY); human rendering is a presentation layer only.
- Every record that authorizes effects carries `actor`: either
  `human:<name>` or `agent:<tribe-v1-identity>`.
- Timestamps: epoch milliseconds UTC, field suffix `_ms`.

### Exit codes (all commands)

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | usage / validation error |
| 3 | precondition failed (state conflict, illegal transition) |
| 4 | authentication / authorization failure |
| 5 | not found |
| 6 | infrastructure error (incus, storage, network) |
| 7 | confirmation required / expired / replayed |
| 8 | internal error (bug; includes crash id for audit correlation) |

### Error classes (machine `error.class` values)

`validation` · `unauthorized` · `forbidden_scope` · `not_found` ·
`state_conflict` · `illegal_transition` · `confirmation_required` ·
`confirmation_expired` · `confirmation_replayed` · `idempotency_conflict` ·
`generation_conflict` (resource-fence CAS) · `stale_fencing_token` ·
`storage_corruption` · `storage_error` · `infra_unavailable` · `internal`

## 1. Schemas

### 1.1 `cluster-instance/v1` — spec

```json
{
  "schema": "cluster-instance/v1",
  "name": "eko",
  "body_ref": "cluster:daimonmatrix:eko",
  "embodiment_id": "embodiment:<uuid>",
  "current_incarnation_id": "incarnation:<uuid>|null",
  "human": "sai",
  "image": "tribe-base",
  "image_version": "2026-08-01.1",
  "profile": "tribe-agent",
  "limits": {"cpu": 1, "memory_mib": 1536, "disk_gib": 8},
  "exceptions": [{"kind": "tun", "reason": "own anyVPN identity", "approved_by": "human:nicolas"}],
  "seed": {"soul_source": "state-repo", "hmk_source": "empty|snapshot:<id>|curated"},
  "created_ms": 0, "actor": "agent:steward@daimonmatrix"
}
```

### 1.2 `cluster-instance-status/v1`

```json
{
  "schema": "cluster-instance-status/v1",
  "name": "eko",
  "state": "running|stopped|parked|transitioning|error",
  "body_ref": "cluster:daimonmatrix:eko",
  "embodiment_id": "embodiment:<uuid>",
  "incarnation_id": "incarnation:<uuid>|null",
  "uptime_s": 0, "rss_mib": 0, "cpu_pct": 0.0,
  "last_backup": {"id": "restic:abc123", "age_s": 0, "verified": true},
  "health": {"http": "ok|degraded|down", "detail": "..."}
}
```

Instance states and legal transitions:

```
            create                start                 stop
  (none) ───────▶ stopped ─────────────▶ running ─────────────▶ stopped
                    │                     │  ▲                    ▲
                    │      park           │  │ wake              │
                    └────── parked ◀──────┘  └── parked ─────────┘
                    │      (checkpoint manifest required)
                    ▼
                 destroyed  (terminal; always preceded by archived backup)

error ◀── any state (infra failure); error ──▶ stopped (manual recovery only)
```

Illegal transitions (rejected with `illegal_transition`): start from parked
(must wake), park from stopped, destroy without archived backup, and any
transition while an operation for the same concrete body/resource is in
flight. Another embodiment of the same being being awake is never an illegal
transition.

### 1.3 `cluster-confirmation/v1` — two-step mutation contract

Every mutation is prepare/confirm:

```json
{
  "schema": "cluster-confirmation/v1",
  "token": "cfm_<uuid>",
  "operation": "destroy|restore|park|wake|create|stop",
  "target": "eko",
  "plan_diff": "human-readable summary + machine diff of effects",
  "actor": "human:sai",
  "issued_ms": 0, "expires_ms": 0,
  "single_use": true
}
```

- Expiry: default 300 s, single-use; reuse → `confirmation_replayed` (exit 7).
- Confirm call must present the exact token; the plan_diff is re-displayed
  at confirm time (steward UX: the human sees the same text they approved).
- Read operations never require confirmation.

### 1.4 `cluster-audit-event/v1`

```json
{
  "schema": "cluster-audit-event/v1",
  "seq": 1024,
  "actor": "human:nicolas",
  "operation": "restore",
  "target": "oliva",
  "idempotency_key": "<uuid>",
  "confirmation_token": "cfm_<uuid>",
  "result": "success|denied|failed",
  "error_class": null,
  "prev_sha256": "...", "sha256": "...",
  "ts_ms": 0
}
```

Append-only JSONL, hash-chained (`sha256` over canonical record +
`prev_sha256`), mirrored to git. Verification walks the chain (issue #19).

### 1.5 `cluster-backup-manifest/v1`

```json
{
  "schema": "cluster-backup-manifest/v1",
  "id": "restic:<snapshot-id>",
  "target_instance": "eko",
  "kind": "scheduled|pre-mutation|manual",
  "paths": ["/var/lib/incus/..."],
  "restic_repo": "ovh|legion",
  "size_bytes": 0, "ts_ms": 0,
  "verified": false, "verify_ms": null,
  "integrity": "ok|failed|unchecked"
}
```

### 1.6 `cluster-checkpoint-manifest/v1` — park

```json
{
  "schema": "cluster-checkpoint-manifest/v1",
  "body_ref": "cluster:daimonmatrix:eko",
  "embodiment_id": "embodiment:<uuid>",
  "incarnation_id": "incarnation:<uuid>",
  "hmk_snapshot": {"path": "...", "sha256": "...", "integrity_check": "ok"},
  "state_repo_head": "<git sha>",
  "handoff_files": ["DIALOGUE-HANDOFF.md", "NOW.md"],
  "bridge_outbox_drained": true,
  "in_flight_work": "none|abandoned-by:<actor>",
  "resource_fences": [{"resource_ref": "volume:eko-state", "epoch": 41}],
  "ts_ms": 0
}
```

Park refuses without a verified checkpoint (HMK `PRAGMA integrity_check`
must be `ok`, outbox drained) unless `in_flight_work` records explicit
human abandonment.

### 1.7 `embodiment-registry/v1`

```json
{
  "schema": "embodiment-registry/v1",
  "embodiments": {
    "embodiment:<uuid>": {
      "embodiment_id": "embodiment:<uuid>",
      "body_ref": "cluster:daimonmatrix:eko",
      "status": "running|stopped|retired",
      "current_incarnation_id": "incarnation:<uuid>|null",
      "incarnations": [{"incarnation_id": "incarnation:<uuid>", "started_at_ms": 0, "stopped_at_ms": null}]
    }
  }
}
```

A body has one stable embodiment id. Each start/restart opens a fresh
incarnation segment. Many embodiments in one being may be running.

### 1.8 `resource-fence/v1`

```json
{
  "schema": "resource-fence/v1",
  "resource_ref": "volume:eko-state",
  "holder_embodiment_id": "embodiment:<uuid>",
  "holder_pubkey": "...",
  "fingerprint": "SHA256:...",
  "epoch": 41,
  "acquired_ms": 0,
  "created_ms": 0,
  "ttl_s": 300,
  "renewer": "self|steward",
  "signature": "..."
}
```

CAS is scoped to the exact `resource_ref`. A stale writer for that resource is
rejected; unrelated resources and embodiments never conflict by identity.

V1 is now the synthetic/offline fixture contract. Production uses the
additive but deliberately distinct `resource-fence/v2`: it binds `body_ref`,
`holder_incarnation_id`, `holder_key_id`, `state`, `operation`,
`signing_key_id` and `authorization_ref`. Its current record, monotonic
high-water/proof, append-only event and release/migration tombstone commit in
one SQLite transaction. Every mutation requires a holder-signed exact expected
epoch/proof; expiry is observed without deleting history. See
`docs/design/production-resource-fences.md`.

### 1.9 `dm.we.status/v1`

The read model reports `being_ref`, installed manifest hash, local origin,
per-incarnation heads, and durable peer cursors. It contains no private key or
provider-store contents. `/we.sync` event bytes are defined by Daimon Matrix.

### 1.10 `cluster-operation-journal/v1`

The owner-only SQLite journal closes substrate mutation intent before effect
dispatch. Each row binds an operation id, optional idempotency key, exact
`cluster-operation-intent/v1` bytes, expected precondition, intended logical
transition, stable audit event id, runtime/logical observations and result.

States are `planned`, `runtime-dispatching`, `runtime-applied`,
`logical-committed`, `idempotency-persisted`, `audited`, `completed`,
`compensated` and `degraded`. `completed` and `compensated` are terminal.
One open row per target is permitted; a degraded row blocks new mutation until
an operation-specific repair policy authorizes a bounded resume. See
`docs/design/operation-journal.md`.

### 1.11 `cluster-volume-observation/v1`

```json
{
  "schema": "cluster-volume-observation/v1",
  "present": true,
  "pool": "default",
  "project": "default",
  "name": "eko-home",
  "identity": "volume:<sha256>",
  "type": "custom",
  "content_type": "filesystem",
  "created_at": "2026-08-10T00:00:00Z",
  "attachments": [{
    "instance": "eko-next",
    "device": "home",
    "path": "/home/agent",
    "writable": true
  }]
}
```

For Incus 6.0 custom volumes, `identity` closes pool, project, name, type,
content type and immutable creation timestamp. It is an operational identity,
not a content hash or a claim about being identity. A relocation journal also
closes source/target, mount/device, manifest hash and the current fence
`{resource_ref, epoch, proof, current}` coordinate. The target is created
stopped without a home device; detach and attach are observe-first and
idempotent. At every writable stage the attachment list must contain exactly
one allowlisted `home` mount, or the workflow fails closed.

## 2. Acceptance matrix (issue → evidence required to close)

| Issue | Evidence artifact |
|-------|-------------------|
| #1 ADR | `docs/adr/ADR-001-v1-architecture.md` ratified by Nicolás |
| #2 Inventory | `docs/inventory/daimonmatrix-2026-07-31.md` (committed) |
| #3 Threat model | `docs/security/threat-model-v1.md` + invariants review |
| #4 Contracts | this document + schemas validated in #10 tests |
| #5 Gate | PLAN/DESIGN diff with tribe approval recorded |
| #6 Foundation | incus health output, bridge + firewall config, reboot survival log |
| #7 tribe-base | image build script + hash-pinned manifest, rebuild reproducibility log |
| #8 Profile/volumes | profile YAML + volume layout doc + mount audit |
| #9 Isolation tests | test log: no socket/kvm/tun/sibling access, resource caps enforced |
| #10 clusterctl base | unit tests for schemas/exit codes/idempotency (`--json` golden files) |
| #11 Lifecycle | lifecycle drill log: create→start→stop→restart→logs on scratch |
| #12 Identity provision | directory epoch record, keys-mode audit (0600, in-container), seed manifest |
| #13 Pilot | pilot runbook executed end-to-end + update/rollback log + `cluster-instance-status` evidence |
| #14 Snapshots | quiesce script + retention config + restore-from-snapshot log |
| #15 restic | two-target backup logs (ovh + legion), encryption verification |
| #16 Restore drills | automated drill output incl. tampered-archive fail-closed test, RPO/RTO numbers |
| #17 clusterd | OpenAPI diff vs clusterctl (1:1), contract tests |
| #18 Auth | 401/403/replay test log, token rotation drill |
| #19 Audit | hash-chain verification tool output incl. tamper detection test |
| #20 clusterd deploy | systemd unit + reboot test + hardening checklist |
| #21 steward identity | directory record for steward@daimonmatrix, scoped-cred grant audit |
| #22 steward reads | tool tests: list/health/logs/backups from Hermes session transcript |
| #23 steward mutations | adversarial approval test log (injection attempts fail closed) |
| #24 dashboard | authenticated fleet/health/activity views, screenshots + session log |
| #25 dashboard actions | lifecycle + backup/restore via UI with confirmation UX log |
| #26 operator drill | usability + failure-state drill notes, issues filed and fixed |
| #27 resource fences | CAS/TTL per-resource tests incl. same-resource stale-writer rejection and different-resource concurrency |
| #41 Weave ledger | independent DB/key, preview/pull, durable cursor, interrupted resume and idempotent resync tests |
| #42 projections/fan-out | preview, human authority, receipts, origin and dedupe tests |
| #43 live convergence | Legion↔daimonmatrix partition, independent appends, bidirectional merge and restart evidence |
| #28 park | checkpoint manifest from real park, integrity gate evidence |
| #29 wake | transfer/wake/re-entry/rollback drill log, rehydration transcript |
| #30 handoff tests | failure-injection matrix: crash mid-flip, never two awake, queue-not-deliver |
| #31 ceremony | onboarding/offboarding/identity-recovery doc, 6 roles mapped to steps |
| #32 cohort | first-cohort onboarding log per ceremony, per-member verification |
| #33 handbook | ops handbook + launch drill report + go/no-go record |

## 3. Forward compatibility

- New fields may appear in any record at any time; consumers must not fail.
- New `error.class` values may be added; consumers must treat unknown
  classes as `internal`.
- New instance states require a minor-version bump of
  `cluster-instance-status/v1` and must extend, never reorder, the
  transition table.
- The confirmation contract (single-use, expiring, re-displayed plan) MUST
  NOT be weakened in any later version.
