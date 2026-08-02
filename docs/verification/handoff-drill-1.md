# Verification: handoff live drill 1 (issue #30)

**Date:** 2026-08-01 · **Operator:** compaii@daimonmatrix (actor `compaii-drill`)
**Environment:** daimonmatrix production host, real IncusAdapter, real
clusterd state (`/var/lib/daimon-cluster`), scratch containers
`handoff-probe` / `handoff-probe-2` (tribe-base/2026-08-01.1).

This drill is the live counterpart of `handoff-failure-matrix.md`: it
exercised park → transfer → wake against REAL incus and caught two
sequencing bugs the FakeAdapter-based unit tests could not see (fakes
do not enforce the "exec requires a running container" constraint).

## What ran (audit trail, 71 events, chain verified intact)

```
create handoff-probe      → ok
start handoff-probe       → ok
park handoff-probe        → ok        (manifest-0.json, fence epoch 0,
                                       resource_fence_acquired_ms bound)
transfer handoff-probe    → error     (BUG 1 — see below; rollback ran)
transfer handoff-probe-2  → ok        (resumed; fence epoch 1; sha256
                                       restore verified)
park handoff-probe-2      → ok        (fence epoch 0)
wake handoff-probe-2      → error ×2  (BUG 2 — same class in wake)
wake handoff-probe-2      → ok        (resumed; fence epoch 1)
```

## Bug 1 — transfer: restore into a STOPPED container

Original step order: create (stopped) → restore-files (exec) → fence →
start. Live incus refuses `exec` into a stopped container
("Instance is not running"), so every real transfer failed at
restore-files. **The rollback engaged exactly as designed**: target
destroyed, target spec deleted, source stayed parked, transfer-state
recorded `failed_step: restore-files` with the resume hint (evidence:
`transfer/handoff-probe-to-handoff-probe-2.json`,
`rollback.target_destroyed: true`, `fence_restored: false` — the fence
had not been taken).

**Fix:** fence → start → restore-files. The acceptance invariant
("target never reachable before state verification and new lease
acquisition") is preserved: reachability begins at `start`, which now
runs after both. The spec only becomes `active` after the restore
succeeds.

## Bug 2 — wake: same class

WAKE_STEPS had restore-files before start as well. Fixed identically:
fence → start → restore-files; on restore failure after start, the
wake failure handler best-effort stops the container so the convergent
state is "both parked" (resumable).

## Resume-after-real-failure evidence

Both retries RESUMED from the interrupted state files (not restarted
from zero): the transfer re-created the rolled-back target and
completed; the wake skipped the completed verify step and completed.
Fence epochs incremented exactly once each (0 → 1).

## Final live state

- `handoff-probe`: STOPPED, spec status `transferred` (kept for audit)
- `handoff-probe-2`: RUNNING, spec status `active`, state files
  byte-identical inside (`# NOW — handoff probe drilling issue 30`)
- lease `handoff-probe-2@daimonmatrix`: epoch 1
- transfer record: `transfer/handoff-probe-to-handoff-probe-2-1.json`
  (signed, `announcement: embodiment-relocation`, `volume: moved`)
- audit chain: `verify_chain ok`, 71 events

## Known v1 limits (recorded, not hidden)

- Signatures in this drill use FakeSigner (the production wiring
  default); SSHSigner is covered by unit tests (test_leases.py).
- The durable volume is not yet attached to the target on create
  (TODO(#29) in transfer.py) — `volume: moved` records the intent.
- `state_commit` is null here (no state_repo in the drill spec).

Suite after both fixes: **248 passed**.
