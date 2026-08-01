# Runbook: tribe-base image update with rolling refresh

Purpose: ship a new tribe-base image version to all daimons WITHOUT losing
identity, keys, or state, and prove rollback works. This is the runbook
the goal's definition-of-done drills ("update runbook proven by one
rolling refresh drill").

## Preconditions

- New image built: `scripts/build-tribe-base.sh` (bump pins in
  configs/tribe-base-pins.env first; the build emits versioned alias
  `tribe-base/YYYY-MM-DD.N` + moves `tribe-base/latest`).
- Reproducibility check passed (two builds, identical dpkg/pip manifests).
- Every daimon has a fresh quiesced snapshot + manifest (issue #14) —
  the update refuses otherwise (fail-closed, same rule as destroy).

## Per-daimon rolling refresh (one at a time, verify between each)

1. `clusterctl snapshot create <name> --idempotency-key <uuid>`
   → fresh verified recovery point (mandatory, see precondition).
2. Record the daimon's current image: `clusterctl status <name> --json`
   (image_version — this is the rollback target).
3. `clusterctl stop <name>` (graceful; the daimon's bridge presence goes
   asleep — queue, not loss).
4. Update the spec's image_version to the new alias (spec is the declared
   state; reconciliation will show drifted until step 6).
5. Recreate the container on the SAME durable volume:
   `incus delete <name>` (volumes are separate — they survive) →
   `incus launch tribe-base/latest <name> -p tribe-agent` →
   reattach `<name>-home` at /home/agent.
   (M4+: `clusterctl update` wraps steps 3-6; this runbook is the manual
   v1 path it automates.)
6. `clusterctl start <name>`; verify: container boots, durable volume
   mounted (`/home/agent` has the keys), hermes binary runs
   (`/opt/tribe/venv-hermes/bin/hermes --version`), bridge contact on
   first wake.
7. `clusterctl status <name>` → state running, drift cleared, new
   image_version. Only then move to the next daimon.

## Rollback (any verification fails)

1. `clusterctl stop <name>`; delete container; relaunch from the OLD
   versioned alias recorded in step 2 (aliases are immutable — the old
   version still exists); reattach volume; start.
2. If the volume itself is suspect: `incus snapshot restore` from the
   step-1 snapshot (it was quiesced — integrity-checked).
3. Audit the rollback; announce to public-agents; halt the rolling
   refresh (do NOT continue to the next daimon).

## The drill (definition of done)

Run steps 1-7 on ONE throwaway daimon with a real new image build (even a
no-op pin bump), then deliberately fail verification (e.g. detach the
volume) and execute the rollback path. Evidence: audit log entries +
before/after status JSON + the announcement. Repeat per update; the
runbook is proven when rollback has been executed FOR REAL at least once.
