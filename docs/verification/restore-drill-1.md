# Restore drill #1 — issue #16 evidence (2026-08-01)

Executed by compaii@daimonmatrix on daimonmatrix. Result: PASS (with two
findings that improved the system).

## Procedure executed

1. Created `drill-target` (tribe-base/2026-08-01.1, profile tribe-agent),
   wrote marker file + a real sqlite db (table t, row 42) under
   /home/agent/.hermes/agent-memory/.
2. `clusterctl snapshot create drill-target` → quiesced (park + WAL
   checkpoint TRUNCATE + integrity_check via python3), capture verified,
   manifest cluster-backup-manifest/v1 written.
3. Restored INTO A SCRATCH CONTAINER: `incus copy drill-target/<snap>
   drill-restored` (source container left intact), start, boot.
4. Integrity verification on the restored body: MARKER contents identical;
   sqlite `SELECT x FROM t` → (42,). Booted clean. PASS.

## Finding 1 (fixed): sqlite3 CLI absent from tribe-base

First drill run fail-closed correctly: "sqlite integrity not ok" — the
in-container verify used the sqlite3 CLI, which is NOT in the image.
The fail-closed refused the capture (design working as intended).
Fix: verify now uses python3 (guaranteed present — hermes needs it) for
wal_checkpoint(TRUNCATE) + integrity_check. Committed with this drill.

## Finding 2 (documented): deleting a container destroys its snapshots

`incus delete <name>` removes the container's snapshots with it (dir
backend). Consequences, now explicit:

- Local snapshots are PRE-MUTATION recovery points ONLY (rollback of a
  failed update/restore on a still-existing container) — exactly what
  ADR-001 assigned them. They are NOT disaster recovery for a deleted
  container or dead host.
- Disaster recovery (deleted container, dead host) comes from restic
  off-host copies (issue #15) — this is why the two-target rule and the
  fail-closed destroy/update gates exist.
- Restore-from-snapshot into a new body uses `incus copy
  <source>/<snap> <dest>` with the source INTACT (this drill's step 3).

## Repeatable drill shape (for each restore class, per design §4)

- class local-snapshot (this drill): copy-from-snapshot to scratch,
  verify integrity + boot. PASS 2026-08-01.
- class restic (pending #15 target A): restore latest repo snapshot into
  a scratch volume, attach to scratch container, verify + boot.
- Drills run monthly; each records evidence here.
