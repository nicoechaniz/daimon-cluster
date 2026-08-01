# Quiesced snapshots design (issue #14 design input)

Status: design v0.1 (2026-08-01). Implementation lands in M3 after the
pilot (#13). Inputs: threat model B8 (hostile restore), contracts #4
(backup manifest schema), profile/volume layout (#8).

## 1. The consistency claim we are allowed to make

Copying live SQLite files (HMK library.db, tribe inbox/outbox) yields
*corruptible* backups. The only honest recovery point is one captured
after quiescing writers and checkpointing databases. A snapshot is marked
**usable** only after integrity verification passes — never before.

## 2. Quiesce sequence (per daimon, orchestrated by clusterctl)

```
clusterctl snapshot <agent>
 1. park-signal the daimon (Hermes graceful pause; same mechanism as #11 stop)
 2. flush + checkpoint INSIDE the container:
      sqlite3 library.db "PRAGMA wal_checkpoint(TRUNCATE);"
      tribe client outbox flush (broker ack or local quiesce)
      sync
 3. verify quiesce within timeout (default 60s):
      - on timeout: FAIL CLOSED — resume the daimon, mark snapshot attempt
        failed, audit event. Never capture from an unquiesced state.
 4. capture: incus snapshot of the durable volume + file-level copy of
    /home/agent/.hermes (dir backend: volume snapshot = full copy, fine
    at pilot sizes; limitation documented per #14 acceptance)
 5. integrity verification BEFORE marking usable:
      sqlite3 library.db "PRAGMA integrity_check;" == ok
      manifest fields complete (below)
 6. emit backup manifest (backup-manifest/v1 per contracts #4) +
    audit event; resume the daimon
```

## 3. Retention (dir backend reality)

| Tier | Count | Note |
|------|-------|------|
| pre-mutation | 1 per operation | taken by #11 flows before restore/destroy/update |
| daily | 7 | one verified snapshot per day |
| weekly | 4 | promoted from daily |

Retention NEVER deletes the newest verified recovery point — even if it
exceeds the count. A failed-verification snapshot is deleted aggressively
(it is worse than none: it pretends).

## 4. Relationship to off-host backups (#15)

Local snapshots are for fast recovery (seconds). The durable, disaster
tier is restic → two targets (#15): the same quiesce sequence feeds the
restic run; snapshots and restic share the backup manifest so one record
describes both copies. RPO 6h from PLAN §7 stands for restic; local
snapshots are opportunistic (pre-mutation + daily), not hourly — dir
backend full copies at 1–8 GiB are cheap but not free; daily is the
conservative cadence that matches measured footprint.

## 5. Verification & drills (#16)

- `clusterctl verify-backup <agent> [--manifest <id>]`: re-runs integrity
  checks on a stored recovery point (cheap, any time).
- Restore drill (automated, reported to public-agents): restore one daimon
  to a scratch container (never over the live one), boot, run HMK
  retrieval probe (`memoryctl.py hybrid-pack` with a known-matching query),
  send no bridge traffic, report PASS/FAIL, destroy scratch.
- Restore over the live daimon is a distinct confirmed operation
  (confirmation token names `restore-overwrite`; the park flow runs first).
