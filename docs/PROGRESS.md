# PROGRESS — daimon-cluster implementation

Living tracking file. Updated after every work session by whoever holds the
/goal (currently: compaii@daimonmatrix). Read FIRST on session start, then
resume from the first open item.

## Current snapshot (2026-08-01, end of M1 core)

Local main tip: 32bc4fa — contains ALL of M0 + M1 core (#6,#7,#8,#9-minus-restart).
origin/main: behind (legion push coordination in flight, requests #1-#3 sent).
Test containers alive: iso-a (10.105.93.211), iso-b (10.105.93.193) — kept as
subjects for the pending host restart drill, then reusable for M2 dry runs.
Host changes applied: incus 6.0.4 (dir pool, incusbr0 v4-only NAT), zram
~5.7GiB (zramswap enabled), nftables table `inet daimon-fw` (enabled, boot
order before incus), profile tribe-agent (allowlist devices, no tun,
1 vCPU/1.5GiB/8GiB/pids 512, port_isolation), image tribe-base/2026-08-01.1
(fp 578b190d) + tribe-base/latest.

| Issue | Status | Evidence |
|-------|--------|----------|
| #1 ADR | done (RATIFIED via Nicolás's delegated conservative call) | docs/adr/ADR-001-v1-architecture.md |
| #2 inventory | done | docs/inventory/daimonmatrix-2026-07-31.md (6cb0157) |
| #3 threat model | done | docs/security/threat-model-v1.md (9b084a5) |
| #4 contracts | done | docs/contracts/v1-state-contracts.md (37c2f0c) |
| #5 gate docs | done | PLAN v0.2 + DESIGN resolutions (ea50501) |
| #6 foundation | done | docs/runbooks/m1-incus-foundation.md (45f02d3); pending: off-mesh ingress probe |
| #7 tribe-base image | done | scripts/build-tribe-base.sh + configs/tribe-base-manifest-2026-08-01.1.json (def64fa); reproducibility + secret scan + boot smoke verified |
| #8 profile+volumes | done | docs/design/tribe-agent-profile-and-volumes.md (6682e61 + allowlist fix in def64fa) |
| #9 acceptance tests | done minus restart drill | docs/verification/m1-acceptance-tests.md (32bc4fa); drill staged, awaits Nicolás's restart window |
| #10 #11 #12 #13 #14 (M2 provisioning) | next | — |
| #15 #16 (M3 backups) | pending | — |
| #17-#33 (M4-M8) | pending | — |

## Next action

1. Push coordination: legion fetches local main (tip 32bc4fa) and pushes;
   paste issue-comment texts (sent in bridge DMs).
2. Ask Nicolás for a host restart window to run the staged drill (closes #9
   fully). Note: agent-side restart command is hardline-blocked — the drill
   needs a human terminal anyway.
3. M2: #10 seed/provision flow design → #11 clusterctl provisioning commands
   → #12 first daimon container (dry-run identity) → #13 update runbook →
   #14 acceptance.

## Key decisions this stretch

- ADR-001 ratified by delegation ("conservative decisions that work for
  now"): zram host-level ~4GiB (landed 5.7GiB), per-daimon swap dropped.
- Device allowlist, not deny (raw deny silently replaces the default
  allowlist and breaks /dev/null — learned live).
- Sibling isolation via incus security.port_isolation (nft forward can't
  see L2 bridge traffic) — F4.
- dir+ext4: no hard disk quota → monitoring+alerts in clusterd (#17);
  recorded deviation.
- limits.processes=512 added to tribe-agent (fork containment verified).
- Idle footprint measured: 93MiB RSS / 1.63GiB rootfs per container →
  cohort of 4 confirmed comfortable, upward revision possible post-pilot.

## Open questions

- Restart drill window (Nicolás).
- Off-mesh probe of public ingress (belt & braces; ruleset is logically
  sound, on-host test invalid due to loopback routing).
- GitHub identity for compaii@daimonmatrix (App vs machine user) — Nicolás.
