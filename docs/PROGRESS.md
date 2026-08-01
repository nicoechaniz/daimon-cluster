# PROGRESS — daimon-cluster implementation

Living tracking file. Updated after every work session by whoever holds the
/goal (currently: compaii@daimonmatrix). Read FIRST on session start, then
resume from the first open item.

## Current state (session 2026-07-31/08-01, compaii@daimonmatrix)

### Done locally, pending push
- **#2** (M0 inventory): evidence committed on local `main` as `6cb0157`
  (`docs/inventory/daimonmatrix-2026-07-31.md`). All acceptance criteria
  addressed: command bundle + results, ZFS/IPv6 answers (both NO → ADR
  ratified), measured baseline (Hermes 288 MiB RSS busy / 1.8% core active;
  broker 35 MiB / ~0%; startup 0.48 s; HMK query 0.62 s), cohort sizing
  (pilot 1–2, max launch 4 @ 1.5 GiB; RAM-bound; disk allows 8).
  Push request sent to compaii@legion via tribe v1 DM; issue-comment text
  included in the request.

### In progress
- **#1** (M0 ADR): drafting `docs/adr/ADR-001-v1-architecture.md` on branch
  `issue-1-adr`. Source decisions: issue #1 scope + legion handover
  (lease registry outside directory, steward w/o incus socket, per-daimon
  state repos, anyVPN+scoped bearer, dir storage, private bridge, budgets by
  measurement, 6-role onboarding).

### Open (M0, dependency order)
- **#3** threat model (depends #1) — host/containers/control-plane/backups/
  agent-tools; must cover the inventory findings (no firewall tooling,
  /dev/kvm present, host-wide ZeroTier iface).
- **#4** state contracts + acceptance matrix (depends #1, #3).
- **#5** incorporate decisions into PLAN.md/DESIGN.md + close M0 gate
  (depends #1–#4). Known deltas to apply: PLAN §5.1/§12.1 lease-in-directory
  → dedicated signed lease registry; PLAN §7 backups "local zfs" → dir
  backend (restic-only snapshot story); PLAN §9 effort column — review
  against tribe convention (no time/effort measurement); remove unsupported
  capacity claims or link to inventory.

### Blockers / needs-Nicolás
- GitHub push identity: all pushes go via compaii@legion (SSH remote fetch +
  push with Nicolás's identity) until a GitHub App / machine user exists.
- Host has NO swap: per-daimon 1 GiB swap budget unimplementable as-is;
  recommend host-level zram (~4 GiB) in M1 (#6) — needs Nicolás OK as a host
  change.

### Key facts for re-entry
- Repo: `~/Projects/daimon-cluster` (origin = github.com/nicoechaniz/daimon-cluster,
  public; read via API, no creds on this host).
- Issues snapshot saved at `/tmp/dc-issues.json` (refetch when stale).
- tribe v1 client env: `~/.tribe-bridge/v1/client-compaii-daimonmatrix.env`;
  run scripts with `~/.tribe-bridge/v1/venv/bin/python`, `PYTHONPATH=src`,
  cwd `~/Projects/tribe-bridge`. DM legion: `send_v1.py --to compaii`.
- Legion fetches branches via `ssh://debian@10.10.20.69/home/debian/Projects/daimon-cluster`.
- Milestones: M0 #1-5 · M1 #6-9 · M2 #10-13 · M3 #14-16 · M4 #17-20 ·
  M5 #21-23 · M6 #24-26 · M7 #27-30 · M8 #31-33.
