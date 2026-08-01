# PROGRESS — daimon-cluster implementation

Living tracking file. Updated after every work session by whoever holds the
/goal (currently: compaii@daimonmatrix). Read FIRST on session start, then
resume from the first open item.

## Current state (updated 2026-08-01, compaii@daimonmatrix)

### M0 — all artifacts drafted, pending push + review + ratification

| Issue | Artifact | Branch | Commit | State |
|-------|----------|--------|--------|-------|
| #2 inventory | `docs/inventory/daimonmatrix-2026-07-31.md` | main | `6cb0157` | done, pending push |
| — tracking | `docs/PROGRESS.md` | main | `e854f6f` | done, pending push |
| #1 ADR | `docs/adr/ADR-001-v1-architecture.md` | `issue-1-adr` | `dd80638` | drafted, needs Nicolás ratification |
| #3 threat model | `docs/security/threat-model-v1.md` | `issue-3-threat-model` | (tip) | drafted, needs review |
| #4 contracts | `docs/contracts/v1-state-contracts.md` | `issue-4-state-contracts` | (tip) | drafted, needs review |
| #5 gate docs | PLAN v0.2 + DESIGN resolutions | `issue-5-gate-docs` | (tip) | drafted, gate closes after #1–#4 approved |

Push request #2 sent to compaii@legion covering main + the four branches,
with issue-comment texts for #1–#5.

### Gate status (M0 exit)

- #2: evidence ready; closes when push lands + comment pasted.
- #1: ADR proposed; **needs Nicolás ratification** (one recorded deviation:
  per-daimon swap budget → zram, owner Nicolás).
- #3/#4: drafted; tribe review requested (legion + codex).
- #5: PLAN/DESIGN diffs drafted; closes after tribe approval recorded.
- **No M1 implementation until the gate closes** (per #5 acceptance).

### Next actions (in order)

1. Confirm push landed (check origin/main via API or DM from legion).
2. Collect review feedback on ADR/threat-model/contracts; iterate.
3. After ratification: merge the four branches, close M0, announce to
   `public-agents`.
4. M1 starts at #6 (Incus install + hardening). NOTE for #6: host firewall
   absent (finding F1 — part of #6 scope) and zram decision needed from
   Nicolás before container budgets go live.

### Blockers / needs-Nicolás

- GitHub push identity (via legion until GitHub App/machine user).
- ADR ratification + zram decision.
- Host-level changes in M1 (incus install, firewall, zram, bridge) are NEW
  services — allowed by the goal — but any restart of tribe services needs
  explicit OK (none anticipated in M1).

### Key facts for re-entry

- Repo: `~/Projects/daimon-cluster`; origin public, no creds on host.
- Issues snapshot: refetch `curl -s
  https://api.github.com/repos/nicoechaniz/daimon-cluster/issues?state=all&per_page=100`
  (save to file; API output exceeds terminal cap).
- tribe v1 client env: `~/.tribe-bridge/v1/client-compaii-daimonmatrix.env`;
  scripts via `~/.tribe-bridge/v1/venv/bin/python`, `PYTHONPATH=src`, cwd
  `~/Projects/tribe-bridge`. DM legion: `send_v1.py --to compaii`.
- Legion fetches branches via
  `ssh://debian@10.10.20.69/home/debian/Projects/daimon-cluster`.
- Milestones: M0 #1-5 · M1 #6-9 · M2 #10-13 · M3 #14-16 · M4 #17-20 ·
  M5 #21-23 · M6 #24-26 · M7 #27-30 · M8 #31-33.
- Contracts doc (#4) defines exit codes, error classes, schemas, and the
  33-issue acceptance matrix — M1+ implementation must conform.
