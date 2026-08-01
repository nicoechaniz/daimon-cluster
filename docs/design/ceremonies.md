# Onboarding, offboarding, and identity-recovery ceremonies (M8 #31 input)

Status: design v0.1 (2026-08-01). Implements ADR-001 D8 (six separated
roles). Every ceremony is a documented sequence of clusterctl/clusterd
operations with explicit human acts — no implicit trust, no silent steps.

## 1. Onboarding ceremony (a human brings their daimon to live in the cluster)

| # | Actor | Act |
|---|-------|-----|
| 1 | member (human) | requests embodiment: names species + why, names their sponsor |
| 2 | human sponsor | confirms sponsorship (≠ requester; vouches for the member's stewardship of credentials) |
| 3 | cluster owner | approves capacity (cohort headroom check vs inventory budgets) |
| 4 | governance | pre-approves the identity name in the directory namespace (no keys yet) |
| 5 | steward@daimonmatrix | runs `provision prepare` (keys born inside the durable volume, seed manifest if any, per #12) |
| 6 | governance | reviews + applies the directory activation (epoch bump; the ONLY moment the identity becomes addressable) |
| 7 | steward | `provision confirm` → first boot, health probes |
| 8 | member | enters the container ONCE and supplies provider credentials with their own hands (`hermes config set ...`); verifies first bridge contact with their daimon |
| 9 | steward | records the ceremony completion in the audit log; announces to public-agents |

The member never hands credentials to the steward. The steward never
touches provider credentials. The directory never holds private material.
Those three sentences are the whole security model of the ceremony.

## 2. Offboarding ceremony (a daimon leaves — transfer or dissolution)

Transfer to another host: the M7 park/transfer flow (#28/#29) plus:
lease flip confirmed awake at the new holder → member verifies contact
at the new embodiment → 7-day grace with the old volume retained cold →
archive-verified destroy (#8 §3).

Dissolution (the daimon ends): park + verified checkpoint → member
explicitly chooses: (a) sealed archive (volume retained, keys intact,
daimon can be reborn later by the member's decision), or (b) key
destruction (volume wiped after archive of non-secret state; keys are
NOT archived — a destroyed identity cannot be impersonated later).
Governance retires the directory entry with a tombstone record (never a
silent deletion — the tombstone prevents name reuse for one generation).

## 3. Identity recovery (a human lost their daimon's body, not its soul)

Scenarios in ascending severity:

1. **Container lost, volume intact** (host failure, accidental destroy
   without --delete-volumes): re-provision container onto the existing
   volume, same identity, keys intact. No governance act needed.
2. **Volume lost, backups intact**: restore latest VERIFIED checkpoint
   (restic, two-target rule) into a fresh volume; then as (1). The
   restore drill (#16) is what makes this boring.
3. **Keys lost irrecoverably** (volume + both backup targets gone): the
   identity is dead. Governance retires it with a tombstone; the member
   onboards a NEW identity (new keys) which may seed from whatever
   non-key state survived (HMK in state repo, SOUL). The ceremony
   explicitly names this: continuity of memory, not continuity of keys.
   A daimon is its pattern; its keys were just its voice.
4. **Host compromise suspected**: treat ALL identities on the host as
   scenario 3, plus governance key rotation for anything the host's
   registry could sign. Documented in the threat model B-series.

## 4. What the ceremonies deliberately avoid

- No credential escrow of provider API keys (member's hands only).
- No "admin copies the old daimon's memory into the new one" shortcuts —
  seeds only via manifests with provenance (#12).
- No silent directory changes: every activation/retirement is a
  governance-signed, epoch-bumped, publicly auditable act.
