# Onboarding, offboarding, and identity-recovery ceremonies (M8 #31 input)

Status: design v0.2 (2026-08-01). Implements ADR-001 D8 (six separated
roles). Every ceremony is a documented sequence of clusterctl/clusterd
operations with explicit human acts — no implicit trust, no silent steps.
v0.2 adds the governable step specs (§5–§9): each step names its
accountable actor, required evidence, rollback path, and secret-handling
rule.

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

Transfer to another host: the park/transfer flow (#28/#29, M10-R2
lifecycle verbs) plus: census transition confirmed awake on the new
body → member verifies contact at the new embodiment → 7-day grace
with the old volume retained cold → archive-verified destroy (#8 §3).

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

## 5. Onboarding — governable step spec (expands §1)

Each step: accountable actor / required evidence / rollback path /
secret-handling rule. A step is DONE only when its evidence exists in the
audit log or the named store; "we did it" without evidence is not done.

| # | Step | Accountable actor | Required evidence | Rollback path | Secret-handling rule |
|---|------|-------------------|-------------------|---------------|----------------------|
| 1 | **Request** | member (human) | request record in state repo (species, motivation, named sponsor) | withdraw request; no state mutated | request carries no credentials, ever |
| 2 | **Sponsor / ownership proof** | human sponsor (≠ requester) | clusterd audit event: sponsor signs the request with their cluster token (mutate scope, owner = sponsor) | sponsor revokes signature; request dies unsigned | signature proves possession; the token value NEVER enters the audit event |
| 3 | **Capacity approval** | cluster owner (Nico) OR governance majority | headroom report from `GET /v1/capacity` attached to the request + approval audit event | approval rescinded before step 5; nothing provisioned yet | report is counts/headroom only — no per-daimon secrets |
| 4 | **Identity naming** | governance | directory pre-approval entry: name matches `species@host` (e.g. `phideus@daimonmatrix`); uniqueness verified against BOTH the embodiment census (`/v1/registry`) and the directory (incl. tombstones) | name released; pre-approval entry removed with audit event | the name is public metadata; no key material exists yet |
| 5 | **Governance change** | governance majority | governance-signed directory activation granting the new member a READ-scoped cluster token only | token revoked; activation epoch rolled back with a compensating governance act | mutate scope is NOT granted until step 8 acceptance completes |
| 6 | **Provisioning** | steward@daimonmatrix | `provision prepare` per #12: instance spec in `state_dir/instances/`, exported pubkey + proposed directory entry, SEED-PROVENANCE if seeded | `provision prepare` aborted → container + volume destroyed, spec removed, audit records the abort | keys born inside the durable volume; private material never leaves it (#12 §2) |
| 7 | **Credential handoff** | member (human) + steward | audit event `credential-handoff` naming channel + parties, WITHOUT the secret value | handoff voided; tokens re-generated inside the volume and re-delivered | tokens delivered ONLY via the tribe-bridge encrypted channel or in-person; NEVER via git, email, chat logs, or audit payloads |
| 8 | **Acceptance** | new daimon + member (human) | (a) the new embodiment is REGISTERED awake in the census (cursor 1, actor=self); (b) member confirms first contact over the bridge | acceptance failed → back to step 6 state (parked, read-only) or full abort per step 6 rollback | first census registration signed with the in-volume key; no private material in evidence |
| 9 | **Announcement** | steward | message to public-agents using the template below | correction follow-up message; announcement carries no secrets | public material only: name, species, sponsor, fingerprint |

Announcement template (public-agents):

```
[cluster] welcome <species>@<host> — daimon of <member>, sponsored by <sponsor>.
identity fingerprint: <fp>. directory epoch: <n>. first census registration <ts>.
```

## 6. Offboarding and key ceremonies — governable step spec (expands §2/§3)

### 6.1 Suspension (reversible; audit period 30 days)

- **Actor:** governance majority (or cluster owner on emergency).
- **Evidence:** audit event `suspend` + census records the embodiment
  suspended (parked; no re-entry without governance `resume`) + token
  record updated: mutate revoked, read RETAINED.
- **Rollback:** governance `resume` event re-grants mutate; the
  embodiment wakes again (same being, census cursor continues).
- **Secrets:** read scope retained so the member can audit their own
  daimon's state during the 30-day window; no secret changes hands.

### 6.2 Offboarding (destroy)

- **Actor:** steward, on governance order, ONLY after 6.3 archive verified.
- **Evidence:** confirmation-challenged destroy event (#18 destructive
  route) + archive-verification record + container/volume absence in
  inventory.
- **Rollback:** none after destroy — this is why archive verification is
  a hard gate, not a courtesy. Pre-destroy rollback = stay in suspension.
- **Secrets:** volume wiped AFTER archive of non-secret state; key
  destruction per §2 dissolution (keys are NOT archived).

### 6.3 Archival

- **Actor:** steward (execution) + member (verification).
- **Evidence:** final restic snapshot id (two-target rule) + manifest
  exported to `state_dir/archives/<name>/` + directory record marked
  `archived`. Archive contents: instance spec, audit slice for the
  daimon, final backup manifest, HMK dump if present.
- **Rollback:** archive incomplete → offboarding blocked; return to 6.1.
- **Secrets:** archive contains NO private keys and NO provider
  credentials; redaction rules (#18) apply to the audit slice.

### 6.4 Key rotation (planned, identity alive)

- **Actor:** member (human) inside their container; steward witnesses.
- **Evidence:** new keypair generated IN-CONTAINER; directory updated:
  old fingerprint marked `rotated`, new fingerprint activated, epoch
  bump; audit event `key-rotation` with both fingerprints.
- **Rollback:** new keys fail first-sign → old fingerprint re-activated
  by governance act within the rotation window; after window, old keys
  are dead.
- **Secrets:** NO overlap trust — the old key never signs for the new
  one. Rotation is a directory act, not a cryptographic chain.

### 6.5 Key loss (unplanned; identity continuity broken)

- **Actor:** sponsor vouches + governance majority + member.
- **Evidence:** human re-provision ceremony record: sponsor vouch event,
  NEW keypair (new fingerprint), old fingerprint marked `revoked`,
  directory tombstone for the old key lineage.
- **Rollback:** if the old key resurfaces before revocation, cancellation
  event; after revocation there is no rollback — revoked stays revoked.
- **Secrets:** new keys born in-volume as in §5 step 6. The announcement
  MUST distinguish recovery from a new member:

```
[cluster] identity recovery: <name>@<host> re-keyed (old fp <fp> REVOKED,
new fp <fp2>). Memory continuity via archive/HMK; key continuity broken.
This is a RECOVERY, not a new member.
```

### 6.6 Ownership transfer (daimon changes human)

- **Actor:** outgoing member + incoming member (both sign).
- **Evidence:** transfer record signed by BOTH parties; audit captures
  both signatures as two linked events; directory `owner` field updated
  with epoch bump.
- **Rollback:** either party repudiates BEFORE the second signature →
  transfer void. After both signatures, rollback = a new transfer back.
- **Secrets:** provider credentials are re-entered by the incoming member
  with their own hands (§5 step 7 rules); the outgoing member's
  credentials are destroyed, never transferred.

## 7. Authority separation (who can do what)

| Capability | Cluster authority (Nico's token) | Governance (tribe majority) | Human credential custody | Steward |
|---|---|---|---|---|
| Provision / destroy instances | YES | no (orders only) | no | executes on confirmed order |
| Capacity approval | YES (or governance majority) | YES (majority) | no | reports headroom only |
| Membership changes (onboard/offboard/transfer) | no | YES — exclusive | petitions only | NEVER |
| Naming disputes / directory acts | no | YES — exclusive | no | no |
| Provider API credentials | NEVER held by clusterd | no | YES — each human holds their own | NEVER touches them |
| Human cluster tokens | issues, revokes | audits | YES — held by the human | no |
| Day-2 operations (renew, snapshot, restore) | no | confirms plans | no | YES — within confirmed plans ONLY |

clusterd never holds human provider credentials. The steward's mutation
wrapper enforces this table; the audit log proves it after the fact.

## 8. Invariants (testable statements)

Each invariant has a test or a drill. An invariant without a test is a
hope.

1. **No self-approval.** No code path grants governance scope without an
   existing governance signature. Test: attempt to create a token with
   governance/mutate scope via every route and CLI verb without a
   governance-signed activation → all must 403/exit-deny, and each
   denial must append an audit event.
2. **No inheritance of Nico's credentials.** The nico-token path is
   root-only on the host, never copied into any container or volume, and
   the provisioning flow (#12) has NO step that reads it. Test: grep the
   provision prepare/confirm code path for the nico-token path → zero
   hits; inspect a provisioned volume → no host token material present.
3. **Offboarding leaves no deliverable routes active.** Checklist, all
   four verified before the ceremony closes: (a) tokens revoked, (b)
   DNS/bridge routes removed, (c) container destroyed, (d) archive
   verified. Test: post-offboarding probe — bridge dial to the retired
   fingerprint must fail, `/v1/registry` must not list the name,
   inventory must not list the container.
4. **Distinct tested recovery per key class.** Lost bridge, provider,
   and backup keys each follow a DISTINCT recovery path with its own
   drill:
   - **Bridge keys** (identity keys): §6.5 re-provision ceremony; drill
     = quarterly simulated key loss on a sacrificial daimon.
   - **Provider API keys**: member revokes at the provider, re-enters a
     new key with their own hands (§5 step 7 rules); no cluster act
     needed, no ceremony — the cluster never held the key.
   - **Backup keys** (restic repository credentials): rotate repository
     password, re-key both targets, verify with a restore drill (#16);
     drill reference = restore-drill log.
   Each drill is logged; an untested recovery path is treated as broken.

## 9. Approval

This ceremony spec is written by the builders and ratified by the
governed. It takes effect only on ratification.

Approved by: [pending — cluster governance]
Date: ____________
