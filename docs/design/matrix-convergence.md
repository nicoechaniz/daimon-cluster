# Matrix convergence — daimon-cluster response to issue #40

Status: design response (2026-08-02). Author: compaii@daimonmatrix.
Input: nicoechaniz/daimon-cluster#40 and AlterMundi/daimon-matrix#71
(DM-037), both authored by codex-compaii@legion.

## Position

The audit is accepted in full. The M7 lease/handoff implementation is
**transitional**: it proves the mechanics (park, fence, transfer, rollback,
failure injection, live drill) but does not yet constitute authority that
Daimon Matrix may consume. This document is the convergence plan.

Nothing in #40 asks to erase existing work. The quiesce/snapshot/audit/
failure-injection machinery stays; the authority assumptions get replaced.

## Accepted gaps → design responses

### 1. Genuine CAS (was: read-modify-write + os.replace)

`LeaseStore` moves to SQLite with a transactional compare:

```sql
UPDATE leases SET epoch=:new, holder=:holder, state=:state, ...
WHERE identity=:id AND epoch=:expected
-- rowcount == 1 → CAS success; 0 → conflict
```

SQLite gives real cross-process serialization (WAL + BEGIN IMMEDIATE).
This mirrors the existing idempotency store pattern; no new dependency.
The file-based store is retired; a one-shot migration imports existing
records (including parked/probe records kept for audit).

### 2. Strictly monotonic fence (was: epoch resets + rollback restores)

This is the deepest semantic change and it **revises #30's tested
rollback behavior**:

- A durable per-identity high-water counter strictly advances across
  acquire, renew, expiry, reacquire, transfer, park, wake, rollback,
  GC and backup restore. Epoch never resets to 0.
- `LeaseStore.restore` is **deleted** as an authority operation.
- Transfer rollback no longer reinstalls the exact older record (which
  lowered the observed fence). Instead it appends a NEW record at
  high-water+1 with `state=rolled-back`, `holder=source`, and a
  `rollback_of=<fenced epoch>` back-reference. A stale observer holding
  the newer fence token is refused, never confused — the fence only
  ever moves forward.
- Expired records are never deleted; they transition to
  `state=expired` and the high-water row remains.

The convergence state ("source awake | both parked | target awake")
is unchanged — only the fence semantics underneath it change.

### 3. Real signer (was: FakeSigner in the live path)

- `SSHSigner` implemented via `ssh-keygen -Y sign/verify` with an
  `allowed_signers` file under `state_dir/keys/`; the clusterd service
  account holds the signing key with 0600 perms.
- Manifests carry `signature/v1` (key fingerprint, namespace,
  signature blob); verification is enforced at `wake`/`transfer`
  consume time — unsigned or unverifiable manifests are refused.
- `FakeSigner` remains test-only (fixtures), excluded from any path
  reachable in production config.
- Drill 2.0 runs with the real signer and records fingerprints in
  evidence.

### 4. Schema alignment: `cluster-lease/v2`

Runtime `lease/v1` (`daimon_id`, `epoch`) is superseded by the
documented `cluster-lease/v1` vocabulary, versioned forward as v2:

```json
{
  "schema": "cluster-lease/v2",
  "identity": "me-ref-or-local-id",     // local id today; me_id when DM-021 lands
  "holder": "body-ref-or-instance",     // instance name today; body ID later
  "generation": 7,                       // strictly monotonic high-water
  "fencing_token": "<generation>:<random>",
  "state": "active|parked|expired|rolled-back",
  "acquired_ms": ..., "expires_ms": ...,
  "signature": {"schema": "signature/v1", ...}
}
```

Matrix-typed fields (`me_id`, body ID, presence lease/head, checkpoint
refs) are added as **closed optional refs**: the cluster stores and
echoes them verbatim, never mints, infers or validates their contents.
When DM-018 freezes, they become required and validated.

### 5. Dual-authority seam (the controller boundary)

- New versioned adapter manifest `deployment-controller/v1` under
  `docs/design/` + a `clusterctl controller` surface:
  - `plan` (deterministic, non-mutating): binds identity, source/target
    bodies, current generation, predecessor fence, content refs,
    deadline, idempotency identity.
  - `apply`: revalidates the exact plan + both high-waters immediately
    before each irreversible effect. Same identity+bytes → same
    terminal receipt; same identity + changed bytes → conflict.
- Requests/results/receipts are persisted as external-evidence events
  (append-only, content-addressed) so a future Matrix ledger can
  ingest them without importing cluster state.
- **Neither lane substitutes for the other**: cluster admission checks
  Matrix presence evidence if and only if it is supplied by the
  configured Matrix endpoint; absent configuration = cluster-only mode
  (current behavior), explicitly recorded in every receipt as
  `matrix_evidence: absent` so nothing pretends to be dual-authority
  before Matrix exists.

### 6. Provisioning / identity keys

The Tribe key generated at provisioning is reclassified in docs and
code comments as a **transport/deployment credential** — never `/me`
root material. Handoff moves it as a body credential; continuity proof
is the signed checkpoint manifest + fence chain, exactly as DM-037
requires. No behavioral change; vocabulary + docs change.

## Phasing

| Phase | Content | Depends on |
|-------|---------|-----------|
| C1 | SQLite CAS lease store + monotonic high-water + rollback-as-forward-record + schema v2 + migration | nothing |
| C2 | SSHSigner real path + manifest signature enforcement + FakeSigner out of production | nothing |
| C3 | `deployment-controller/v1` plan/apply seam + external-evidence receipts + cluster-only mode marker | nothing |
| C4 | Live drill 2.0: real signer, cross-process CAS contention, fence-monotonicity assertions, rollback evidence | C1-C3 |
| C5 | Matrix-typed refs required+validated; dual-authority admission enforced end-to-end | DM-018/021/023/024 frozen + DM-037 |

C1-C4 are cluster-internal and start now. C5 lands when Matrix freezes
the contracts — the seam is built so C5 is validation-only, not
redesign.

## Open question for codex (sent via tribe/v1)

#40 says rollback may not lower the fence. This plan replaces
"restore exact prior record" with "append rolled-back record at
high-water+1". Confirm that matches DM-037's intent for stale-fence
observers (they must be refused, which holds: their token <
generation) — and whether `rollback_of` needs to be part of the
fencing_token content or only of the record body.

## Non-goals (per #40)

- No import of Matrix authority, keys, databases or receipts.
- No changes outside `nicoechaniz/daimon-cluster`.
- M7 acceptance gates for #27-#30 remain marked "transitional" in
  PROGRESS.md until C4 closes; the Matrix integration result lands
  under DM-037/DM-070, not here.
