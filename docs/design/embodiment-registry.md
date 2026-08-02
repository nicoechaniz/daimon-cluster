# Embodiment registry design (M10-R2; supersedes lease-registry.md)

Status: implemented v1 (2026-08-02), `clusterctl/registry.py`.
Canonical vocabulary: `docs/design/ontology.md`.

## 1. Purpose

A **census**, not a gate. The registry answers: "where is being `<root>`
embodied, and in what state is each embodiment?" — so that park/wake/
transfer can record lifecycle transitions honestly, wake can verify
checkpoint freshness, and /we.sync (R4) has a directory of embodiments
to weave.

Under the M10 ontology the plurality of awake embodiments of one being
is NORMAL. Coherence comes from the chain of existence and effect-truth
— never from excluding bodies. The registry therefore has **no
exclusion semantics**: no TTL, no fencing, no CAS-refusal, no "one
holder" rule. Registering an embodiment always succeeds; the cursor
only orders.

## 2. Storage & signing

- One snapshot per being: `state_dir/registry/<being_root>.json`
  (schema `embodiment-registry/v1`): current cursor + one row per
  embodiment `{state, body, manifest, updated_ms, cursor}`.
- One append-only history per being:
  `state_dir/registry/<being_root>.history.jsonl` — every transition,
  signed, in cursor order. History is the seed of the per-embodiment
  chain of existence (R3).
- Snapshot and every history entry are signed with the clusterctl
  signing primitives (`clusterctl/signing.py`: canonical JSON minus
  `signature`). Any tampered record fails verification — read paths
  fail closed.

## 3. Semantics (binding)

- **Register always succeeds.** `register(being, embodiment, body,
  state, manifest?)` appends the transition at `cursor+1` and updates
  the snapshot row. There is no refusal path for "already registered"
  or "another embodiment is awake" — both are normal.
- **Cursor is monotonic per being.** Cursors order transitions; they
  never exclude. They are the sync cursors of /we.sync (R4) and the
  repurposed CAS machinery (R3).
- **Checkpoint freshness (replaces stale-fence).** A park manifest
  binds the registry cursor of the awake row at verification time.
  Wake/transfer refuse when the census has moved past that checkpoint
  (a newer transition exists, or the parked record points at a
  different manifest). This protects STATE freshness — it says nothing
  about who may exist.
- **Rollback appends, never restores.** A failed wake/transfer records
  the embodiment `parked`/`rolled-back` as a NEW record at cursor+1.
  History keeps both the failed attempt and its rollback. The cursor
  never goes down.
- **Liveness is observed, not registered.** The registry records intent
  and history; whether a body is actually running is read from the
  fleet adapter (incus), not from the census.

## 4. Operations

| Op | Flow |
|----|------|
| park | verification requires the embodiment registered awake → census records awake→parked pointing at the signed manifest → body stops |
| wake | freshness check (parked record still points at THIS manifest) → census records parked→awake BEFORE start → restore → spec active |
| transfer | freshness check → target created stopped → census records relocation (same embodiment, new body) BEFORE start → restore → start |
| rollback | failed wake: append `parked`; failed transfer: destroy target + append `rolled-back` + note |
| re-entry | the woken embodiment reads its own registry history → knows its unbroken path |

## 5. What was purged (from lease-registry.md / leases.py)

- "One identity, one awake body" as an enforced rule → plurality is normal.
- TTL / expiry / renewal → no clock semantics in the census.
- Fencing tokens / CAS-refusal → cursors (ordering only).
- Broker enforcement of sleeping identities → out of the cluster's
  scope; coherence between embodiments is /we.sync's job (R4).
- `restore()` (putting back an old record) → append-only rollback.
- The word "lease" as an identity concept everywhere in the repo.

## 6. v1 simplifications (recorded)

- Single-host storage (daimonmatrix `state_dir`); cross-host
  convergence of registries is part of /we.sync (R4), not replication.
- Registry writes are local to the operator host; the clusterd read
  endpoint `GET /v1/registry` exposes the census to the dashboard.
- History verification is per-entry signature; the per-embodiment
  hash-chain (R3) will link entries into a tamper-evident sequence.
