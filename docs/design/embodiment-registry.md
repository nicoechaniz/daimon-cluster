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
  signed, in cursor order. This IS the being's chain of existence
  (M10-R3): each entry carries `prev_sha256` (sha of the canonical
  previous entry, signature included) and `genesis_sha` (the being's
  root anchor — sha of the canonical genesis entry minus
  signature/genesis_sha).
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

## 5b. Chain of existence (M10-R3, implemented)

The invariant — common root + unbroken path — is checkable code:

- `EmbodimentRegistry.verify_chain(being_root)` → per-entry signatures,
  cursors strictly increasing, prev links intact, one genesis_sha
  throughout, genesis declares the same being_root.
- `EmbodimentRegistry.segment(being_root, after_cursor)` → the /we.sync
  (R4) export primitive: entries past a peer's high-water mark.
- `verify_common_root(entries_a, entries_b)` → two chains are the same
  being iff they share a genesis_sha. /we.sync runs this before merging.
- **The chain is authoritative; the snapshot is a derived view.** A
  host that receives a chain segment rebuilds its snapshot from the
  chain before mutating, so its next append lands at the right cursor.

## 6. v1 simplifications (recorded)

- Single-host storage (daimonmatrix `state_dir`); cross-host
  convergence of chains is /we.sync (R4), not replication.
- Registry writes are local to the operator host; the clusterd read
  endpoint `GET /v1/registry` exposes the census to the dashboard.
