# /we.sync v1 design (M10-R4, implemented)

Status: implemented v1 (2026-08-02), `clusterctl/wesync.py` + CLI verbs.
Canonical vocabulary: `docs/design/ontology.md`.
Mirror of: daimon-matrix DM-023 (sync cursors + idempotent convergence)
and the DM-070 acceptance scenario.

## 1. What syncs

Per being root, between its embodiments:

- **Experiences** — `we-experience/v1` records, append-only, signed by
  the origin host, keyed `(origin, origin_seq)`. Origin attribution is
  never rewritten: a synced experience still says who lived it and
  carries its original signature.
- **Chain segments** — the R3 primitives (`registry.segment`,
  `verify_common_root`) carried in the same `we-sync-bundle/v1`.

Skills and larger state ride as experience payloads/refs in v1.

## 2. Cursors and convergence

- Peer high-water marks: `wesync/<being>/peers/<peer>.json`
  (`chain_cursor` + per-origin experience seqs). Export computes the
  delta against them; import advances them.
- Experiences converge by UNION — no cross-origin conflict is
  possible, re-import is idempotent (no duplicates, ever).
- Chain entries append only when they link onto the local tip. Same
  cursor with different content = a partition BRANCH: v1 never picks a
  winner — it flags `wesync/<being>/merge.json` (the dashboard's
  "mergeando" state, R7) and still weaves experiences. Branch merge is
  R6's partition+coherent-merge test.
- Common root is enforced: a bundle whose genesis differs from the
  local chain is refused — a different being, not a conflict.

## 3. Transport

Bundles are plain JSON on stdout/files. Cross-host path: pipe through
tribe-bridge v1 (`wesync export | send_v1 ...`, `wesync import --file`)
— the bridge is transport, never authority. Cross-host SSH-signer key
trust is the cross-host milestone's concern (documented, not silent).

## 4. CLI

- `clusterctl wesync status <being>` — chain verification + census +
  peers + merge state.
- `clusterctl wesync record <being> --origin <emb> --kind <k> --payload <json>`
- `clusterctl wesync export <being> --from <emb> [--peer <p>]`
- `clusterctl wesync import [--file <bundle.json>] [--dry-run]`

## 5. Acceptance (tests/test_wesync.py — mirrors DM-070)

Two embodiments seeded from one consistent snapshot; independent
appends; preview without mutation; bidirectional convergence; origin
attribution intact (original signatures preserved); re-sync without
duplicates; resume after interruption; tampered bundle refused;
foreign being refused; partition branch flags merging while
experiences still converge. No shared keys or databases.
