# Daimon Cluster delivery plan

## Release target

Ship the first operational `/we` without requiring a Matrix runtime. Cluster
hosts an isolated Weave service; Tribe transports its messages; Matrix defines
the canonical protocol.

## Work packages

1. Body/embodiment/incarnation registry integrated into lifecycle operations.
2. Resource-scoped fence registry replacing identity-wide exclusion.
3. `dm.we.v1` ledger with transactional origin chains and bounded deltas.
4. Preview/pull, difference navigation, local successor decisions, and
   projection receipts.
5. Live `/we` request fan-out, deduplication, deadlines, and partial results.
6. Tribe typed transport and founded-membership protocol.
7. HMK and external-identity adapters with preview and confirmation policy.
8. Dashboard/read APIs and Legion–daimonmatrix acceptance runbook.

## Acceptance

Two embodiments of one being run simultaneously, exchange origin-marked
events, report unapplied differences, choose independently, reverse a choice,
answer one `/we` query separately, restart and resume without duplicates, and
still reject stale writers against the same resource.
