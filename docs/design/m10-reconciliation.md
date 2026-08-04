# M10 branch reconciliation

Status: accepted design decision, 2026-08-02.

## Scope and lineage

Two implementations grew from `ed8a249` while the ontology rectification was
being applied:

- GitHub `main` at `f93ee80` is the canonical line. It contains the
  `dm.we.v1` Ed25519/JCS protocol, origin-separated incarnation chains,
  resource-scoped fences, the dashboard read model, and the successful
  Legion–daimonmatrix canary.
- The daimonmatrix R-series at `c59d134` is an archived implementation line.
  It is evidence and a source of reviewed deltas, not a branch to merge
  wholesale.

The trees differ in protocol shape, registry ownership, signing, and dashboard
implementation. A Git merge or broad cherry-pick would restore superseded
contracts. Reconciliation therefore evaluates each semantic delta against the
canonical line.

## Decisions

| Candidate from the R-series | Decision | Canonical treatment |
|---|---|---|
| R5 effect-truth idempotency (`cd7595b`, completed by `f5937d0`) | Accept with adaptation | An idempotency hit is only a replay candidate. Cluster verifies the operation-specific observed postcondition. Drift re-enters only workflows proven convergent; other contradictions and unverifiable non-convergent effects fail closed. |
| R6 deterministic partition merge (`3437ef3`, fixed in `f5937d0`) | Do not port its chain rewrite | Normal partitioned embodiments already converge by additive set union of immutable `dm.we.v1` events. Every origin/incarnation retains its own signed predecessor chain and causal parents may cross origins. |
| R-series registry, bundle format, signing, and dashboard | Do not port | `embodiments.py`, the `dm.we.v1` envelope, Ed25519 signing, independent SQLite ledgers, and the existing Weave card remain authoritative. |
| R-series ontology document | Link semantics; do not duplicate | `docs/design/embodiment-and-weave.md`, the installed Matrix protocol, published vectors, and the canary receipt describe the boundary. Matrix is now the active identity authority. |
| R-series cross-host runbook | Archive only | The executed receipt in `docs/verification/weave-r6-legion-daimonmatrix.md` supersedes a prospective runbook. |
| R-series handoff terminology cleanup | Port selectively | Historical test names and the guarded `leases/` storage path remain compatibility artifacts; all current safety claims are resource-scoped and never presence or identity exclusion. |

## Why R6 is not a compatible successor protocol

The R-series merge chooses one global cursor branch, selects the smaller
canonical hash as a deterministic base, and reanchors the losing records under
`merged_entry`. That is a coherent design for its own unsigned/global-chain
model, but it is not a valid transformation of `dm.we.v1`:

1. parallel embodiments append to different origin/incarnation chains, so
   their equal sequence numbers are not a conflict;
2. reanchoring changes canonical bytes and invalidates the original origin's
   Ed25519 signature;
3. different embodiment keys cannot independently create byte-identical
   signed merge records; and
4. normal experiences, proposals, and decisions converge by immutable set
   union while preserving who authored and lived each event.

Same-incarnation, same-sequence different content remains equivocation and is
quarantined. Defining recovery from that security fault requires a normative
successor/fork-resolution protocol in Matrix before Cluster implements it. It
must not be confused with ordinary life during a network partition.

The existing
`test_partitioned_embodiments_merge_without_losing_origin` acceptance test and
the R6 canary already prove interrupted, bidirectional, idempotent convergence
without rewriting signed history.

## Effect-truth boundary

The reconciled verifier is deliberately operation-shaped:

- create/start/stop/restart check the exact Incus state;
- snapshot replay requires both the named readable snapshot and its durable
  manifest;
- provision prepare requires the pending spec, body, and an unconsumed,
  unexpired confirmation bound to the same target;
- plain park re-executes because writer quiescence is not observable through
  container state;
- handoff park, wake, and transfer additionally require their durable records,
  expected runtime state, and the recorded live resource-fence generation.

Terminal handoff journals are not declared convergent after their durable
records or fence drift: blindly re-entering a completed journal could reproduce
the same stale terminal result. Those retries fail closed pending an explicit
repair protocol. This is intentionally stricter than the source R5 patch.

This closes the stale-success replay class without claiming that the current
fence implementation is production-grade. Authenticated inter-process CAS,
origin-to-key authorization, real volume relocation, projection execution,
and other hostile-peer hardening are intentionally deferred to issue #46.

## Repository disposition

After this reconciliation lands, `c59d134` stays reachable as historical
evidence and should not be deployed as the active Cluster line. Deployments
move back to GitHub `main`; no R-series database, signing key, registry, or
bundle is copied into the canonical runtime.
