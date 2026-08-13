# Runtime mutation intent journal

Status: implemented candidate for issue #65; not enabled on a live host.

## Problem and invariant

An Incus call can succeed even when its response is lost or a later registry,
spec, idempotency or audit write fails. Returning an error without remembering
that substrate effect permits a retry to invent a second incarnation or to
publish a false logical state.

Every implemented substrate workflow now closes its exact intent in
`operation-journal.sqlite3` before dispatch. At most one non-terminal
operation may exist for a target. A pending or degraded record blocks a
different follow-on operation until the original operation converges or a
bounded repair is authorized.

The journal covers:

- create, start, stop and restart;
- `provision prepare` container, volume, in-container identity and seed work;
- the outer park-handoff, wake-handoff and transfer-handoff workflows, whose
  existing step journals remain the operation-specific resumability layer.

The destroy endpoint still returns 501 and performs no substrate mutation.
There is therefore no destroy effect to journal yet. Archive evidence and the
destructive confirmation gate must land before an executable destroy path is
added; that future path must enter this journal before its first Incus call.

## Closed intent and state machine

`cluster-operation-intent/v1` binds the operation and target, exact runtime
call bytes, expected runtime/registry/spec precondition, intended logical
transition and stable audit identity. Starts and restarts reserve one
incarnation id and start timestamp before runtime dispatch. Provisioning
similarly reserves one spec, confirmation token and token timestamp.

The owner-only SQLite record advances monotonically:

```text
planned -> runtime-dispatching -> runtime-applied -> logical-committed
        -> idempotency-persisted -> audited -> completed

any safely reversed workflow -> compensated
unresolved or contradictory truth -> degraded
```

The move to `runtime-dispatching` is durable before the adapter call.
`runtime-applied` includes a post-call observation, not merely a successful
return. Logical state is committed only after that observation matches the
closed postcondition. Audit uses a preallocated event id, so response loss
after append reuses the exact event instead of appending a second success.
Transient lock-break context is also captured in the original audit identity;
retry cannot change the bytes of that event.

A terminal idempotency identity cannot silently create a successor journal.
Only the existing operation-shaped effect-truth verifier may explicitly allow
a new start/stop convergence attempt after it has recorded a contradiction;
missing or corrupt projection state therefore fails closed instead of
restarting an old effect.

The database uses WAL, `BEGIN IMMEDIATE` and `synchronous=FULL`. Database,
WAL and shared-memory files are regular owner-controlled files with mode
0600. The legacy JSON idempotency projection is written by fsyncing an
owner-only temporary file, atomically replacing the target and fsyncing the
parent directory. Corruption or unsafe ownership fails closed.

## Operation-specific convergence

Start and stop observe runtime truth after dispatch. Recovery skips an
already-satisfied effect but commits the original intended registry/spec
transition. Restart response loss is ambiguous even when the instance is
running, so recovery forces one stopped boundary and starts again while
retaining the single preallocated successor incarnation.

Create recovery adopts only the exact container named by the closed intent.
A partial adapter failure is deleted; if deletion cannot be verified the
operation becomes degraded and the target stays blocked. A runtime-applied
container whose spec/registry write failed remains explicitly tracked and is
resumed with the same body and embodiment ids.

Provision recovery repeats only idempotent steps: exact container creation,
start, volume attachment, create-if-absent identity generation and exact seed
staging. Any ordinary post-creation failure compensates container and volume
and marks the reserved spec `creation-failed`. If cleanup cannot be verified,
the journal remains degraded rather than claiming reversal.

Handoff operations have two layers. The outer operation journal establishes
the intent-before-substrate invariant and closes idempotency/audit. The
existing park/wake/transfer step journal resumes or rolls back individual
checkpoint, fence, container and spec steps. A policy refusal or verified
rollback closes the outer record as compensated, allowing a later request
with changed approved flags.

Transfer intent additionally closes both lock targets, the source/target
names, exact custom-volume identity/device/mount, checkpoint manifest hash and
immutable fence epoch/proof. Runtime retry must re-observe those same bytes.
The target container is created stopped without a home device; create, start,
detach and attach response loss converge from substrate truth. One intended
incarnation id is persisted before target start and registry recovery may
commit that id only once. A rollback is compensated only after the exact
volume is observably back on one stopped source attachment and the target is
gone; inability to prove custody leaves the row degraded.

## Observation and bounded repair

`clusterctl reconcile --json` adds one `pending_operation` warning or
`degraded_operation` error per open record and reports
`counts.open_operations`. `/v1/health` remains HTTP 200 for liveness but is
`degraded` while any operation needs attention or the journal is unreadable.

`clusterctl repair --operation-id <id> --json` is intentionally narrow. It
can authorize only a degraded start, stop or restart whose container is
present and observably running or stopped. Every repair resumes at
`runtime-dispatching`, so runtime truth is re-observed while the normal target
lock is held; start/stop skips an already-satisfied effect, while restart
forces an observable stopped boundary because a merely running process cannot
prove that the original restart occurred. The authorization audit is appended
before the degraded row is released. Create, provision and handoff ambiguity
has no generic repair because safe policy depends on their concrete artifacts.

## Rollback

Do not delete or roll back the journal independently of Incus, specs,
embodiment registry, audit log or idempotency projection. Quiesce cluster
mutations, preserve the SQLite database and WAL, inspect `reconcile`, and
finish or explicitly compensate every open operation before reverting code.
Never clear a degraded row merely to unblock a target.
