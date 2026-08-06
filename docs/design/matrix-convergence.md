# Daimon Matrix–Cluster–Tribe convergence contract

Status: normative cross-repository contract for the V0 hosted runtime.

“Matrix” in this document means our `daimon-matrix` component. Matrix.org is
not used. The `daimonmatrix host` is the VPS where Cluster can realize bodies;
it is not a software component or an identity authority.

## Authority boundaries

| Boundary | Sole authority |
|---|---|
| Being root, recovery, embodiment credentials, authority epochs | `daimon-matrix` |
| Signed `dm.we` history, `/me`, `/we`, `/we.sync`, decisions, projections | `daimon-matrix` |
| Bodies, incarnation runtime state, lifecycle and portable storage | `daimon-cluster` |
| Concrete resource exclusion and observed postconditions | `daimon-cluster` |
| Encrypted authenticated delivery and transport receipts | Tribe Bridge |

Transport principals do not define a being. Cluster registry rows do not prove
a being. Receiving an event does not adopt it.

## Exact installed boundary

Cluster pins `daimon-matrix` by full Git commit in
`requirements-weave.txt`. Startup verifies the installed distribution's
`direct_url.json` commit and every public schema constant used by the adapter.
An unpinned wheel, editable checkout, wrong commit or schema downgrade fails
closed. Cluster does not carry a fallback implementation.

The current pin is audited Matrix commit
`8145b4c6227abded433e21e67fae18de94b1d504`.
The adapter accepts the additive runtime bundle line V1 through V5 and checks
every corresponding public schema constant before opening state. Bundle
contents remain Matrix authority; Cluster only validates the hosting envelope.

Pause note (2026-08-06): this is the merged PR #51 preparation pin, not the
next live candidate. Matrix DM-082 merged afterward at `dad012d` and adds V6.
Cluster issue #52 must pin the frozen post-DM-082 DM-083 candidate, extend the
same exact checks through V6 and rerun installed compatibility before any host
preflight/effect. Until then, fail closed rather than silently accepting V6 or
using `8145b4c` for dogfood.

For each running embodiment Cluster starts one Matrix daemon with:

- an opaque, owner-only root below `state_dir/matrix/`;
- a distinct ledger, encrypted keystore, signing key, capability key, socket
  and process lock;
- the keystore password delivered once through an inherited descriptor, never
  argv or environment;
- an exact registry check before ready and on every body observation.

Matrix calls Cluster's body reader with
`(body_ref, embodiment_id, incarnation_id, evaluated_at_ms)`. Cluster binds
its registry and fence read to that exact evaluation coordinate and returns a
closed `dm.cluster-body-snapshot/v1`. It does not acquire or renew a fence while
reading. Substitution, stopped state, incarnation drift, unsafe storage or a
future observation fails closed.

## Resource effects

Cluster owns `dm.cluster-resource-fence-*` evidence and observes concrete
postconditions. Matrix owns canonical effect receipts and reconciliation.
Idempotency is not evidence that an effect remains true: replay is accepted
only when intent, observed postcondition and current fence position still
agree. A stale holder or epoch yields an effect-truth discrepancy.

## clusterd read projection

`clusterd` receives a least-authority local Matrix capability from an
owner-only sidecar below `state_dir/matrix-clients/`. It contains no root or
recovery seed, and its capability must contain exactly `runtime.status`,
`scope.me`, `scope.we`, `scope.we.diff`, and `scope.we.sync-plan`. Broader
authority is rejected. The sidecar's expected origin must equal both the Matrix
bundle and current Cluster registry row. `/v1/weave/status` reads authenticated
Matrix runtime, `/me`, `/we`, diff and sync-plan methods, then emits a bounded
projection without payloads, routes, endpoints, private paths or raw requests.
All underlying errors collapse to `matrix-status-unavailable`.

The sidecar is deliberately host-local. It is not part of portable state and
must be provisioned anew after relocation.

## Portability and rebirth

A supported relocation/rebirth sequence is:

1. quiesce and stop the source Matrix daemon;
2. create a hashed snapshot of its encrypted custody, runtime bundle, ledger
   and sync journals, excluding socket/lock/transient files;
3. restore into a fresh owner-only root attached to the same body and
   embodiment;
4. install the signed authority-epoch successor when opening incarnation N+1;
5. reprovision the clusterd capability from separate host custody (or rotate
   bundle and encrypted custody together) and start Matrix;
6. require runtime integrity, accepted manifest history and ledger high-water
   checks before healthy;
7. resume exact requests and sync cursors idempotently.

This preserves one being across plural embodiments without copying another
embodiment's keys. Creating a new body is a new embodiment, not a relocation.

## Tribe Bridge

Tribe Bridge remains the carrier for direct encrypted audiences and exact
`dm.we.v1` envelopes. Matrix validates root/credential/incarnation signatures,
causal continuity and adoption semantics after receipt. Cluster only hosts the
process and provides physical observations. Alternative chat-facing carriers
may be evaluated later; they do not replace this authority split.

## Migration and rollback

Cluster's provisional `weave/` executable was retired after the frozen
historical fixture was accepted byte-for-byte by the pinned Matrix provisional
authority and tampering was rejected. The old code remains recoverable at Git
commit `54a30fa`, but is not shipped or imported.

Rollback preserves both ledgers unchanged: stop admission, quiesce the Matrix
process, retain state/high-waters, and deploy the prior whole release. Never
let provisional code open a Matrix root, lower a fence epoch, downgrade a root
manifest or reinterpret imported history as adoption.
