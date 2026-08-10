# Daimon Matrix–Cluster–Tribe convergence contract

Status: normative cross-repository contract for the V0 hosted runtime.

“Matrix” in this document means our `daimon-matrix` component. Matrix.org is
not used. The `daimonmatrix host` is the VPS where Cluster can realize bodies;
it is not a software component or an identity authority.

## Authority boundaries

| Boundary | Sole authority |
|---|---|
| Being root, recovery, embodiment credentials, authority epochs | `daimon-matrix` |
| Signed `dm.we` history, `/me`, `/we`, `/we.sync`, decisions, projections, relationship/grant authority and canonical communication semantics | `daimon-matrix` |
| Bodies, incarnation runtime state, lifecycle and portable storage | `daimon-cluster` |
| Concrete resource exclusion and observed postconditions | `daimon-cluster` |
| Transitional v1 ordinary human-message transport, deduplication and its own ACK evidence | Tribe Bridge |

Transport principals do not define a being. Cluster registry rows do not prove
a being. Receiving an event does not adopt it.

## Exact installed boundary

Cluster pins `daimon-matrix` by full Git commit in
`requirements-weave.txt`. Startup verifies the installed distribution's
`direct_url.json` commit and every public schema constant used by the adapter.
An unpinned wheel, editable checkout, wrong commit or schema downgrade fails
closed. Cluster does not carry a fallback implementation.

The current pin is audited Matrix DM-083 candidate
`d086e7432c46310c563af14e51c7a4fa5a5f6b88`.
The adapter accepts the additive runtime bundle line V1 through V6 and checks
every corresponding public schema constant before opening state. Bundle
contents remain Matrix authority; Cluster only validates the hosting envelope.

DM-083 gate (2026-08-10): Matrix draft PR #112 is frozen at the exact commit
above after DM-082 merged at `dad012d`. Cluster issue #52 owns the source and
installed-process verification of this pin. Any later Matrix candidate change
requires another exact repin and complete downstream gate.

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

Tribe Bridge remains temporarily deployed for ordinary human messages and its
own authenticated transport/deduplication/ACK evidence. It is not the Matrix
peer wire, does not carry canonical `/we.sync` authority, and its ACK is never
Matrix recipient intake or a semantic receipt. Matrix DM-051 through DM-055 and
DM-082 independently own recipient encryption, logical message legs,
authenticated intake, signed semantic receipts, relationships/grants and the
native peer carrier. Cluster only hosts the exact Matrix process and provides
physical observations. Alternative chat-facing carriers may be evaluated
later; they do not replace this authority split.

## Migration and rollback

Cluster's provisional `weave/` executable was retired after the frozen
historical fixture was accepted byte-for-byte by the pinned Matrix provisional
authority and tampering was rejected. The old code remains recoverable at Git
commit `54a30fa`, but is not shipped or imported.

Rollback preserves both ledgers unchanged: stop admission, quiesce the Matrix
process, retain state/high-waters, and deploy the prior whole release. Never
let provisional code open a Matrix root, lower a fence epoch, downgrade a root
manifest or reinterpret imported history as adoption.
