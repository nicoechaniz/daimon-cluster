# Daimon Matrix–Cluster–Tribe convergence contract

Status: normative cross-repository contract for the V0 hosted runtime.

“Matrix” in this document means our `daimon-matrix` component. Matrix.org is
not used. Historical references to a similarly named host do not make that
host an RC target; this contract assumes no existing infrastructure.

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

The V0 RC functional merge is
`09414d6edd9586f539be8272c4979d0b36c86b87`; the exact merged installed pin is
its reviewed RC closeout successor
`bf5f7415f075af09442973144bc529f4c5ce7985`. The functional merge consolidates
the fresh-embodiment, distributed-custody, least-authority capability and
recovery work. Historical deployed-pair commits are recorded in dated
receipts, not in the current execution contract. The only production-shaped RC bundle is V7
and the only client configuration is V3; older undeployed formats fail closed
at both Matrix and Cluster boundaries. The adapter also
checks the closed DM-031 item/claim/result/inspection schemas, work kinds,
coordination modes, exact four-method curator capability and the complete
DM-034 profile/intent/receipt/reconciliation/rebuild schema line introduced at
Matrix merge `1b133976932cbbc0914ba4ecc403020c647f53c1`; the current pin is an
audited additive descendant of that merge. Bundle contents remain Matrix
authority; Cluster only validates the hosting envelope.

Cluster owns source and installed-process verification of the exact pin, the
V7 client config/binding boundary and the exact five-method status-observer
set. Cluster does not interpret historical servers or Matrix custody. Any
later Matrix candidate change requires another exact repin and complete
downstream gate.

H7 adds the Matrix `operator_rebirth` contract to the same closed import gate.
Cluster accepts only the root-authorized package produced by the exact pin,
installs new target custody without opening it, and forward-updates prior peers
with the signed activation. See `docs/design/fresh-embodiment-rebirth.md`.
The recovery successor additionally exposes a canonical-ledger-only restore
boundary. Cluster verifies the portable snapshot, journals installation and
restore separately, and gates first start on the exact restore receipt; it
does not restore predecessor custody or public runtime bytes.

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

The hosted process injects `MatrixHostAdapter.verify_fence` into Matrix's
DM-031 coordinator. Effect truth passes through a closed router selected by
the exact receipt adapter, curator work kind and first `resource_ref`
namespace. Unknown, duplicate, unavailable or throwing routes are
`effect_truth_unverifiable`; there is no receipt-trusting fallback.

H5 provides the exact personal-memory route:
`(cluster-dm034-hmk/v1, memory-projection, hmk)`. It is created only together
with a fixed per-embodiment executor; the generic Matrix host still has no
ambient/default route. The executor accepts no queue-selected path, database,
process or operation. It re-resolves Matrix's current payload-free intent,
checks the exact DM-034 profile and preview/plan hash, current actor and any
independent source-review reference, verifies the production fence before and
after the effect, and invokes only `MemoryProjectionAdapter.project`,
`rebuild_plan`, `rebuild_apply`, `inspect`, `verify`, and `reconcile`. Its
observer repeats inner effect observation and returns current fence evidence.
See `docs/contracts/dm034-hmk-executor-v1.md`.

H6 adds the separate exact reviewed-publication route
`(cluster-dm035-publisher/v1, publication, publication)`. Matrix DM-035 still
owns final-byte rendering, explicit consent, purpose-separated human signature,
source checkpoint, predecessor, claim, provider receipt and signed canonical
acceptance. Cluster projects those decisions into a payload-free current
intent, verifies the outer production fence, and invokes only the complete
Matrix `PublicationCoordinator`. The pinned provider runs in a minimal-env
subprocess with six closed operations and fixed Wiki/state/runtime/HMK roots;
it cannot inspect Matrix custody or choose configuration from queue bytes.
Cached outer observation re-enters DM-035 exact replay/reconciliation and
reconstructs the complete Cluster receipt instead of trusting it. See
`docs/contracts/dm035-reviewed-publisher-v1.md`.

DM-036 remains unavailable until its own exact route and acceptance evidence
land. Queue-item coordination remains available because it represents no
shared external effect.

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

Curator workers use a second owner-only sidecar below
`state_dir/matrix-curator-clients/`. Its capability must contain exactly
`curator.enqueue`, `curator.claim`, `curator.complete`, and `curator.inspect`.
It is never reused by clusterd and the five-method status capability is never
expanded. Both sidecars bind the exact current origin and remain host-local;
neither is identity, review, fence or effect authority by itself.

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

Tribe Bridge remains a transitional option for ordinary human messages and its
own authenticated transport/deduplication/ACK evidence. No deployment is
assumed. It is not the Matrix
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
