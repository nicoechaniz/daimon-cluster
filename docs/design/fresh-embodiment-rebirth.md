# Fresh embodiment rebirth

Status: H7 candidate contract. It creates another embodiment of the same
being; it does not clone an existing embodiment or copy its private custody.

## Authority and custody split

Matrix owns the signed `dm.we.embodiment-enrollment/v1` transition. The target
generates a new signing key, encryption key, transport key and capability key
inside owner-only encrypted custody. Its public request proves possession with
separate body and transport signatures. Offline root custody signs only that
public request. Neither Cluster nor the offline root process receives the
target private keys, and the target never receives root custody.

The root-signed activation binds the exact previous and successor manifests,
request, body, embodiment, incarnation, principal and public credentials. It
adds exactly one active embodiment and leaves every prior row byte-identical.
The activated target package contains a loadable Matrix V7 runtime with empty
writable history, its own local origin and a host-local least-authority client.

## Cluster installation

`clusterctl rebirth-install` accepts the activated owner-only package plus the
exact runtime root of every existing active embodiment. Before mutation it
checks the installed Matrix Git pin, root activation, package receipt, runtime
hash, empty-state assertion, target origin, target profile and complete peer
set. A peer may carry the previous manifest or the exact successor, allowing a
retry after a partial forward update; any third state fails closed.

The operation holds the target and all peer locks in stable order. It installs
the target runtime and client atomically, advances each old peer to the signed
successor, and registers the target as stopped with no current Cluster
incarnation. Its SQLite operation record crosses planned, dispatched, applied,
logical, audited and completed states. A crash or lost response at every
mutation boundary resumes the same operation. The signed activation and the
caller idempotency key are both durable identities, so concurrent or renamed
retries produce one result and one audit event.

Example shape (identifiers and paths must come from the verified package and
current peer inventory):

```text
clusterctl --state-dir STATE rebirth-install \
  --package-dir TARGET_PACKAGE \
  --peer EMBODIMENT_A=RUNTIME_A \
  --peer EMBODIMENT_B=RUNTIME_B \
  --idempotency-key UUID --json
```

## Deliberate stopped boundary

H7 success is `installed-stopped`, not a running daemon. It has changed accepted
authority on disk and admitted the physical body, but it has not claimed that
the target process is reachable. H8 provides the separate foreground
`python -m clusterctl.rebirth_host` supervisor. It resolves the exact completed
H7 receipt from Cluster's journal, binds the registry to the root-authorized
target incarnation, supplies the target password only by inherited descriptor,
waits for Matrix readiness, and authenticates `runtime.status`, `/me` and `/we`
before emitting its own `READY` or completing the start receipt.

If the child refuses before readiness, the start journal remains at
`runtime-dispatching` and the exact admitted incarnation remains the only
permitted retry. The supervisor never invents a replacement incarnation and
never reports healthy from registry state alone. A later supervisor restart
reopens the same completed receipt, starts a new process over the same durable
runtime, and redoes all authenticated observations; the Matrix writer lock
still rejects a concurrent second daemon.

Prior peers must be restarted or reloaded from the H7-updated bundles before
the convergence gate. The disposable H8 journey runs all three real daemon
processes, exchanges one event in each direction through native encrypted peer
pull, repeats the exact request without a second import, and proves both remote
events remain pending until an observer explicitly adopts them.

Rollback before target start is a whole-candidate rollback: stop admission,
preserve every runtime and journal, and restore the previous release. Never
rewrite the signed successor as if enrollment had not occurred. Removing an
authorized embodiment requires a later root-signed authority transition.
