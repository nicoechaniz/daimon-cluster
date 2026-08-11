# Distributed fresh-embodiment rollout

Status: H9 design candidate. H7/H8 prove the authority, custody and process
contract under one Cluster state; this document closes the physical-host gap.

## Why the local transaction is insufficient

An existing embodiment's Matrix root belongs to its current physical host.
Copying that root to the target merely to update `runtime.json` would copy
custody and writable state across embodiments and violate the boundary H7 was
built to protect. A real rollout therefore has one target-only package and a
separate public rollout bundle that every existing host can apply locally.

The rollout is forward-only. Once any running peer accepts the root-signed
successor, failure recovery continues toward that successor or a later signed
successor. No operator may restore the previous manifest as current merely to
make a deployment look rolled back.

## Public rollout bundle

The target preparation exports no custody to peers. Its public rollout bundle
contains only:

- the root-signed activation and target profile;
- request, activation, previous and successor manifest identifiers;
- target being/body/embodiment/incarnation and advertised endpoint;
- the exact sorted set of existing active embodiment IDs;
- the Matrix contract commit and target public runtime hash; and
- a content-derived rollout ID over every field above.

Each host revalidates the activation against its own current Matrix authority.
The bundle is not new identity authority: a changed endpoint, participant,
manifest, commit or activation changes the rollout ID and is refused.

The canonical `dm.cluster.distributed-rebirth-rollout/v1` document is closed.
It carries the public activation verbatim, the target's public profile, the
previous and successor manifest hashes, the target origin, the sorted
predecessor IDs, the exact Matrix commit and the target runtime hash published
by the target-only receipt. `rollout_id` is a domain-separated SHA-256 of the
rest of that document. Runtime/custody directories, encrypted keystores,
client keys, passwords and filesystem paths are never bundle fields.

## Per-peer state machine

For each existing active embodiment, its local Cluster performs:

```text
planned -> runtime-dispatching -> runtime-applied
        -> logical-committed -> audited -> completed
```

`runtime-applied` means the owner-only local bundle durably contains the exact
successor and target endpoint; it does not claim the running process reloaded
those bytes. The operator then restarts that one daemon with its existing
custody. Completion requires an authenticated local `runtime.status`, `/me`
and `/we` observation proving integrity, unchanged local origin, successor
manifest and the target as an active configured peer.

The resulting acknowledgement contains no key or payload. It binds rollout,
host-local embodiment, unchanged incarnation, successor manifest, observed
runtime hash and journal/audit IDs. Its delivery must use the already
authenticated operator plane (for the V0 drill, pinned SSH host keys); the
acknowledgement is deployment evidence, not Matrix authority.

Application and acknowledgement are deliberately separate calls. `apply`
durably advances the local runtime bundle and leaves its journal open at
`runtime-applied`. The host service manager must then stop and start that exact
daemon. `ack` talks to the restarted daemon through its existing owner-only
status client and is the only operation that can advance the journal through
logical commit, audit and completion. Losing either response is safe: replay
resolves the exact open journal by rollout and local embodiment.

## Target gate

The target host installs only its separately encrypted target package. It may
prepare and validate that package before peer rollout, but H8 refuses to admit
or start it until it receives one exact completed acknowledgement for every
participant in the rollout bundle. Duplicate acknowledgements must be
byte-identical; missing, extra, previous-manifest, wrong-origin or wrong-rollout
rows fail closed.

Admission itself is durable. The target host records one closed
`dm.cluster.distributed-rebirth-admission/v1` object containing the rollout and
the exact sorted acknowledgement set. H8 checks that content-derived admission
before changing Registry state or opening the target password descriptor; a
caller cannot bypass the gate by invoking the lower-level supervisor directly.

After all acknowledgements, H8 starts the target and requires its authenticated
active set to equal the rollout set plus itself. Native pull must succeed in
both directions with pending-before-adoption semantics before the rollout is
declared converged.

## Failure and recovery

- Before any peer update, discard the public rollout and target package.
- After a peer bundle update but before restart, retry that same host; its
  bundle may already be the exact successor.
- After peer restart, retain its acknowledgement and continue remaining hosts.
- If a host is unavailable, keep the target stopped and report the exact
  incomplete participant set. Existing successor peers remain valid but may
  report partial topology.
- If the target cannot become ready, retain all journals and custody, keep the
  signed successor current and repair/retry the same incarnation.
- Removing the target requires a new root-signed retirement/revocation
  transition and another distributed rollout. Deleting files or restoring the
  previous manifest is not rollback.

The focused suite injects response loss around peer operations. The disposable
acceptance journey uses synthetic authority and custody on two physical hosts,
proves no private target bytes reach a peer, exercises terminal replay and
removes only its exact temporary roots. Its redacted receipt is
[`../verification/h9-distributed-rebirth.md`](../verification/h9-distributed-rebirth.md).
A live same-being rollout remains gated by the DM-078 content-addressed
preflight and same-plan human GO.
