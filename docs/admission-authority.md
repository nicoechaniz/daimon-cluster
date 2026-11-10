# Shared embodiment admission authority

`clusterctl.admission` is the V0 launch-fencing boundary for fresh embodiments.
It is a separate service whose SQLite database, trusted clock high-water and
Ed25519 authority key are not available to host clients. The Unix transport is
explicitly a same-host fixture. The TCP transport is the purpose-built,
network-capable endpoint for independent hosts; every response and every
session request is authenticated at the application layer with Ed25519.

The exclusion coordinate is exactly `(being_ref, embodiment_id)`. Two active
embodiments of the same being therefore remain legitimate, while copied state
directories or hosts trying to launch the same embodiment credential contend
for one lease. Each launch generates an in-memory-only Ed25519 session key and
derives `session_id` from its fingerprint; a copied holder key and copied
session id cannot renew or release another launch session's lease.

Holder keys are never trusted on first use. A configured Matrix registrar must
sign an exact enrollment binding the holder key to the being, body,
embodiment, incarnation, activation, credential and manifest. Every acquire,
renew and release has a short-lived holder signature over the exact CAS
position. The authority returns a signed receipt containing the fencing token,
proof hash, holder/session coordinates and expiry.

The registrar configuration is an exact desired set, not an additive startup
hint. A restart fails closed if an active database registrar is omitted or any
key differs. Registrar changes use a compare-and-swap generation high-water;
`transition_registrars` adds a successor explicitly and `revoke_registrar`
records revocation before a process can reopen with the new exact set.

`clusterctl.rebirth_host` fails before registry or process effects if
the client configuration, enrollment, authority, authorization or lease is
missing. Its supervisor terminates the runtime with SIGKILL on the first failed
renewal. Each successful authority round trip establishes a conservative local
deadline from its monotonic start plus the signed TTL; the remote absolute
expiry is evidence, never a scheduling clock. Renewal begins after one quarter
of that interval, each of its two possible network round trips is capped at one
tenth, and an independent monotonic watchdog kills at three quarters even if
renewal I/O is stuck.
The runtime continuously verifies its exact guardian PID and kills itself if
reparented, so a killed launcher cannot leave an unsupervised child.
Normal process exit releases the lease. Authority database restart preserves
the monotonic token and trusted-clock high-water.

Bounded event-history maintenance uses the same authority's local
`--retire-history` mode, existing protected configuration and permanent
database-owner UID drop, without opening a listener or restarting admission. See
[production fence retention](design/production-resource-fences.md) for its
signed checkpoint, batch budget and unchanged position/tombstone semantics.
This candidate is not evidence of actual live retirement or receiving adoption.

Admission is rechecked immediately before and after the registry start and at
the spawn boundary. If it is lost before spawn, the exact just-created
incarnation is removed with a guarded compensation and that compensation is
persisted in the open operation journal. A compensation precondition failure
marks the operation degraded instead of leaving a false stopped claim.

The same transport also exposes `FenceMutationClient` for concrete writable
resources. A host persists a holder-signed prepared mutation whose
`authorization_ref` hashes the exact operation, resource, predecessor
epoch/proof/current state, requested fence TTL, holder authorization, nonce and
derived successor before asking the authority to commit it. Both client and
authority recalculate those bindings; editing any prepared semantic is refused.
Before any retry submits a CAS, it reads the authority and adopts only the
already-signed successor with that exact `authorization_ref`. Release recovery
uses an authority-signed last-evidence receipt, so a committed tombstone remains
recoverable after response loss or client restart while a different holder,
predecessor or authorization cannot claim it. Before returning that receipt,
the authority issues a one-use challenge bound to the new session, exact
resource/predecessor/successor, release operation and `authorization_ref`; the
enrolled holder private key must sign the complete challenge proof. A copied
public verifier, substituted session or replay therefore cannot adopt it. Park
records the authority receipt in its Ed25519-signed checkpoint manifest;
wake/transfer commit that successor before spec, create, volume or start
effects. A verifier-only local database is never a handoff mutator.

Generic-instance wake/transfer may use this handoff path. Matrix-managed
execution may not: a generic adapter cannot mint a new incarnation
authorization or keep admission alive after `clusterctl` exits. A Matrix
successor must instead be a root/activation-authorized `clusterctl
rebirth-install` artifact launched by the `python -m clusterctl.rebirth_host`
foreground supervisor. That supervisor uses an enrollment/client bound to the
new incarnation and owns renewal plus the independent monotonic kill watchdog
for the complete runtime lifetime.

This is a cooperative software guarantee, not a claim that a malicious host
cannot ignore fencing. Writable external resources must reject stale fencing
tokens, and a physical trial needs a purpose-built shared authority with
independent failure handling. A state-directory-local database is not a global
authority and must not be presented as one.

## Current admitted-body inventory

An already-running holder can explicitly call `AdmissionClient.inventory()`.
The existing authenticated transport returns `dm.cluster.admission-inventory/v1`
inside its normal authority-signed response. The request uses the existing
holder binding and actual launch-session proof. Enrollment alone, a copied
holder credential, an expired lease or a different launch session cannot read
the inventory. No new key, enrollment, worker or attention mechanism is needed.

The caller's exact current holder/session and every returned member are checked
inside the same read-only SQLite snapshot. A release or replacement before that
snapshot cannot authorize the retired session through an earlier successful
read. That snapshot verifies current admission positions and their
holder bindings. Released, revoked and expired positions are excluded; an
inconsistent signed position refuses the read instead of silently omitting a
member. Each item exposes only the being/body/embodiment/incarnation,
credential/manifest references, admission resource, fence token, proof reference
and expiry. Session identifiers, holder custody, resource contents, endpoints and
ordinary writable-resource positions are not disclosed. The read renews no
lease and changes no position, token or history.

The inventory scans at most256 current admission positions and returns at
most256 items; each signed evidence record is bounded to64KiB and the serialized
result to512KiB. `truncated=true` explicitly means the scan/item bound excluded
positions; expired positions can consume that scan bound. Do not interpret a
truncated view as a complete roster. The client validates closed fields, exact
admission resource coordinates, ordering, uniqueness and expiry at the reported
evaluation time. The existing authority request/response signature and deadline
checks still apply.

The existing inherited native observation channel also supports an explicit
`inventory` callback alongside the original body and optional surface reads.
It binds the request to the exact local body/time, verifies the current parent
admission and presence, and uses the supervisor's serialized existing session
for the authority read. H8 and relocated native parents share this implementation.
The wrapper is `dm.cluster-inventory-snapshot/v1` with separate `body` and
`inventory` evidence. Framing remains bounded to1MiB, large enough for the
512KiB authority result. An older authority refuses this optional read; ordinary
body/surface observation remains unchanged. No background refresh or alternate
transport is installed.

This supplies Cluster membership/admission evidence for Matrix domain discovery.
It does not assert that a process answered, infer Tribe membership, resolve an
OS surface or a geographical distance, or authorize input/model work. Matrix
must combine it with actual origin-bound surface observations for `/here` and
preserve unavailable/partial results. The source/API addition is not evidence
that the running authority or a receiving Matrix scope has adopted it; retain
actual selections and native results in the current delivery checkpoint.

## Required client configuration

Each installed target needs an owner-only `admission-client.json` containing:

- schema `dm.cluster.admission-client/v1`;
- an explicit `unix-local-fixture` path or `tcp-authenticated` host/port
  endpoint and the pinned authority public key/id;
- the target-owned holder private-key path and enrolled key id; and
- a lease TTL between 3 and 300 seconds.

The authority is started separately with `python -m clusterctl.admission`, an
owner-only state directory, its authority key, a pinned registrar public key,
and exactly one endpoint: `--socket` for a same-host fixture, or
`--listen-host` plus `--listen-port` for an authenticated network endpoint.
Enrollment is an explicit signed provisioning step; runtime never creates
synthetic holders or authority state as a fallback. Test helpers that generate
all roles are named `synthetic` or `disposable` and operate only below temporary
test roots.
