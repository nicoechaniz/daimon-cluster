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

Admission is rechecked immediately before and after the registry start and at
the spawn boundary. If it is lost before spawn, the exact just-created
incarnation is removed with a guarded compensation and that compensation is
persisted in the open operation journal. A compensation precondition failure
marks the operation degraded instead of leaving a false stopped claim.

The same transport also exposes `FenceMutationClient` for concrete writable
resources. A host persists a holder-signed prepared mutation (exact resource,
predecessor epoch/proof, nonce and expected successor) before asking the
authority to commit it. Before any retry submits a CAS, it reads the authority
and adopts only the already-signed successor whose `authorization_ref` hashes
those exact prepared bytes. Park
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
