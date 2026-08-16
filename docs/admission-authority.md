# Shared embodiment admission authority

`clusterctl.admission` is the V0 launch-fencing boundary for fresh embodiments.
It is a separate owner-only Unix service whose SQLite database, trusted clock
high-water and Ed25519 authority key are not available to host clients.

The exclusion coordinate is exactly `(being_ref, embodiment_id)`. Two active
embodiments of the same being therefore remain legitimate, while copied state
directories or hosts trying to launch the same embodiment credential contend
for one lease. Each launch also has an ephemeral `session_id`; a copied holder
key cannot renew or release another launch session's lease.

Holder keys are never trusted on first use. A configured Matrix registrar must
sign an exact enrollment binding the holder key to the being, body,
embodiment, incarnation, activation, credential and manifest. Every acquire,
renew and release has a short-lived holder signature over the exact CAS
position. The authority returns a signed receipt containing the fencing token,
proof hash, holder/session coordinates and expiry.

`clusterctl.rebirth_host` fails before journal, registry or process effects if
the client configuration, enrollment, authority, authorization or lease is
missing. Its supervisor renews after one third of the lease and terminates the
runtime on the first failed renewal, before the last verified lease expires.
Normal process exit releases the lease. Authority database restart preserves
the monotonic token and trusted-clock high-water.

This is a cooperative software guarantee, not a claim that a malicious host
cannot ignore fencing. Writable external resources must reject stale fencing
tokens, and a physical trial needs a purpose-built shared authority with
independent failure handling. A state-directory-local database is not a global
authority and must not be presented as one.

## Required client configuration

Each installed target needs an owner-only `admission-client.json` containing:

- schema `dm.cluster.admission-client/v1`;
- the authority Unix socket and pinned authority public key/id;
- the target-owned holder private-key path and enrolled key id; and
- a lease TTL between 3 and 300 seconds.

The authority is started separately with `python -m clusterctl.admission`, an
owner-only state directory, its authority key, and a pinned registrar public
key. Enrollment is an explicit signed provisioning step; runtime never creates
synthetic holders or authority state as a fallback. Test helpers that generate
all roles are named `synthetic` or `disposable` and operate only below temporary
test roots.
