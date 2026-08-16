# Embodiment operations and authority ceremonies

Status: active design, ontology rectified 2026-08-16.

This document governs bodies hosted by Daimon Cluster. It does not create a
being, decide whether two embodiments are one being, or manage Tribe
membership. Those are Matrix and founded-Tribe authorities respectively.

## 1. Generic instances are not embodiments

`clusterctl create|start|stop|restart` manages only an
`instance_kind: generic-instance`. These commands never mint a `body_ref`,
`embodiment_id`, incarnation, being binding, Matrix credential, or registry
entry. A spec containing any Matrix identity marker is rejected before a
runtime adapter call. Generic runtime state is operational inventory, not
evidence of identity.

An embodiment is admitted only through the root-authorized installation and
`rebirth_host` path. That path verifies the Matrix credential and activation,
acquires shared hosting admission before any spawn, and owns incarnation
creation. Converting an arbitrary generic instance into an embodiment is not a
supported lifecycle transition.

## 2. Provision a new body

1. A human requests a body, capacity, species image, and sponsor.
2. The cluster owner approves concrete host resources.
3. The steward runs `provision prepare` for a generic stopped body and its
   host-local material. This step does not grant Matrix identity.
4. The human enters provider credentials directly. Cluster never receives
   their values.
5. `provision confirm` may boot only the generic workload.
6. A distinct Matrix ceremony creates a root-authorized credential for a new
   `body_ref` and `embodiment_id`, with keys generated in that embodiment's
   custody. Cluster installs that exact artifact through `rebirth_host`; no
   provisional or locally invented identity is accepted.
7. Shared admission opens the first `incarnation_id`; Cluster audits the
   admitted launch and the embodiment may announce lifecycle state through
   Weave.

Creating a body never copies another embodiment's database or private key.
Several embodiments from one installed being manifest may run concurrently.

## 3. Park and wake

Parking quiesces writers, verifies database integrity, drains transport,
records in-flight work, snapshots durable state, and emits a signed manifest.
It closes activity for this body; it does not make other embodiments invalid.

Wake verifies the manifest and restores this body's writers. It opens or
resumes the appropriate embodiment lifecycle. Any resource that can have only
one writer requires a current `resource-fence/v1` for its exact
`resource_ref`. No identity-wide fence exists.

## 4. Relocate an embodiment

Relocation moves one body's durable volume to a replacement container or host:

1. Park and checkpoint the source.
2. Lock both names and bind the exact checkpoint, volume identity, attachment
   and production fence position in a durable operation journal.
3. Create the target stopped without a new home, detach the stopped source,
   and attach that same existing volume to the stopped target.
4. Verify one writable target attachment and commit the exact fence successor
   before the target can start.
5. Start the target, verify the same volume/bytes again, preserve `body_ref`
   and `embodiment_id`, and open one preallocated `incarnation_id`.
6. Emit `embodiment-relocation` with source, target, manifest digest, resource
   fence generations, and outcome.
7. Retain the old source container cold for the rollback window; the volume is
   not copied and exists as one attached object.

A clone is different: it receives a new body and embodiment, separate keys,
ledger, cursors, and local adoption state.

## 5. Partition and merge

A network partition is not an identity emergency. Each embodiment continues
its signed local origin chain. When transport heals:

1. Exchange heads and request bounded deltas.
2. Preview the exact missing events without applying provider effects.
3. Pull atomically; persist peer cursors only with committed events.
4. Resume from the durable cursor after interruption.
5. Verify bidirectional event-set convergence and preserved origin.
6. Re-sync and prove no duplicate events or effects.

Conflicting proposals remain visible differences. Every embodiment decides
locally whether to adopt, reject, defer, or revert them.

## 6. Offboard or retire a body

1. Park, checkpoint, and verify an archive.
2. Drain/revoke transport routes and cluster tokens for the body.
3. Retire the embodiment in the installed manifest and registry.
4. Release its concrete resource fences.
5. Destroy the container/volume only after the human chooses the archive and
   key-destruction policy.

Retiring one embodiment does not dissolve its being or a Tribe. Founded-Tribe
leave/expel operations are separate signed membership artifacts.

## 7. Recovery classes

- Container lost, volume intact: rebuild around the same body and embodiment;
  open a new incarnation.
- Volume lost, verified backup intact: restore the same body only if the
  checkpoint, keys, and provenance prove it; otherwise create a new embodiment
  and explicitly import eligible history.
- Embodiment signing key lost: retire that embodiment/key. Matrix root/recovery
  authority may issue the explicit supported successor; Cluster must not infer
  identity from copied memories.
- Host compromise: retire/revoke affected embodiment and transport keys,
  rotate resource-fence authority, restore on a clean host, then reconcile
  Weave from independently verified peers.

Provider, transport, backup, embodiment, and Matrix root/recovery keys have
distinct custody and recovery paths.

When a Matrix recovery quorum intentionally replaces every active embodiment,
Cluster installs the fresh target and restores only events that verify through
the signed recovery history. Predecessor custody and runtime configuration are
never restored. A distinct completed restore journal gates first start, and an
exact retry must reproduce the same canonical event-set hash.

## 8. Testable invariants

- No provider credential enters git, audit, Weave, or steward payloads.
- No new body reuses an embodiment id or private signing key.
- Restart preserves embodiment and changes incarnation.
- Two embodiments of one being may be running simultaneously.
- Only equal concrete `resource_ref` values contend for CAS/TTL fencing.
- A failed transfer restores the previous resource holder or remains safely
  parked; it never starts two writers for the same volume.
- Partitioned ledgers converge after healing without losing origin or
  duplicating events/effects.
- Cluster transport authentication is never treated as Matrix being proof or
  founded-Tribe membership authority.
