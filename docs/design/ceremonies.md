# Embodiment operations and authority ceremonies

Status: active design, ontology rectified 2026-08-02.

This document governs bodies hosted by Daimon Cluster. It does not create a
being, decide whether two embodiments are one being, or manage Tribe
membership. Those are Matrix and founded-Tribe authorities respectively.

## 1. Provision a new body

1. A human requests a body, capacity, species image, and sponsor.
2. The cluster owner approves concrete host resources.
3. The steward runs `provision prepare`. The body receives a stable
   `body_ref` and new `embodiment_id`; keys are born inside its durable volume.
4. The human enters provider credentials directly. Cluster never receives
   their values.
5. `provision confirm` boots the body. Each boot opens a fresh
   `incarnation_id` segment in `embodiment-registry/v1`.
6. If this embodiment belongs in an existing being, an administrator installs
   a `being-manifest/v1` that binds its principal, body, and embodiment. Until
   future Matrix root credentials exist, this is explicit provisional trust.
7. Cluster audits completion and the embodiment may announce lifecycle state
   through Weave.

Creating a body never copies another embodiment's database or private key.
Several embodiments from one installed being manifest may run concurrently.

## 2. Park and wake

Parking quiesces writers, verifies database integrity, drains transport,
records in-flight work, snapshots durable state, and emits a signed manifest.
It closes activity for this body; it does not make other embodiments invalid.

Wake verifies the manifest and restores this body's writers. It opens or
resumes the appropriate embodiment lifecycle. Any resource that can have only
one writer requires a current `resource-fence/v1` for its exact
`resource_ref`. No identity-wide fence exists.

## 3. Relocate an embodiment

Relocation moves one body's durable volume to a replacement container or host:

1. Park and checkpoint the source.
2. Acquire/renew fences for each concrete resource being moved.
3. Restore and verify the target before starting writers.
4. Preserve `body_ref` and `embodiment_id`; open a new `incarnation_id`.
5. Emit `embodiment-relocation` with source, target, manifest digest, resource
   fence generations, and outcome.
6. Retain the old volume cold for the rollback window.

A clone is different: it receives a new body and embodiment, separate keys,
ledger, cursors, and local adoption state.

## 4. Partition and merge

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

## 5. Offboard or retire a body

1. Park, checkpoint, and verify an archive.
2. Drain/revoke transport routes and cluster tokens for the body.
3. Retire the embodiment in the installed manifest and registry.
4. Release its concrete resource fences.
5. Destroy the container/volume only after the human chooses the archive and
   key-destruction policy.

Retiring one embodiment does not dissolve its being or a Tribe. Founded-Tribe
leave/expel operations are separate signed membership artifacts.

## 6. Recovery classes

- Container lost, volume intact: rebuild around the same body and embodiment;
  open a new incarnation.
- Volume lost, verified backup intact: restore the same body only if the
  checkpoint, keys, and provenance prove it; otherwise create a new embodiment
  and explicitly import eligible history.
- Embodiment signing key lost: retire that embodiment/key. Future Matrix root
  recovery may bind a successor; Cluster must not infer identity from copied
  memories.
- Host compromise: retire/revoke affected embodiment and transport keys,
  rotate resource-fence authority, restore on a clean host, then reconcile
  Weave from independently verified peers.

Provider, transport, backup, embodiment, and future Matrix-root keys have
distinct custody and recovery paths.

## 7. Testable invariants

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
