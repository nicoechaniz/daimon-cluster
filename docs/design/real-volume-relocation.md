# Real durable-volume relocation

Status: implemented candidate for issue #66; not enabled on a live host.

## Custody invariant

Relocation moves one existing Incus custom volume; it never creates or copies
a replacement home. The volume contains embodiment keys and owner-local
state, so Cluster may observe metadata, attachment truth and public
fingerprints but never reads private-key bytes. Git, audit, the operation
journal and transfer receipts contain no state payload or private material.

Incus 6.0 does not expose a custom-volume UUID. Cluster therefore derives an
operational identity from the exact pool, project, name, type, content type
and creation timestamp returned by `incus storage volume show`. Every
attachment is reconciled against the corresponding unexpanded instance
device. Unknown `used_by` references, a different device/path, read-only
drift, multiple attachments or an identity change fail closed.

## Closed transition

Both source and target locks are acquired in stable name order. Before any
target state exists, the outer H2 journal binds:

- source and target names;
- exact volume identity, device `home` and mount `/home/agent`;
- verified checkpoint-manifest hash;
- immutable resource-fence coordinate `{resource_ref, epoch, proof, current}`.

The inner transfer journal then creates the target spec and stopped container
without a home device, detaches the stopped source, attaches the same volume
to the stopped target, and verifies identity plus exactly one writable target
attachment. A fence transition must commit the exact successor coordinate
before `start`. Post-start observation repeats identity and attachment checks;
fixture adapters additionally bind a content hash. State-file restore verifies
each manifest hash before writing.

Create, start, detach and attach are observe-first. A successful substrate
effect followed by response loss is adopted only when the exact postcondition
is visible. Transfer reserves one intended incarnation id before start;
registry/spec reconciliation reuses it and refuses any different running
incarnation.

The production acceptance path accepts the H1 `ResourceFenceStore.production`
backend and a holder-authorized transition callback. The deployed CLI remains
on the explicit compatibility backend until H1 signing custody and holder
authorization are activated together; there is no implicit production
fallback.

## Rollback and degradation

Rollback first closes the intended target incarnation and stops the target.
It then detaches the exact target volume, reattaches it to the stopped source,
and verifies one source attachment with the original identity. Only after
that proof may it delete the target container and spec. A fence transition is
monotonic: rollback verifies and preserves the committed signed successor,
never restores predecessor bytes or lowers the high-water. If any
attachment, identity, stop, deletion or fence condition cannot be proven, the
outer journal remains `degraded`, the target remains stopped, and no generic
repair guesses custody.

## Operational drill

`scripts/h3-volume-drill.py` accepts only an explicit `h3-*` prefix and is a
plan unless `--execute` is present. It collision-checks exact names, creates
two stopped scratch containers and one custom volume, and crosses every Incus
storage boundary through a fresh Python process. It simulates lost detach and
attach responses, verifies the same state hash and public-key fingerprint on
the target, rolls the volume back to the source, re-verifies bytes, and removes
only the exact scratch resources in `finally`.
