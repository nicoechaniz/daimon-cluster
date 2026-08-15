# H10 recovery-quorum rebirth verification receipt

Date: 2026-08-12. Candidate only; local, synthetic, not deployed or
independently reviewed.

## Exact boundary

- Matrix recovery and canonical-ledger restore:
  `306900c64aac5b0aa6ca062e777ca5ea2686d84e`.
- Cluster install/restore/start gate: this H10 branch, stacked directly on
  PR #85 at `9e6100baba705394ad9dc40ffbd38d721bc7e41d`.
- Collective-memory contract:
  `3e3b39416917f8e3c2bc5ca69362b20296205938`.
- Hermes Memory Kit contract:
  `f10fd5c3089c0962920314c97e14bc024feffa7a`.

All ceremonies used temporary owner-only directories and synthetic keys. No
SSH connection, production state, live authority, administrative access or
external host was used. Mona was categorically excluded.

## Recovery result

The synthetic recovery quorum revoked every active predecessor, rotated to
fresh root custody with no old root seed retained, and authorized exactly one
fresh embodiment with no peer targets. The source first verified its complete
portable snapshot, then derived a custody-free recovery transfer containing
only the public runtime bundle and canonical ledger. Cluster accepted only a
transfer whose exact Matrix commit, manifest, origin, file names, sizes and
SHA-256 values matched the recovery activation.

The target installed stopped. A direct start before restore failed with
`rebirth_host_recovery_restore_missing`. Matrix copied the predecessor ledger
to an owner-only scratch file, rechecked its manifest-bound size and hash, and
read it under the predecessor authority without modifying the snapshot. It
then ingested only canonical events through the verified recovery history.
The fresh runtime bundle, embodiment custody and transport custody remained
byte-identical; predecessor custody, runtime configuration, derived stores and
transport/RPC journals were not copied.

Before Cluster creates or mutates target state, it freezes only the manifest-
bound public runtime bundle and canonical ledger into owner-only scratch using
stable `O_NOFOLLOW` descriptors, inode/device checks and streaming SHA-256.
An injected ledger-to-symlink swap between verification and staging was
rejected before the state directory existed, and scratch cleanup was proven.
The scratch is a process-owned private directory outside both the imported
snapshot and the prospective Cluster state (using the target parent only when
it is already owner-only and writable), so a snapshot transfer mounted
read-only remains a valid recovery source without mutating target state before
verification.

An intentionally wrong target password left a resumable journal. Retrying the
same operation with the correct descriptor completed once; a terminal replay
did not reread the password. The admitted process reported integrity `ok` and
exactly one active fresh embodiment, retained the pre-recovery event, and
signed a new post-recovery event with fresh custody. Rebuilding a second
Cluster state from the same package and snapshot produced the same canonical
event-set hash. A byte-altered snapshot failed before Cluster state mutation.

## Gates

```text
Matrix ruff/strict mypy/compile/generators: clean (56 checked files)
Matrix complete partition: 531 tests, 4 skipped + 30 tests, 1 skipped
Matrix installed conformance: 98/98, release_ready=true, two byte-identical runs
Cluster lint/type/compile: clean
Cluster complete suite: 477 passed, 4 skipped
Installed recovery boundary on Python 3.11/3.12/3.14: Matrix 18 + Cluster 7 each
Disposable encrypted exporter/offline restore: 1 passed
Disposable no-network recovery roles/read-only restore: 1 passed
```

The disposable recovery-host job builds a pinned Python 3.13.5 image from an
exact verified Git bundle of Matrix `24a0ac`, then runs trusted bootstrap,
source full-snapshot verification/custody-free export, offline-root
recovery/authorization, target preparation and target restore as separate
containers. Every container has a read-only root
filesystem, no network, no Linux capabilities and only its explicit role
mounts. The bootstrap staging is destroyed before recovery begins; the target
receives only the two-file recovery transfer read-only, starts with exactly one fresh active
embodiment, retains the old canonical event and signs a new event. Passwords
and custody files are absent from the public exchange. This is strong
filesystem/process isolation on disposable infrastructure, not evidence of
independent physical hardware or a live custody ceremony.

The Matrix checkout used to construct that offline bundle must contain full
history (`fetch-depth: 0`). The integration proof explicitly rejects a shallow
source before bundle construction. This prevents a checkout that names the
right Matrix head but omits a required ancestor from producing a locally
unclonable bundle inside the build container.

Matrix reproducible artifacts were byte-identical across two isolated builds:

- wheel:
  `8ed3fee727a136067b65b389061a538cfbd18b16825162bc831c02cf82a06373`;
- sdist:
  `355ce1d65b8cc3b04025e84235ccf66f19f7a1def1a3d68cf673bcbfe106b6db`.

The two installed conformance reports were byte-identical at SHA-256
`b7848eaa2d6f12486ca8d9fea852a3a9907c0dfe7024c34e34707942da3a69a7`.
Their registry hash was
`91330eb27b97e7b7e71532f1f802d1f6a24f99bbab6ac209d8865d1df4f64234`,
report summary hash
`a434c7134607e73a884d8a43878f74828bb4d2dd7d29fa0eb429dc5c8dd9e9ce`,
and transcript hash
`f777b397f3bbb95cd0c5500c57cc6952f5579f9602e294ab97c9e84343f938ba`.
Artifact and report secret scans were clean.

The installed conformance also exercises two-being recipient encryption,
authenticated intake, route ACK versus semantic-delivery separation, signed
terminal receipts, bilateral relationship consent and replay-safe native peer
transport. That is the reproducible replacement boundary; it is not evidence
that the separately consented real cross-being canary has happened. Tribe
Bridge therefore remains a transitional human-message carrier until that
external canary, review and explicit migration/archive decisions complete.

This qualifies the automated local Journey C boundary. It does not authorize
a live recovery or deployment. Independent review, an approved real custody
policy, content-addressed live preflight and exact same-plan human GO remain
mandatory external gates.
