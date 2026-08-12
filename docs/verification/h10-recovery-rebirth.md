# H10 recovery-quorum rebirth verification receipt

Date: 2026-08-12. Candidate only; local, synthetic, not deployed or
independently reviewed.

## Exact boundary

- Matrix recovery and canonical-ledger restore:
  `24a0ac665088550ec91529cdbd92af7721ba2adb`.
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
fresh embodiment with no peer targets. Cluster accepted only a portable
snapshot whose exact Matrix commit, manifest, origin, file names, sizes and
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
Cluster complete suite: 473 passed, 3 skipped
Disposable encrypted exporter/offline restore: 1 passed
```

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

This qualifies the automated local Journey C boundary. It does not authorize
a live recovery or deployment. Independent review, an approved real custody
policy, content-addressed live preflight and exact same-plan human GO remain
mandatory external gates.
