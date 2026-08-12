# H10 recovery-quorum rebirth verification receipt

Date: 2026-08-12. Candidate only; local, synthetic, not deployed or
independently reviewed.

## Exact boundary

- Matrix recovery and canonical-ledger restore:
  `ac34305f01e01d23a61855b3bb8a096336dc2926`.
- Cluster install/restore/start gate:
  `6985b239051348534030994db792c5455761a340`.
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

An intentionally wrong target password left a resumable journal. Retrying the
same operation with the correct descriptor completed once; a terminal replay
did not reread the password. The admitted process reported integrity `ok` and
exactly one active fresh embodiment, retained the pre-recovery event, and
signed a new post-recovery event with fresh custody. Rebuilding a second
Cluster state from the same package and snapshot produced the same canonical
event-set hash. A byte-altered snapshot failed before Cluster state mutation.

## Gates

```text
Matrix ruff/strict mypy/compile/generators: clean (53 typed source files)
Matrix complete partition: 564 tests, 4 skipped + 30 tests, 1 skipped
Matrix installed conformance: 102/102, release_ready=true, two byte-identical runs
Cluster lint/type/compile: clean
Cluster complete suite: 474 passed, 3 skipped
Disposable encrypted exporter/offline restore: 1 passed
```

Matrix reproducible artifacts were byte-identical across two isolated builds:

- wheel:
  `2dd785b65a40cce8545b92dfe198e2908a6fdb5073c434cbc8465c662b6198ca`;
- sdist:
  `fa36bff41ef6f298a8da4770230a9fe252a4519aefe0192fe0cb70e91286964d`.

The two installed conformance reports were byte-identical at SHA-256
`dbc447b32b20be8101630e28ecad2d445762f087f7d58578eb10c7d2faf6865f`.
Their registry hash was
`37e8b791194f0d13eaa08c99b0cb8f8b52d0afba1ec792c50a95b8cb02c2bba0`,
report summary hash
`47f3b91855222488b986e7c7a11d99851a399d3810d7dc283420af9f6a10e4c8`,
and transcript hash
`593e7edebc658d69ea923a9ac4c810d7e16161dd562e03a991f0dbfe938cb157`.
Artifact and report secret scans were clean.

This qualifies the automated local Journey C boundary. It does not authorize
a live recovery or deployment. Independent review, an approved real custody
policy, content-addressed live preflight and exact same-plan human GO remain
mandatory external gates.
