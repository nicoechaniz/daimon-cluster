# Runbook: hosted Daimon Matrix runtime

This runbook installs the exact Matrix dependency and describes the private
material Cluster expects. It does not cover Matrix.org.

## Install and verify

From the checked-out Cluster release, create a dedicated environment and use
the committed pins:

```sh
python -m venv .venv
.venv/bin/python -m pip install -c constraints.txt -r requirements.txt
.venv/bin/python -m pytest -q tests/test_matrix_parity.py
```

The constraints file freezes the complete tested resolver set. The parity test
reads package metadata and refuses any Matrix commit other than
`clusterctl.matrix_host.MATRIX_CONTRACT_COMMIT`.
`daimon-matrix` is MIT-licensed; CI also verifies that installed package
metadata retains that license declaration.

## Per-embodiment layout

For embodiment `E`, Cluster derives opaque names rather than embedding `E` in
a path:

```text
STATE/matrix/HASH/                 portable Matrix root (0700)
  runtime.json                     public runtime bundle (0600)
  custody.json                     encrypted custody (0600)
  ledger.sqlite                    canonical ledger (0600)
  matrix.sock                      host-local, excluded from snapshot
  .daimon-matrixd.lock             host-local, excluded from snapshot
STATE/matrix-clients/HASH/         host-local clusterd client (0700)
  client.json                      capability descriptor + expected origin
  capability.key                   exactly 32 bytes (0600)
STATE/matrix-curator-clients/HASH/ host-local curator worker client (0700)
  client.json                      separate capability + expected origin
  capability.key                   separate 32-byte key (0600)
STATE/dm034-executors/HASH/         host-local HMK executor custody (0700)
  journal.sqlite                   recovery only, never memory authority (0600)
  journal.sqlite.lock              process lock (0600)
STATE/dm035-publishers/HASH/        host-local publisher custody (0700)
  runtime/                         leases/transactions/receipts (0700)
  projection/                      protected compaii-state projection (0700)
  hmk/                             derived publication index (0700)
```

Provision `client.json` with schema `dm.local.client-config/v1` for an unchanged
incarnation, or V2 after succession with the exact current origin and Matrix-
verified bounded historical origin rows. The capability contains exactly
`runtime.status`, `scope.me`, `scope.we`, `scope.we.diff`, and
`scope.we.sync-plan`. Write the raw 32-byte capability key separately. Broader
capabilities are rejected. Do not give Cluster root or recovery seeds. On
incarnation succession update the expected origin and retain each eligible
retired origin with its exact retirement millisecond. On relocation restore
the capability from separate host custody; rotate it only by updating the Matrix
bundle and encrypted custody atomically.

Only when an embodiment has a curator worker, provision the second sidecar
with exactly `curator.enqueue`, `curator.claim`, `curator.complete`, and
`curator.inspect`. Its key and descriptor must differ from the clusterd client.
The worker capability coordinates Matrix queue state; it does not grant human
review, Cluster fence mutation, identity mutation or a generic tool call.

## Start

The supervisor opens a pipe containing the keystore password, passes its read
descriptor as `--password-fd`, optionally passes a ready pipe as `--ready-fd`,
then closes its copies. Never place the password in argv, environment, a unit
file or a log.

```sh
scripts/matrix-host \
  --state-dir /var/lib/daimon-cluster \
  --embodiment-id "$EMBODIMENT_ID" \
  --password-fd "$PASSWORD_FD" \
  --ready-fd "$READY_FD" \
  --production-fence-verifier
```

The production flag requires an initialized, owner-controlled
`STATE/resource-fences.sqlite3`. It opens that database query-only and loads
only registered public verification keys. Do not pass the Cluster fence
private-key path or material to the Matrix host process. Omit the flag only for
the explicit V1 compatibility fixtures used by tests and offline migration;
that mode is not a production fence authority.

Ready is emitted only after pin/schema, owner, registry, bundle/origin, socket
length and second-writer checks pass and Matrix has loaded encrypted custody.
SIGTERM/SIGINT quiesces the service boundary.

For a target admitted by `rebirth-install`, run the H8 foreground supervisor
instead of invoking `matrix_host` directly:

```sh
python -m clusterctl.rebirth_host \
  --state-dir /var/lib/daimon-cluster \
  --embodiment-id "$EMBODIMENT_ID" \
  --password-fd "$PASSWORD_FD" \
  --ready-fd "$READY_FD" \
  --production-fence-verifier
```

It accepts only a completed exact H7 install receipt, admits the signed initial
incarnation, starts the ordinary Matrix host child, and emits ready only after
authenticated status, local-origin, body-state and complete active-manifest
checks. A password failure or crash before ready is retried against the same
open journal; do not stop/restart the registry with a generated incarnation.
Keep the state path short enough for the derived Unix socket and use the same
foreground service supervision/cgroup rules as the ordinary host process.
For a rollout spanning physical hosts, follow
[`distributed-rebirth.md`](distributed-rebirth.md); direct H7 installation is
not a substitute for its per-predecessor restart/acknowledgement and exact
target-admission gate.

The host injects the current Cluster fence verifier and a closed effect-truth
router. Without an explicitly constructed executor its route list is empty and
resource-fenced completion remains `effect_truth_unverifiable`. H5's only HMK
registration is the `DM034ProjectionExecutor.route` coordinate
`(cluster-dm034-hmk/v1, memory-projection, hmk)`. Construct it with fixed
per-embodiment HMK checkout/base, content resolver, Matrix adapter and journal;
none may come from queue bytes or environment-selected dispatch. Do not
configure a wildcard or receipt-trusting fallback.

The HMK checkout must be clean at the exact Matrix-pinned commit and the base
must be owner-only. The closed transport exports only its fixed instance/base
and a minimal non-secret environment, sets umask 077, accepts five DM-034
operations, and collapses diagnostics to stable codes. Before a canary, run:

```sh
PYTHONPATH=. .venv/bin/python scripts/h5-hmk-projection-drill.py \
  --hmk-checkout /opt/hermes-memory-kit-dm034
```

The drill uses synthetic bytes and temporary bases. Its receipt reports only
booleans, exact commits, stable hashes, byte counts and SQLite integrity—not
paths, statements, database contents or credentials.

H6's only publisher registration is
`(cluster-dm035-publisher/v1, publication, publication)`. Construct the
executor with one exact Matrix `PublicationCoordinator`, a fixed resource
fence and an owner-local publisher root. The provider transport additionally
receives a fixed owner-controlled Wiki root and clean detached checkouts at
compaii-state `cf56e9de703f68f44b85fdf21f503d55a5557984` and HMK
`f10fd5c3089c0962920314c97e14bc024feffa7a`. The checkout roots/files must not
be group/other writable.

The provider is not imported into the Matrix host. Each closed operation runs
in a child process with a minimal non-secret environment and umask 077. The
child receives only fixed host configuration plus the DM-035 logical document,
and stdout/stderr/time are bounded. Before a canary, run:

```sh
PYTHONPATH=. .venv/bin/python scripts/h6-reviewed-publication-drill.py \
  --provider-checkout /opt/compaii-state-dm035 \
  --hmk-checkout /opt/hermes-memory-kit-dm034
```

This synthetic drill must report plan parity, exact replay, current effect
reconciliation, concurrent publisher refusal and unchanged unrelated target.
It does not authorize a live Wiki/state publication. A real canary still needs
an exact current Matrix request and independent human review of its final byte
hash.

## Snapshot and restore

Stop the daemon, call `create_portable_snapshot`, transfer the resulting closed
directory, and call `restore_portable_snapshot` into a nonexistent target.
Recreate `STATE/matrix-clients/HASH/` and, when applicable,
`STATE/matrix-curator-clients/HASH/` on the destination; neither may appear in
the snapshot. Start the daemon and require authenticated `runtime.status`,
`/me`, `/we`, cursor, curator queue and authority-epoch checks before routing
traffic.

The host boundary accepts the additive Matrix runtime bundle line V1 through
V7 at the pinned commit. V3 enables native peer transport, V4 adds species,
V5 adds attributed sources, V6 adds relationships and grants, and V7 adds
configured peer targets; all remain owned and interpreted by Matrix. Any
commit/schema mismatch, unsafe path, altered hash, registry/origin drift,
stale resource epoch or missing local capability is a refusal. Preserve the
source and destination state roots for diagnosis; do not rewrite either
ledger.
