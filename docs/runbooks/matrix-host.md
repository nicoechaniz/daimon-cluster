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
```

Provision `client.json` with schema `dm.local.client-config/v1`, the descriptor
of a capability containing exactly `runtime.status`, `scope.me`, `scope.we`,
`scope.we.diff`, and `scope.we.sync-plan`, and the exact current Matrix
`local_origin`. Write the raw 32-byte capability key separately. Broader
capabilities are rejected. Do not give Cluster root or recovery seeds. On
incarnation succession update the expected origin. On relocation restore the
capability from separate host custody; rotate it only by updating the Matrix
bundle and encrypted custody atomically.

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
  --ready-fd "$READY_FD"
```

Ready is emitted only after pin/schema, owner, registry, bundle/origin, socket
length and second-writer checks pass and Matrix has loaded encrypted custody.
SIGTERM/SIGINT quiesces the service boundary.

## Snapshot and restore

Stop the daemon, call `create_portable_snapshot`, transfer the resulting closed
directory, and call `restore_portable_snapshot` into a nonexistent target.
Recreate `STATE/matrix-clients/HASH/` on the destination; it must not appear in
the snapshot. Start the daemon and require authenticated `runtime.status`,
`/me`, `/we`, cursor and authority-epoch checks before routing traffic.

The host boundary accepts the additive Matrix runtime bundle line V1 through
V5 at the pinned commit. V3 enables native peer transport, V4 adds species and
V5 adds attributed sources; all remain owned and interpreted by Matrix. Any
commit/schema mismatch, unsafe path, altered hash, registry/origin drift,
stale resource epoch or missing local capability is a refusal. Preserve the
source and destination state roots for diagnosis; do not rewrite either
ledger.
