# Runbook: second encrypted off-host mirror

This procedure adds a pull-only ciphertext copy of the checked local restic
repository. It does not give the mirror host the restic password, Matrix
custody, Cluster authority, a general source shell, or access outside the
repository. Target 2 must be in a failure domain independent from target 1.

## Preflight

Record the source repository size and latest snapshot ID, a successful source
`restic check`, target free space, exact source and target host-key pins, the
target account, paths and deployed commit. Stop if target ownership or storage
approval is absent, either host is untrusted, the target shares target 1's
site/power/network failure domain, or the source check is not green.

The mirror is only a recovery copy. Keep the repository password in the
separate offline recovery escrow; never install it on a ciphertext-only mirror.

## One-time target preparation

On the target, create a service identity and generate a key locally. The
private key never leaves the target:

```sh
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin \
  daimon-backup
sudo install -d -o root -g root -m 0700 /etc/daimon-backup
sudo install -d -o daimon-backup -g daimon-backup -m 0700 \
  /srv/daimon-backups/daimonmatrix /srv/daimon-backups/receipts
sudo ssh-keygen -q -t ed25519 -N '' \
  -C daimon-restic-mirror-target2 \
  -f /etc/daimon-backup/daimonmatrix.key
sudo chmod 0600 /etc/daimon-backup/daimonmatrix.key
```

Transfer only the `.pub` line to the source through the approved operator
channel. Pin the source host key independently into
`/etc/daimon-backup/daimonmatrix.known-hosts`; do not use `accept-new`.

## Source read-only authorization

Keep the current source session open for recovery. Build a sibling candidate
from the complete existing `authorized_keys` plus exactly one target-specific
key; never overwrite the file from only the new public fragment. The forced
command must preserve the original rsync request across `sudo` so `rrsync` can
validate it:

```text
restrict,command="sudo -n env SSH_ORIGINAL_COMMAND=\"$SSH_ORIGINAL_COMMAND\" /usr/bin/rrsync -ro /var/lib/daimon-cluster/restic-repo"
```

Before the atomic rename, require the candidate line count to equal the old
count plus one, preserve owner/mode, and keep a byte-identical backup beside
it. From a second fresh connection, prove both that the operator's original
key still opens the host and that the mirror key rejects `id`/shell while an
rsync sender request succeeds. Restore the backup through the first open
session on any failure. Only then close that session.

The mirror key must have no other authorization. `rrsync -ro` constrains every
request to sender mode below that exact repository. Revoke only this exact
line to remove target access; do not grant a shell or a broad rsync sudo
command.

## Install and verify

Install the reviewed checkout at `/opt/daimon-cluster`, the service/timer
templates in `/etc/systemd/system`, and a root-owned mode-0600 environment:

```text
MIRROR_SOURCE=debian@daimonmatrix.altermundi.net
MIRROR_DEST=/srv/daimon-backups/daimonmatrix
MIRROR_RECEIPT=/srv/daimon-backups/receipts/daimonmatrix.json
```

Then run one foreground service attempt before enabling the timer:

```sh
sudo systemctl daemon-reload
sudo systemctl start daimon-restic-mirror@daimonmatrix.service
sudo systemctl status daimon-restic-mirror@daimonmatrix.service
sudo systemctl enable --now daimon-restic-mirror@daimonmatrix.timer
```

Require an `ok` receipt with the exact source snapshot ID, nonzero file/byte
counts and a stable tree hash on idempotent replay. Compare the same snapshot
ID with target 1. A failed pull leaves the last good mirror and receipt in
place, writes a small `last-error` marker, exits nonzero, and must alert; it
must not erase the successful target 1 copy.

For restore acceptance, copy one selected mirror into a network-disabled
scratch root, provide the escrowed password only at that recovery boundary,
run `restic check` and restore, verify the closed manifest and Matrix/Cluster
integrity, and destroy the exact scratch root after recording redacted RPO/RTO.
