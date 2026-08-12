# Runbook: second encrypted off-host mirror

This procedure adds a pull-only ciphertext copy of the checked local restic
repository. It does not give the mirror host the restic password, Matrix
custody, Cluster authority, a general source shell, or access outside the
repository. Target 2 must be in a failure domain independent from target 1.

The source export must use a dedicated `daimon-backup-export` identity. This
workflow must never add, remove, rewrite or otherwise inspect-as-candidate an
existing administrator's `authorized_keys`; in particular it must not operate
as `root`, `debian` or another established login. Breaking or deleting the
export identity must leave administrative access unchanged.

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

Transfer only the `.pub` line to the source's separately reviewed
`daimon-backup-export` bootstrap through the approved operator channel. Pin
the source host key independently into
`/etc/daimon-backup/daimonmatrix.known-hosts`; do not use `accept-new`.

## Source read-only authorization

Provision a new source-only system identity through reviewed host bootstrap,
with no password, no provider/Matrix/Cluster credentials and no sudo command
except the fixed exporter wrapper. Its owner-only key file contains exactly
one target-specific public key. Do not implement this by editing an existing
login or by copying an administrator's SSH configuration.

The dedicated key's forced command must pass the original rsync request as one
quoted argument to a root-owned exporter wrapper. The wrapper accepts exactly
one argument, reconstructs `SSH_ORIGINAL_COMMAND`, and execs only:

```text
/usr/bin/rrsync -ro /var/lib/daimon-cluster/restic-repo
```

The mirror key must have `restrict` and no other authorization. `rrsync -ro`
constrains every request to sender mode below that exact repository. Prove
shell, TTY, forwarding, receiver mode and paths outside the repo fail closed.
Revoke or destroy only the dedicated export account to remove target access.
The repository currently contains no authorized installer for that source
identity: do not improvise one in a live shell. Its reviewed implementation and
disposable-host lockout test are deployment gates for this runbook.

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
