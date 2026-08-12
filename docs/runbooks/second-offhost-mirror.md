# Runbook: second encrypted off-host mirror

This procedure adds a pull-only ciphertext copy of the checked local restic
repository. It does not give the mirror host the restic password, Matrix
custody, Cluster authority, a general source shell, or access outside the
repository. Target 2 must be in a failure domain independent from target 1.

Mona is explicitly excluded: it is a production server, not a candidate
target, test source, staging host or discovery surface. Pre-production work
uses purpose-created disposable infrastructure only. Selecting any eventual
live target is a separate owner approval and is not inferred from SSH access.

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
Reject Mona by hostname or resolved inventory identity before any connection.

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
with no password, no provider/Matrix/Cluster credentials and no sudo. Give it
`/bin/sh` only because sshd needs a command interpreter; the identity's
`Match User` block forces every request through the root-owned exporter and
disables forwarding and TTY allocation. Its key material lives only at
`/etc/daimon-backup/export-keys`, outside every established login's home. Do
not implement this by editing an existing login or by copying an
administrator's SSH configuration.

Install `configs/70-daimon-backup-export.conf` as an sshd drop-in only after
`sshd -t` accepts the candidate. The drop-in supplies `ForceCommand`; the key
file contains an unadorned, target-specific public key rather than improvised
per-key shell syntax. The wrapper preserves the sshd-provided
`SSH_ORIGINAL_COMMAND` and execs only:

```text
/usr/bin/rrsync -ro /var/lib/daimon-cluster/restic-repo
```

The sshd Match block is the restriction boundary. `rrsync -ro` constrains every
request to sender mode below that exact repository. Prove shell, TTY,
forwarding, receiver mode and paths outside the repo fail closed. Revoke or
destroy only the dedicated export account to remove target access. The source
identity remains undeployable on live infrastructure until the
content-addressed preflight and disposable-host lockout test are reviewed and
a production-specific same-plan gate exists; do not improvise it in a live
shell.

## Disposable provisioning proof

`scripts/restic-export-preflight.py` renders an immutable bundle containing
only the dedicated key file, sshd Match block and exporter wrapper. Its
`verify` command requires the exact bundle SHA-256 and rejects altered content,
modes or paths. It has no apply mode.

`scripts/restic-export-apply-disposable.py` is deliberately not a production
installer. It refuses to run without the exact root-owned disposable marker,
allowlists all three target paths, creates only `daimon-backup-export`, runs
`sshd -t`, emits a receipt and never reloads sshd. The container proof exercises
that exact applicator:

```sh
DAIMON_RUN_DOCKER_TESTS=1 python -m pytest -q -s \
  tests/integration/test_restic_export_container.py
```

Acceptance requires a read-only repository pull plus denials for shell, TTY,
forwarding, upload and path escape. It then revokes the export key and deletes
the export account, requiring a fresh administrative login after each action
and an unchanged synthetic administrative-key hash. The Dockerfile pins its
base image digest and the test destroys its named container and image.

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
