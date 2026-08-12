# Runbook: distributed fresh-embodiment rollout

This runbook adds a new embodiment of an existing root-authorized being on a
target host. It does not clone another embodiment, copy writable Matrix state,
or relocate an existing body. The rollout is forward-only after root
authorization.

The commands require the reviewed Matrix DM-078 and Cluster H7-H9 commits.
Replace every uppercase token from a signed, content-addressed preflight. Do
not paste private keys or passwords into shell arguments, environment
variables, issue comments, logs, or public receipts.

## Mandatory preflight and GO

Record one immutable plan containing:

- exact Matrix and Cluster commits, installed artifact hashes, dependency-lock
  digest, CI/review verdicts and clean install checks;
- being, active manifest, every active predecessor embodiment/incarnation and
  the intended target body, principal, host, listener and advertised endpoint;
- per-host state root, service unit and status-client identity by redacted
  digest, plus owner/mode checks for every private root;
- a fresh quiesced backup cutoff, repository-check result, independent
  off-host copy and restore-smoke receipt;
- root/recovery custody owner and location policy, target-custody owner, who
  may open each password descriptor, and proof that no host/process receives
  both root seeds and target private keys;
- exact public files allowed to cross hosts, transfer channel and host-key
  pins; and
- maintenance window, restart order, stop triggers, forward-recovery owner and
  the later root-signed target-retirement policy.

Read-only discovery may happen before approval. Do not install the candidate,
create target custody, sign an enrollment, change a runtime bundle, restart a
peer, admit the target, or change a service until the operator replies `GO`
while naming the exact plan digest. A changed commit, manifest, participant,
endpoint, backup cutoff or custody policy invalidates that GO.

Preflight must stop on dirty/unreviewed commits, non-green gates, an incomplete
active set, partial `/we`, integrity failure, unchecked backup, shared private
bytes, an implicit route, a listener collision, an unsafe file mode or a
service without a tested restart path.

## Paths and artifact classes

Use short, unique owner-only ceremony roots. In the examples:

```text
TARGET_PREPARATION   target-private; never leaves target
TARGET_PACKAGE       target-private; never leaves target
ROOT_CUSTODY         root-private; never leaves root host/offline device
TARGET_PASSWORD      target-private; opened only as a descriptor
ROOT_PASSWORD        root-private; opened only as a descriptor
REQUEST.json         public target proof; target -> root host
ACTIVATION.json      public root authorization; root host -> target
ROLLOUT.json         public closed deployment plan; target -> all hosts
ACK-*.json           public bounded deployment evidence; peers -> target
```

The preparation directory, target package, password files, custody files,
client keys and predecessor runtime roots are never transfer artifacts. Hash
public transfers at both ends and require byte identity before use.

## Phase 1: target preparation

On the target host, create the target password in owner-only custody and run
the packaged Matrix command. File descriptor 3 is illustrative; use a fresh
descriptor and close it immediately.

```sh
umask 077
exec 3<TARGET_PASSWORD
daimon-rebirth prepare \
  --authority PUBLIC_AUTHORITY.json \
  --profile TARGET_PROFILE.json \
  --output TARGET_PREPARATION \
  --password-fd 3 \
  --ttl-seconds 3600
exec 3<&-
```

`TARGET_PROFILE.json` must name exactly every current active predecessor and a
distinct target endpoint. Preparation performs reachability checks but creates
no relationship or authority. Verify that `REQUEST.json` is the only exported
preparation artifact and that it contains no path, password, private key,
custody or payload field.

## Phase 2: offline root authorization

Transfer only the canonical request to the root-custody boundary. Recheck its
hash, expiry, being, base manifest, target origin, key-purpose separation and
proof-of-possession fields. Then authorize it with the offline root command:

```sh
umask 077
exec 3<ROOT_PASSWORD
daimon-rebirth authorize \
  --authority PUBLIC_AUTHORITY.json \
  --request REQUEST.json \
  --root-custody ROOT_CUSTODY \
  --root-password-fd 3 \
  --output ROOT_AUTHORIZATION
exec 3<&-
```

Transfer only the public activation back to the target. Root custody never
enters the target host. The root host never receives target preparation or
target password bytes.

## Phase 3: target activation and public rollout

On the target, activate against the exact public base runtime named by the
preflight:

```sh
umask 077
exec 3<TARGET_PASSWORD
daimon-rebirth activate \
  --base-runtime PUBLIC_BASE_RUNTIME.json \
  --preparation-dir TARGET_PREPARATION \
  --request REQUEST.json \
  --activation ACTIVATION.json \
  --output TARGET_PACKAGE \
  --password-fd 3
exec 3<&-

clusterctl --state-dir TARGET_STATE rebirth-rollout-create \
  --package-dir TARGET_PACKAGE \
  --output ROLLOUT.json --json
```

Secret-scan the closed rollout and compare its content-derived ID on every
host. It must bind the exact previous/successor manifests, target, endpoint,
Matrix commit, target runtime hash and sorted predecessor set from the approved
preflight. Do not continue if recreating the rollout changes any byte.

The target package may now be installed, but it remains stopped and cannot be
admitted without all predecessor acknowledgements:

```sh
clusterctl --state-dir TARGET_STATE rebirth-target-install \
  --package-dir TARGET_PACKAGE \
  --rollout ROLLOUT.json \
  --idempotency-key TARGET_INSTALL_UUID --json
```

Require result `installed-stopped` and `admission_required=true`. Retry only
with the same UUID.

## Phase 4: predecessor rollout

Visit each predecessor host independently. A host applies only to the local
embodiment root named in the rollout:

```sh
clusterctl --state-dir PEER_STATE rebirth-peer-apply \
  --rollout ROLLOUT.json \
  --embodiment-id PEER_EMBODIMENT --json
```

Require `restart-required`, then restart exactly that embodiment's supervised
service through its existing password descriptor. Wait for authenticated
Matrix readiness; do not infer readiness from a process, port or Cluster
registry row. Emit the acknowledgement only afterward:

```sh
clusterctl --state-dir PEER_STATE rebirth-peer-ack \
  --rollout ROLLOUT.json \
  --embodiment-id PEER_EMBODIMENT --json >ACK-PEER.json
```

The acknowledgement must be canonical and contain only rollout, embodiment,
unchanged incarnation, successor manifest, runtime hash and journal/audit IDs.
Reapplying a completed peer returns `already-acknowledged`; repeating `ack`
returns the original bytes. Preserve completed acknowledgements and continue
other hosts after an outage. Never restore the previous runtime manifest.

## Phase 5: target admission and start

Transfer every acknowledgement to the target over the approved operator
channel. Record the exact closed set:

```sh
clusterctl --state-dir TARGET_STATE rebirth-target-admit \
  --rollout ROLLOUT.json \
  --ack ACK-PEER-A.json \
  --ack ACK-PEER-B.json \
  --json >ADMISSION.json
```

Missing, extra, duplicate-different, wrong-rollout, wrong-manifest or wrong-
incarnation rows must fail before Registry or password access. Repeating with
an exact duplicate returns byte-identical admission.

Perform the first bounded foreground start through H8, not by directly invoking
`daimon-matrixd`:

```sh
umask 077
exec python -m clusterctl.rebirth_host \
  --state-dir TARGET_STATE \
  --embodiment-id TARGET_EMBODIMENT \
  --password-fd 3 \
  --production-fence-verifier \
  3<TARGET_PASSWORD
```

After that check, stop the foreground supervisor cleanly and install the
reviewed template. Keep the source password root-only; systemd exposes a
private copy to the unprivileged service and the shell opens only descriptor 3:

```sh
install -o root -g root -m 0644 \
  configs/daimon-matrix-rebirth@.service \
  /etc/systemd/system/daimon-matrix-rebirth@.service
install -d -o root -g root -m 0700 /etc/daimon-matrix/rebirth
INSTANCE=$(systemd-escape "TARGET_EMBODIMENT")
install -o root -g root -m 0600 TARGET_PASSWORD \
  "/etc/daimon-matrix/rebirth/${INSTANCE}.password"
systemctl daemon-reload
systemctl enable --now "daimon-matrix-rebirth@${INSTANCE}.service"
```

Do not substitute an environment file, inline secret, readable service-account
file or command-line password. Verify the installed unit with `systemctl cat`,
confirm the credential source is `0600 root:root`, and confirm the process runs
as `clusterd`. The long-running H8 supervisor owns the Matrix child. Ready is
valid only when authenticated `runtime.status`, `/me` and `/we` prove
integrity, exact target origin, successor manifest and the complete
participant-plus-target active set.

## Convergence and postflight

Before declaring success:

1. query authenticated status and `/we` from every embodiment;
2. exchange one inert shareable event in each direction through native peer
   pull, replay one exact request and require zero duplicate effects;
3. prove every imported event remains `pending` before observer-local adoption;
4. inspect journals/audit for one target install, one admission, one start and
   one completed acknowledgement per predecessor;
5. inspect process argv/environment/logs for zero password/private-byte hits;
6. take and check a new quiesced backup, replicate it off host, and run the
   bounded restore smoke; and
7. publish only the redacted IDs, public hashes, state transitions and test
   results allowed by the approved plan.

## Failure and forward recovery

- Before root authorization, delete only validated target staging and restart
  later from a new preparation.
- After root authorization but before any peer apply, keep the signed activation
  and repair/retry the exact target package; do not mint another target under
  the same plan.
- After any peer accepts the successor, the previous manifest is no longer a
  rollback target. Continue the same rollout or publish a later root-signed
  successor.
- A down predecessor leaves the target stopped. Do not waive or shrink the
  participant set.
- A failed target start retains its custody, admission and journal and retries
  the same incarnation after repair.
- Removing the new embodiment requires a later root-signed retirement or
  revocation rollout. Deleting its files, restoring an old backup as current or
  rolling only one peer backward is forbidden.
- Release-code rollback after root authorization must retain software capable
  of completing this successor. Preserve both candidate and predecessor
  releases until postflight backup/restore and the observation window pass.

The synthetic qualification receipt is
[`../verification/h9-distributed-rebirth.md`](../verification/h9-distributed-rebirth.md).

## Recovery-quorum rebirth from a verified snapshot

Recovery is a different transition from adding a concurrent embodiment. The
Matrix recovery quorum must revoke every active predecessor, rotate to fresh
root custody and authorize exactly one fresh target with no peer targets. Do
not run the predecessor acknowledgement rollout for this case.

After the target-only package and a quiesced `dm.cluster-matrix-snapshot/v1`
are independently available, derive the target transfer on the source side:

```sh
clusterctl rebirth-recovery-export \
  --snapshot-dir VERIFIED_FULL_SNAPSHOT \
  --output RECOVERY_TRANSFER --json
```

The export first verifies every file in the full snapshot, then emits a new
valid `dm.cluster-matrix-snapshot/v1` containing exactly the public runtime
bundle and canonical ledger. Require `custody_files_exported=false`, record
both source and recovery snapshot hashes, and transfer only
`RECOVERY_TRANSFER`. The full backup, predecessor custody, runtime journals,
derived stores and host-local capabilities remain at the source/backup
boundary.

On the target, keep the target password on an inherited file descriptor and
run:

```sh
clusterctl --state-dir TARGET_STATE rebirth-recovery-restore \
  --package-dir RECOVERY_PACKAGE \
  --snapshot-dir RECOVERY_TRANSFER \
  --password-fd 3 \
  --idempotency-key RECOVERY_RESTORE_UUID --json \
  3<TARGET_PASSWORD
```

The restore command verifies every transferred file and the exact Matrix source pin
before mutating Cluster state. It installs the fresh runtime stopped, opens
the predecessor ledger under its old authority, and re-ingests only canonical
events through the recovery successor's historical authority. It never copies
the old runtime bundle, custody, local RPC/transport journals or derived
stores. Require `installed-restored-stopped`, preserve the content-addressed
recovery transfer and retry with the same UUID after interruption. General
portable snapshots remain accepted during the compatibility period, but new
recovery journeys must use the custody-free export.

The H8 supervisor refuses a recovery target until the separate restore journal
is complete. After bounded start, require the old event set and one newly
signed event from the fresh embodiment. Release rollback may restore old code
that understands the new successor, but signed authority never rolls back;
disaster retry rebuilds another fresh target root from the same package and
snapshot and must reproduce the same canonical event-set hash.
