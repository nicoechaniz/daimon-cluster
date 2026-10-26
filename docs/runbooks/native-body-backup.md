# Native body backup and disconnected restore

Current scope: an existing body on its own native host. This is not Incus
onboarding, a global Stop, a new Matrix identity or permission to replay work.
The body and retained source keep their identities and history separately.

## Preparation and custody

`scripts/native-restic-init.py` initializes only a new encrypted repository and
an age-sealed recovery envelope. Run it as the authorized receiving operator
with a private state directory, a protected selected public-recipient file and
an existing authorized operator public key included in that selection. It never
modifies SSH admission. Keep the plaintext unlock file below the excluded backup
state directory. Retain the sealed envelope alongside the offhost ciphertext.

Repeated preparation preserves the same unlock material, envelope and repository.
Missing unlock material for an existing repository must be recovered, never
replaced with a new password. Retained partial envelopes require inspection;
preparation does not overwrite them or claim that a backup is usable.

Actually prove recovery with an existing authorized recipient. Use a private
pipe rather than plaintext argv, conversation output or an offhost password file.
If an operator's private key exists on the mirror host, the correct isolation
claim is that the mirror **service** lacks decryption authority; root is not
cryptographically excluded. Background export/pull uses its own restricted
identity, never an administrative private key.

## Consistent capture contract — implementation still pending

A hot pre-copy reduces the final pause but is not a recovery point. An online
SQLite backup can verify one database; it cannot establish consistency among
Matrix authority/history/receipt stores, Codex rollouts and Telecodex transport
journals. Matrix's pool snapshot contract explicitly requires writer quiescence
for a cross-file cutoff. Do not use the broad legacy `restic-backup.sh` on a
native member or stop other tribe bodies to capture this one.

Use the existing body's declared native writer boundary and preserve its actual
service/activation state. Before capture, observe the existing native daemon
without starting models or importing conversation text. Prefer an idle window;
retained active work must not become an implicit replay or an automatic goal
resume. Quiesce only the selected body's actual writers gracefully, stop their
activation sources for the cut, complete the final exact delta, and resume the
previously active services before hashing, encryption, repository checks or
network transfer. A failed quiescence/copy must retain its attempt, restore the
previous receiving availability and leave the candidate unaccepted. Do not
SIGSTOP writers mid-transaction or pretend separate hot copies share one cutoff.

Capture the complete durable native boundary, including selected configuration,
SDK/application assets and signed history outside the home. Exclude the backup
repository/unlock/staging boundary, virtual filesystems and temporary runtime
sockets. Shared remote mounts remain their owning services' backup responsibility;
preserve their bindings and grants instead of silently substituting a local copy.
A hot rsync exit24 from vanished files is a retained incomplete seed, not acceptance.

## Export and acceptance — implementation still pending

Reuse the existing read-only rrsync export and atomic mirror-pull mechanism.
Serialize export with repository writes/prune so a pull cannot mix generations.
Measure actual encrypted size and free space, including staging overhead, before
selecting an offhost destination. Source-host rollback is not an offhost backup
of new receiving writes.

Restore the actual offhost ciphertext into a new private, disconnected directory,
recovering the password through the retained envelope. Verify SQLite integrity,
signed history, native rollout/topic references and deterministic DMK retrieval.
Do not start the restored Telegram bot, Matrix delivery, native goals or models.
A verified one-DB sample does not establish the whole-body recovery contract.
Publication, repository initialization, consistent capture, offhost delivery and
restore acceptance remain separate observed outcomes in the owning resource record.
