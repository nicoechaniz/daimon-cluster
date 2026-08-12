# Incident: daimonmatrix SSH administrative-key lockout

Date: 2026-08-11 (America/Argentina/Cordoba)  
Severity: high operational availability; no confidentiality or integrity loss

## Summary and impact

During a second-backup-target rehearsal, an operator automation
replaced `/home/debian/.ssh/authorized_keys` with one temporary restricted
mirror key instead of appending it to the existing administrative key. New SSH
sessions using the normal key were rejected until the original key was
restored through the already-running daimonmatrix agent.

The rehearsal also incorrectly used Mona, a production server that the owner
had not authorized for experiments. It created an owner-local scratch tree and
temporary mirror key under `/tmp` on Mona. The exact scratch tree, including
the private key, was later destroyed and no account, authorization, service,
timer or configuration had been installed there. This still violated the
production boundary; none of its results count as backup acceptance evidence.

The VPS, SSH daemon, Cluster, Matrix and Tribe services remained running. No
private key, Matrix custody, repository password or restored content was
copied. The temporary public key had `restrict` plus a forced read-only export
command and did not obtain a shell. The original `authorized_keys` had been
copied beforehand to an owner-only backup on the same host.

## What happened

The intended candidate was `existing keys + one restricted mirror key`. The
actual shell block emitted only the forced-command prefix and new public key,
then atomically renamed that incomplete candidate over `authorized_keys`.

Three independent controls were also absent:

- no assertion proved the candidate contained every original line and exactly
  one addition;
- the initiating SSH command exited without retaining a recovery session or
  scheduling a timed rollback; and
- the old administrative key was not tested from a second fresh connection
  before the recovery path was released.

The restricted-key smoke test then found a second defect: `sudo` did not carry
`SSH_ORIGINAL_COMMAND` into `rrsync`, so the temporary key rejected both shell
and the intended rsync sender request. That defect did not cause the lockout,
but meant the temporary path could not be used to repair it.

## Recovery and final verification

The daimonmatrix agent restored normal key access from
`authorized_keys.dm15trial`. A read-only audit afterward found two authorized
lines: the exact original line plus the temporary `dm15trial-mona` line.

Final cleanup used a persistent multiplexed recovery session and proved:

- current line count `2`, original-backup line count `1`;
- the backup line was byte-identical to one current line;
- the sole extra line was the temporary rehearsal key;
- the installed file became byte-identical to the original backup;
- mode/owner were `0600 debian:debian`; and
- a separate connection with control multiplexing disabled succeeded before
  the recovery session closed.

Final authorized file SHA-256:
`cd4de53f83199dc410603bf611d96203aa5e9f0dc6d5e5fa36ffabec2c2d063f`.
No key bytes are recorded here.

## Root cause

The direct cause was an omitted read of the existing file while constructing
the candidate. The systemic cause was treating an administrative-access
mutation as an ordinary reversible substep of a backup rehearsal. The
procedure had backup mechanics but no proven recovery channel, semantic diff,
fresh-session acceptance or blast-radius isolation.

Permissive execution mode did not cause the error and does not authorize this
class of change. The automation failed to distinguish ease of syntax from
operational risk.

## Durable corrective controls

1. `AGENTS.md` forbids autonomous mutation of existing administrative access;
   future sessions load this rule from the repository rather than chat memory.
2. CI scans executable/configuration surfaces and rejects references to
   administrative SSH roots or any `authorized_keys` mutation.
3. Backup export must use a distinct source identity. A broken, revoked or
   malformed mirror identity cannot remove or replace an administrator's key.
4. The second-target PR remains draft and undeployed until the dedicated
   identity/export boundary is implemented, adversarially tested and reviewed.
5. Any exceptional future access change requires exact user authorization, a
   reviewed tool, open recovery session, timed rollback and a fresh-session
   test of the pre-existing access before rollback cancellation.
6. Mona is recorded as categorically excluded from experiments. Pre-production
   proof uses fixtures, containers or purpose-created disposable hosts only.

## Closure criteria

The immediate lockout is recovered. The incident is fully closed only after a
disposable-host rehearsal proves that malformed provisioning, failed export,
key revocation and total deletion of the mirror account leave the pre-existing
administrative login continuously usable, and the corresponding PR receives
independent review.
