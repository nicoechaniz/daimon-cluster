# Children's scheduled maintenance observation

The children's host uses the maintained Daimon Alerts `scheduled_job` observer
to check the existing daily inventory service and timer. This observes execution;
it does not install package fixes, validate all advisories or perform cleanup.
The broader security handoff and its unfinished acceptance remain authoritative.

## Selected route

The receiving monitor selects Alerts PR31, source
`a1a43176fa52f60d61f11386d18ff830026bc266`. Its supported maximum age is up to
172800 seconds; this deployment selects **93600 seconds (26 hours)** for the
daily job and **900 seconds** maximum running time. A disabled timer, absent
first execution, unsuccessful exit, stale success or excessive running time is
unhealthy. An inactive oneshot after successful completion is normal.

Use the existing dedicated host producer credential and private configuration,
not another body's token. The producer is `children-lotf-daily`; the observer is
`children-lotf-daily-observer`. Keep its binding and SQLite journal when changing
software. A changed target binding requires the monitor's explicit reconciliation
operation, never deleting the journal or silently replacing its configuration.

The finite `children-daily-observer.service` runs through a `Wants` dependency of
the existing `children-storage-observer.service`. The latter's existing timer
retains its ten-second cadence. There is no additional timer or model scheduler.
Do not run or restart the inventory merely to check its health. Preserve both
existing timer definitions and the storage observer's own command and limits.

The daily observer has a 20-second timeout, 64 MiB memory, 10% CPU, 16 tasks and
an 8 MiB per-file write limit. It has no new privileges, read-only system/home,
private temporary storage and write access only to its own private state. Its
one-target projection replaces the previous status; no per-tick files accumulate.
SQLite retains pending incidents/outbox and reuses pages. The database and its
rollback journal each have the file bound; exhausted writes fail rather than
deleting pending work. Existing bounded system journal retention applies.

To stop future observations, remove only the daily observer's `Wants` drop-in
from the storage service and reload systemd. Let a current finite observation
finish. Keep the daily inventory timer, storage timer, credentials and journals.
Rollback software selection without restoring an older database.

## Actual receiving evidence, 2026-11-08

The existing daily inventory was healthy. Two distinct actual systemd invocations
after selection observed it as healthy and reached the Alerts service with an
empty outbox. Both existing timer files remained byte-identical. The receiving
checkpoint records exact source/configuration digests, invocation IDs and bounds.

A disposable fixture exercised missing first execution and an actual failed exit,
then a successful recovery. Both failure observations used the same incident;
recovery resolved it at revision 2. The established adapter retained delivered
receipts for the opening and resolution. No resend, acknowledgment or human
reading was inferred. The fixture units were removed; production inventory was
not replayed or stopped. A prior fixture/launcher name collision produced no
incident and remains in the operator evidence, separate from the corrected test.

The original partial daily-security coverage notice remains open. Package
transactions, broader application/malicious-advisory applicability, bounded
cleanup and independent host availability remain separate unfinished work.
