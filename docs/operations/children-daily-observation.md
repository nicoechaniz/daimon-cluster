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

## Signed indexes and reviewed package changes

On 2026-11-08 the four guests' APT timers were enabled, but their cached package
indexes still selected an older Chromium than the Debian advisory feed. A
successful manual signed-index refresh changed their candidate. Timer enablement
alone therefore must not be reported as fresh package evidence.

The existing guest APT cadence now consumes this explicit local policy:

```aptconf
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::AutocleanInterval "0";
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=trixie-security,label=Debian-Security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";
```

This enables daily signed indexes, not automatic package commits. The complete
transaction preflight and future automatic-update policy remain unfinished; do
not enable unattended installation merely because its tool or timer exists.
Existing APT timer definitions and the host's separate policy were preserved.
The next scheduled consumption of the guest policy remains to be observed.

One reviewed transaction upgraded only `chromium` and `chromium-common` from
`154.0.8037.92-1~deb13u1` to Debian-Security `156.0.8078.79-1~deb13u1` on all four.
Signed-index hashes matched the downloaded archives. Their control scripts and
contents had no service units/restart hooks; no browser was running, and no
installed APT invoke hooks were present. Each plan contained exactly those two
upgrades, with no added/removed packages. These are dated candidate observations,
not an allowlist for arbitrary future maintainer scripts or dependencies.

The finite downloads had 300-second/512-MiB/50%-CPU/64-task guest limits. Each
package writer used its own persistent service with 1-GiB/100%-CPU/128-task limits;
no collector deadline killed dpkg. For a stalled writer, stop admitting subsequent
targets and inspect the same transaction; do not restart it or kill a committed
package operation. Verify actual packages, executable version, dpkg health and
existing application processes after each target before continuing.

All four installed/executable versions matched and their three native/web service
PIDs and restart counts were preserved. After qualification, the exact two
completed public archives were hash-checked and retired under APT's existing
locks: 493665344 bytes total, without touching other caches, profiles or work.
The existing daily collector was then rerun because software had changed; retain
its current findings and partial coverage rather than reusing the pre-update
inventory or resolving the broader coverage incident.

## Check the transaction while APT owns its package locks

`tools/children_package_guard.py` is a read-only, per-command APT pre-install
hook for an already reviewed local transaction. It does not download packages,
verify repository signatures, decide that maintainer scripts are safe, install
updates or schedule work. The owning producer must perform those source/maintainer
checks before producing its private `children-reviewed-apt-transaction/v1` manifest.
The initial closed package family is Chromium plus Chromium-common; every other
package remains a deferred transaction, including service/runtime changes.

The manifest has `source: verified-local-debian-security`,
`maintainer_reviewed: true` and `packages`, keyed by the exact two names. Each
entry binds `old_version`, `version`, absolute `archive`, `sha256` and `bytes`.
These are trusted operator observations, not assertions accepted from a companion
message or an external feed. The manifest is operator-owned mode0600; archives
must have trusted ownership/parents and a combined maximum of256MiB. APT's v2
old/new/action fields must match the complete selection: no removal, downgrade,
new or extra package. The hook also refuses unknown invoke hooks, unsafe dpkg
options, insecure source flags, changed archives and an active browser; process
observation is repeated after hashing and fails closed when unavailable.
The producer must reject unreviewed installed APT invoke hooks **before starting
APT**: APT runs `Pre-Invoke` before this seam. The guard's later configuration
check cannot undo an earlier hook's effects and is not that producer preflight.

Use APT protocol2 explicitly with the hook's exact Python command. APT3.0.3
selects its protocol option using the **first command token**, so a command
beginning `/usr/bin/python3` needs
`DPkg::Tools::Options::/usr/bin/python3::Version=2`. Do not assume that reopening
an APT option scope replaces an existing hook list. Keep this hook local to the
selected automatic transaction; do not install it globally or change manual
operator access. [APT's contract](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)
and [the selected implementation](https://github.com/Debian/apt/blob/3.0.3/apt-pkg/deb/dpkgpm.cc)
own the protocol and pre-dpkg ordering.

`tools/qualify_children_package_guard.py GUARD --state EMPTY_PRIVATE_STATE`
exercises the actual installed APT3.0.3 seam using tiny synthetic packages,
separate APT configuration/status/cache and fixed `Debug::pkgDPkgPM=true`.
The latter runs the hook but skips dpkg execution. Source/review fields in these
fixture manifests are imitations for protocol testing, never signed-source
qualification or production grants. The checks require unchanged real and
fixture package-status bytes, admit the exact inert fixture and reject an extra
service-package plan, a live synthetic browser process and a mismatched archive.
Only its newly created fixture tree is retired; bounded logs/result remain.
Run it in the owning finite guest service (180seconds/256MiB/50%CPU/64tasks),
not as a new timer or a real package reinstall. Preserve a failed stage and
inspect it before selecting a continuation. Reuse completed valid evidence.

This component is not the complete automatic updater. The signed selection/
maintainer-review producer, durable commit/recovery coordinator and its daily
activation still need qualification before enabling future automatic writes.
The existing report-only/index policy and daily coverage incident remain in place.
