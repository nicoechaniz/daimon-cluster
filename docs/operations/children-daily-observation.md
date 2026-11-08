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

These native periodic settings enable signed indexes, not package commits. The
selected coordinator below independently handles the reviewed browser family;
keep native unattended installation disabled and broader transactions deferred.
Existing APT timer definitions and the host's separate policy were preserved.
Actual native `apt-daily.service` execution succeeded on all four with a fresh
`/var/lib/apt/periodic/update-stamp`; package-status bytes stayed unchanged.
Naturally scheduled consumption remains distinct and unobserved.

One reviewed transaction upgraded only `chromium` and `chromium-common` from
`154.0.8037.92-1~deb13u1` to Debian-Security `156.0.8078.79-1~deb13u1` on all four.
Signed-index hashes matched the downloaded archives. Their control scripts and
contents had no service units/restart hooks; no browser was running, and no
installed APT Pre/Post-Invoke hooks were present. The standard debconf
Pre-Install callback remained configured; these packages had no config/templates. Each plan contained exactly those two
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

The guard alone is not an updater. The current producer and daily coordinator
below own selection, commit/recovery and activation. Broader package families
remain deferred and the original daily coverage incident stays open.


## Select signed security metadata and inspect reviewed archives

`tools/children_package_selection.py --policy PRIVATE_POLICY --state PRIVATE_STATE`
consumes native APT trusted `indextargets` for the official Debian trixie-security
main/amd64 index. APT remains the signature verifier. The producer checks the
native source binding, update-stamp age (26h), signed Release identity/expiry,
installed/candidate versions, package database health and exact two-package plan.
It audits APT configuration before invoking APT; unknown hooks, weakened trust,
new dependencies, removals, downgrades and active/unobservable browsers defer.
The initial reviewed family is Chromium and Chromium-common, not a general
permission to install Debian packages or silently revise this policy.

`support/children-maintenance/browser-package-policy.json` records reviewed
payload paths/links and maintainer-script hashes from the actual Debian package
baseline156.0.8078.79-1~deb13u1. Changed controls, service files, modes, links or
scripts require review. Packages with debconf config/templates always defer.
The existing root-owned `/usr/sbin/dpkg-preconfigure --apt || true` callback is
recognized only with its exact reviewed file hash. For this family without
config/templates, generated **per-transaction** configuration clears that callback
and selects only the current protocol2 guard. No global hook or manual APT
configuration is changed; unknown/binary-scoped hooks still refuse.

The default mode produces metadata only. `--download` fetches exact signed-index
archives, verifies custody/bytes/SHA, inspects control tar and payload listing,
then prepares `manifest.json` and `transaction.apt.conf` for the existing guard.
It never runs a package writer. An existing manifest requires reconciliation;
it is not overwritten or automatically retired after an uncertain transaction.
State is root-owned0700, files0600, one current/previous result, exclusive lock,
512MiB total and256MiB archive cap; native downloads have300s deadlines. Run under
a finite resource-bounded guest service. Keep unfinished archives/results when a
stage fails; only retire exact verified task-owned copies after qualification.

All four actual guests consumed the selected standalone producer and reported
`up_to_date`, with native signed index metadata and no package writes. The first
Pixin check refused the standard debconf callback before any download; that
outcome was retained before the exact callback audit/continuation. Native index
qualification initially read the wrong stamp name; Pixin's already-successful
APT service was not replayed, and the continuation consumed the native stamp.
The selected daily coordinator below now owns the narrow browser transaction
and its automatic admission. Keep native APT periodic install/download and
automatic reboot/removal off; this producer never enables those global controls.
The original broader partial-coverage incident remains open.

A single actual Pixin download-only qualification then exercised the same selected
inspector against both real signed-index archives (123416336bytes total). Actual
control/listing/hash checks passed, exact copies were retired and real dpkg status
SHA remained unchanged. No installed-version substitution, reinstall, production
manifest or provider call was used to exercise that seam. The byte-identical
inspector needs no fourfold duplicate archive download.

## Durable daily package coordinator

`tools/children_package_maintenance.py` composes the existing selector and guard.
Each guest owns `children-package-maintenance.service`, installed from
`deploy/systemd/children-guest-package-maintenance.service`. It holds the same
private state lock as the standalone selector and records one current and one
previous daily transaction. A pending manifest is bound by SHA; reviewed but
uncommitted work revalidates rather than downloading another transaction.

Before commit it rechecks trusted/fresh native security metadata, exact archive
hashes, installed versions, held packages, the exact scoped guard configuration,
package simulation, browser inactivity, guest free space and all three existing
native/web services. It fsyncs **commit_requested before launching APT**. The
command uses no-download, no-remove, only-upgrade and preserved local config;
APT owns the real package locks and executes the current protocol2 guard.
No arbitrary package/service/runtime upgrade is admitted by this browser policy.

The guest writer service has1GiB/100%CPU/128tasks, no start/stop deadline and
`KillMode=process`. Its APT process inherits the systemd journal directly; a
Python-owned output pipe would cause SIGPIPE after supervisor loss. Existing
guest journals are bounded64MiB persistent/16MiB runtime/7days. No collector
read deadline or cleanup command may kill a package writer. An actual harmless
child-process test survived its Python supervisor; this is not an induced
production APT interruption. Failed/OOM/uncertain transactions retain their
journal, manifest and archives and require the existing operator to inspect
actual versions/locks/health; they never automatically repeat commit.

Recovery obtains the actual POSIX frontend/dpkg/cache locks without deleting or
replacing lock files. It requires installed and executable target versions,
empty dpkg audit and unchanged active native/web process identities. Only then
can it mark complete and retire exact verified archives/config/manifest. This
cleanup is resumable after partial completion and touches no unrelated cache,
profile, history or work. An unchanged old version after a lost response is
**not** evidence that installation was never admitted. A deferred pre-commit
browser check, however, can resume the same reviewed manifest without another
selection or download. Unknown/orphan state remains preserved.

The host `children-packages-daily.service` has900s/128MiB/25%CPU/32tasks and
observes the four independent guest units serially for at most600s. It checks
actual Incus fast-root quota headroom (at least2GiB) before guest admission;
guest `df` alone measures shared backing and cannot establish quota headroom.
An already-running guest is observed, never restarted. Observer expiry leaves
its writer alive. Missing/stale/failed guest receipts make the fleet degraded.
The host keeps current/previous successful fleet projections. Each private
state tree has a384MiB admission threshold within the existing512MiB cap,
including the selector's256MiB maximum archive set. Pending work is not evicted.

The supported daily link is a drop-in on the **existing** inventory service:

```ini
[Unit]
Wants=children-packages-daily.service
After=children-packages-daily.service
```

Do not add a second timer. Stopping future package admission means removing only
this owned dependency drop-in and reloading systemd. Preserve both existing
timers, all guest units/state and any running writer; let it finish. Code rollback
preserves transaction journals and selected guard dependencies. Never restore an
old package database to roll back code.

The existing Alerts observer supports explicit additive target extension. Add
`daily-packages`, same existing inventory timer, host unit
`children-packages-daily.service`, explicit
`trigger_unit: children-daily-inventory.service`, max_age93600s and max_run900s.
Alerts PR32 checks actual timer Triggers plus the trigger service's Wants/Requires
and After. The original matching-name-only adapter refused this target; that
no-effect binding refusal is retained. Use its maintained
`Monitor.extend`/`--extend-to` operation and update the private configuration
while holding that monitor's lock; retain the same authority, journal, original
target and pending outbox. Merely editing targets makes the bound monitor refuse.
Do not acknowledge or close the broader partial-coverage incident.

First actual fleet evaluation succeeded for all four with current native metadata,
up_to_date and write_requested=false; no reinstall was needed. Source/policy
readback and actual unit/cgroup selections are separate from a future real
upgrade through this coordinator. Existing signed Chromium installation, native
APT guard and real archive-inspector evidence remain valid and are not repeated.
Broader upstream/malicious applicability, host/critical package policy, cleanup
and independent availability are still unfinished parts of daily coverage.


Receiving activation now selects the existing daily inventory dependency; its
remove/reload/readback/restore stop-path test passed without changing either
existing timer's bytes or starting another package installation. Alerts PR32
sourcec80c8e8 is installed only on the owning children's observer, preserving
its client, configuration authority, SQLite journal, original target and cadence.
Its supported additive extension admitted daily-packages; actual subsequent
scheduled ticks report both daily-inventory and daily-packages healthy, with
empty pending outbox. No acknowledgment or broad coverage resolution occurred.

The initial fleet success existed in its durable receipt but systemd later
reported zero exit timestamps after the dependency stop-path reloads. Observation
correctly refused to infer a successful native lifecycle from that receipt. One
new coordinator execution under the selected dependency recorded an actual
successful terminal. All guest transaction timestamps and write_requested=false
remained identical, proving daily intent reuse rather than another selection,
download or installation. Naturally scheduled package execution remains a future
acceptance item; dependency selection and actual manual execution are distinct.

## Optional bounded compiler-cache phase

The current collector accepts only one additional opt-in key,
`compiler_cleanup_enabled` (boolean; absent/false preserves the original route).
When selected it invokes the installed own guest's finite
`children-cache-cleanup.service` before its inventory. The service owns the
90s/128MiB/25%CPU/32task limit and a1MiB current/previous-state bound. The collector
waits at most100s and reads at most64KiB of its result. No child model or browser
is started. Host inventory remains separate; this phase is scoped to the four
own guests, not a general host-cache deletion grant.

Cleanup and actual Debian inventory/advisory matching are retained separately.
A failed/partial/unavailable cleanup causes a degraded daily exit even when
inventory matching succeeded; existing Alerts scheduled-job observation therefore
continues to cover the expanded pipeline. Browser/other-cache/worktree coverage
is explicit, not converted to complete cleanup by a zero-removal result. See
[storage hygiene](host-storage-hygiene.md) for the unprivileged deletion,
privileged activity projection, allowed roots, budgets and stop/recovery route.

## Own browser readiness without periodic wakeup

The optional browser metadata stage uses the existing inventory service/timer,
not a new schedule. See [browser selection and stop path](children-browser.md#daily-connection-and-standby-observation).
Intentional standby passes; failed units, unavailable helper/extension or invalid
metadata degrade the daily result and produce a nonzero service exit, consumed
by the unchanged scheduled-job observer. No tab, private page, lifecycle action,
model input or provider call is part of the read. Package/advisory and cleanup
evidence remains separate if the browser stage fails. Complete idle detection
and independent host availability remain unfinished.
