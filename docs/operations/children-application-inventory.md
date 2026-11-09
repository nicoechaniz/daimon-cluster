# Selected application inventory without package execution

An optional `components` list on a selected `cwd` deployment extends the same
file verifier to its explicitly qualified public dependency trees. Select one
to three additional `{root, source_ref, files}` entries and the complete ordered
`pythonpath`, including the main deployment root. The actual process PYTHONPATH
must match before and after component reads and again at the final process check.
Each complete tree retains the existing ownership, mode, symlink, file-set, hash
and mutation checks. No package is imported or started. A mismatching component
or changed search path makes that unit unavailable, preserving other observations.

The existing private deployment-manifest writer owns these fields. Use retained
maintainer/component/wheel manifests, never hashes learned from an unknown live
tree. Keep at most1024files per tree and4096 across the complete manifest; the
existing256KiB manifest,128MiB shared byte-hash budget and finite read-job bounds
still apply. The result proves those selected files and process search-path
selection, not actual Python imports, upstream authenticity of every dependency
or external exposure. Only independently verified provenance supports a stronger
claim for a particular package. Old manifests without these optional fields keep
their existing behavior; this change creates no additional timer or scanner.

Optional browser_components uses the same existing read job for guests only.
It invokes /usr/bin/readelf -dW on the fixed Chromium image, records the direct
FreeType DT_NEEDED and presence of custom RPATH/RUNPATH, and hashes the standard
root-owned library file with before/after image/link consistency checks. It
never executes Chromium, ldd or the library. The331MiB browser is inspected as
metadata, not copied or silently admitted into the128MiB image-hash budget.
Browser size is capped512MiB, readelf accepted output64KiB/5seconds, library
size/hash4MiB within the remaining original hash budget. Existing job40seconds/
128MiB/25CPU/32tasks and output/state bounds remain. Unknown/changed/oversized
or unavailable data stays unavailable while other unit observations remain.
This supports the explicitly selected FreeType source assessment; it is static
dependency evidence, not upstream authenticity or actual runtime loading.

Invoke `python3 -B -I -S tools/children_application_inventory.py --units NAME.service`
through the bounded native read job. It reads explicitly selected systemd main
processes. It binds executable bytes to the actual running PID, then checks the
service is still active with that PID. It also pins the kernel process start
ticks and rechecks the current executable's device/inode/size/mtime/ctime and
link after metadata collection. PID reuse, exec replacement and observable
same-size writes become unavailable, including when the initial image hash was
reused for another selected unit. This is a bounded observation of the selected
main process, not continuous monitoring or protection from a privileged attacker.
It captures executable path/SHA, not
arguments. It selects only PYTHONPATH metadata in memory, discarding every other
environment key and value. It parses distribution Name/Version headers as data;
no package import, .pth execution, installer, model or provider call is requested.

An empty venv is not proof of no dependencies. The actual child web deployment
uses a venv created without pip and separate vendored PYTHONPATH roots. Read both
those selected roots and the venv's ordinary site-packages. The observed PyPI
metadata is not an authenticated wheel or proof of loaded/imported code. Process
descendants, dynamic startup paths, non-Python dependencies, upstream artifact
authenticity and advisory applicability remain partial/unassessed.

Native receiving found a Pydantic METADATA file with a131572-byte description.
Read at most64KiB of its headers, requiring complete bounded headers, rather than
rejecting a valid version because its unused description is long. Record the
header SHA and full-file size separately; never call that hash a full metadata
or package hash. Preserve the initial empty-venv and header-limit observations.

Each resource accepts at most8 unique explicit service names,25seconds soft
read deadline,128MiB of executable hashing (same-image reads reused within one
run),8 Python roots,1024 directory entries/root and256 distributions/root.
Headers are64KiB each; output is256KiB. The owning native read job enforces
40seconds/128MiB/25%CPU/32tasks and the outer read55seconds/384KiB. These are
read-only jobs, separate from application/native cgroups and package writers.
Unavailable/changed PID, oversized/incomplete metadata or read failure never
becomes an empty healthy inventory. Keep a private current/previous receipt in
the existing bounded daily state; do not upload paths, package lists or env data.

## Existing daily route

Optional `application_inventory.network_listeners=true` uses the same selected
helper, service list and bounded native read job. It associates actual main-process
socket descriptors with that process's kernel TCP/TCP6/UDP/UDP6 tables, retaining
only protocol, IP family, local port and bind scope. TCP connections and foreign
socket rows do not become listeners; no remote peer, raw address, socket path or
process arguments are retained. No connection, port scan or application start is
performed. Standalone use accepts `--network-listeners`.

Each process permits1024descriptors,128listeners and128KiB/2048rows per table,
within the existing deadline/output limits. Missing or malformed tables, exhausted
bounds or changed socket ownership remain unavailable. The original process/image
checks still run afterward. The same daily receipt exposes the separate
`selected_main_process_listeners` phase; a selected incomplete read fails collection
health rather than becoming a healthy empty list. Unselected installations remain
compatible. Disable only that flag to omit the phase, preserving other observations.

This is main-process socket binding evidence, not external reachability. Worker
descendants, other socket families, firewall/NAT effects and IPv6 dual-stack policy
remain unassessed. A wildcard bind does not by itself establish public exposure,
and an empty main-process list does not prove its workers have no listeners.

The optional private `application_inventory` object selects `helper`, `sha256`
and `units`, keyed by exactly the existing host and four companions. The helper
must be a root-owned, non-writable, regular absolute file with verified ancestry
and exact bytes on each receiver. The collector runs that qualified code under
`python -I -S` in a finite native read job. It requests no service start/stop for
the observed apps. Native read jobs have a distinct fixed unit name per receiver.

Only successful inventory reads make this stage observed; overall security
coverage remains partial. A failed application stage preserves Debian matching,
browser and cleanup evidence but fails the daily occurrence for its existing
scheduled-job observer. No additional timer, producer credential, repair loop or
child grant is created. Remove only `application_inventory` to stop this optional
phase, preserving all other phases, current findings, profiles and pending work.
The existing collector900second read-only deadline remains; a slow/exhausted run
stays failed/unassessed instead of exceeding its bound or killing package writers.

Before advisory queries, reconcile declared metadata with the owning deployment
lock/provenance and explicitly select only public ecosystem/name/version tuples.
Keep private identifiers offline. Empty advisory results are not a clean-system
certificate; missing sources, alias/revision handling, no-fix/malicious advisories,
artifact authenticity and real exposure require their maintained evidence.

A first receiving occurrence captured all five application inventories but failed
a Calipso cleanup-receipt JSON read. The retained original receipt was complete
with zero removals; the failed transport output was unavailable, so no cause was
invented. The collector now reads the bounded structured receipt and permits
one parse-only re-read without starting cleanup again in that reconciliation.
It preserves failure size/digest if recovered; a second invalid read stays
failed. Original partial occurrence and later verification remain distinct.

## Selected deployment manifests

Optional `application_inventory.deployment_manifests` maps selected target IDs
to an exact root-owned `path` below `/etc/children-maintenance` and its `sha256`.
The same qualified helper loads that bounded256KiB manifest as data, verifies
root ownership/ancestry and bytes, and consumes it inside the existing finite
read job. No application import, provider request, code execution or new timer is
added. A standalone read accepts `--deployment-manifest PATH` together with
`--deployment-manifest-sha256 SHA`.

The closed `children-selected-deployments/v1` document contains `units` for a
nonempty subset of the already selected services. Each unit selects `root`,
`bind` (`executable` or `cwd`), public `source_ref` and relative `files` SHA256 map.
Roots are restricted to maintained public application or Incus code prefixes.
At most8units/1024files total are accepted. Expected manifests come from retained
maintainer deployment records, not from hashing the current observed tree and
calling that observation trusted. Explicit source selection is technical work;
it requires no second approval or another account.

The helper checks exact source file sets, custody and hashes; symlinks, writable
files, unexpected/missing source, changed process/cwd and changed files remain
unavailable. It rechecks file identities and the selected process before returning.
Runtime `__pycache__`/`.pyc` is excluded and explicitly not verified. Hashing shares
the original128MiB/25second budget and same-image cache, so a native image already
hashed through `/proc/PID/exe` is not read a second time. The native job's existing
40second/128MiB/25%CPU/32task and256KiB output bounds remain unchanged.

An executable binding verifies selected files and the current loaded main image.
A cwd binding verifies selected source files and current working directory;
it DOES NOT establish already imported Python modules, every dependency's
upstream authenticity, process memory or exposure. `phases.selected_deployments`
retains the actually selected targets and explicitly lists unselected units.
Changed or missing selected evidence fails observation health without restarting
the application or erasing other assessment. Full security coverage remains
partial. Refresh the manifest/reference through the existing host writer from
an actual newer maintainer selection after an application deployment; never
silently bless a changed live tree or interpret the gap as missing human authority.


## Python supervisor entrypoint binding

A selected deployment may use `bind: "python-script"` for the immutable public
`/opt/daimon-onboarding-runtime` code family. The existing owner manifest pins
the complete selected directory's file set and hashes from its maintained
release, never a newly learned live tree. A Python service's working directory
may legitimately be `/`; it is not evidence for that script's source selection.

The observer checks the actual Python3 executable and bounded current cmdline's
script argument, accepting only explicit non-executing interpreter flags before
that absolute declared script path. Python `-c`, `-m`, option substitution,
relative/foreign scripts and oversized command metadata do not qualify. Remaining
arguments are never retained. The selected source bytes are read as data;
nothing is imported, compiled or executed. The result keeps only the public
relative `python_entrypoint`, and still marks `loaded_main_executable=false`.

Process/PID/image and entrypoint checks repeat after metadata collection to
refuse a changed same-PID script selection. Existing root custody, complete file
set, symlink refusal,128MiB hash budget and read/output deadlines are unchanged.
Interpreter upstream authenticity, runtime imports/dependencies and exposure stay
unassessed; verified entrypoint/source selection does not clear those gaps.

All4 current native supervisors were observed to select the same retained
runtime artifact. Their candidate manifests derive68 declared module files from
its verified release receipt, preserving the existing App/native manifests.
Actual receiving selected the helper on the existing host/four-guest pipeline.
The complete occurrence observed13main processes and verified12deployments,
including68declared source files for each of the four supervisors. All process
identities/invocations were preserved;38seconds/234971136bytes peak remained
within900seconds/512MiB/25%CPU/64tasks. No new timer, model or native restart.
Host Incus package provenance remains a separate current gap.


## Recovering a changed source selection

Resolve current web provenance from the maintained Interaction receiving pointer
and its qualified per-target adoption manifest before updating the observer.
An older successful observation is historical; it must not silently bless a
newly loaded directory. The receiving run detected old833web references against
the already adopted834web. The replacement came from the maintained834receipt,
not hashes learned from the running tree; the App was neither changed nor rolled
back. Include this manifest refresh in the owning deployment path when selecting
a new qualified source. Automatic cross-component publication wiring is not
established by this receiving refresh.

A terminal failed finite observer with MainPID0 and no active systemd Job may
admit scoped recovery just as an inactive observer can. Preserve its failed
report, invocation and source preimage; never require `reset-failed` or confuse
terminal failure with a running worker. An active/queued job or held lock still
refuses overlapping work. The first receiving recovery's inactive-only check was
corrected before configuration dispatch, preserving that original refusal.

Keep current and original rollback manifests. A third manifest was temporarily
staged for the qualified web refresh; after the actual healthy collection, the
unselected failed intermediate's byte-verified metadata was retained in its
bounded operation journal and the live manifest directory returned to2entries.
No app data, runtime code, original rollback or uncertain native effect was
retired. The known-exploitation HTTP failure also remained unavailable with its
prior successful source hash. A later bounded read observed all3fixed sources200;
one new complete occurrence then passed. The exact failed source/status was not
recorded by that old HTTP error path and is not inferred from later success.

The producer's health incident resolved at higher revision2. The distinct partial
coverage incident remains open at revision5 with original provenance/delivery
history and no requested acknowledgment. It still records host Incus provenance,
Python imports/dependency authenticity/exposure, malicious releases outside the
selected public versions and current vendor applicability as pending. Healthy
collection is not security clearance or family/device acceptance.


## Read-only Incus package provenance

`python3 tools/children_incus_provenance.py --state OWNER_STATE` prepares an
ordinary `manifest.json` and a bounded `receipt.json` for the host Incus unit.
It performs no package installation, service action, maintainer-script execution
or source import from the archive. This is a foreground operator, not a new timer.

The selector reads the exact installed `incus-base` version, reuses the existing
native26hour APT-update/Release freshness check, verifies the security InRelease
with the installed Debian archive keyring using Debian13's existing `sqv`, and compares the decoded
Packages index against the signed SHA256/size entry. Only the exact amd64 package
version in that authenticated security index is eligible. This read-only route
supports the host's native mirror/deb822 index without widening the separate
browser/library package-installation policy's legacy source restrictions.

The archive is capped32MiB, fetched from one fixed HTTPS Debian security origin,
and verified by the existing archive custody/size/SHA helper. Interrupted bytes
remain in the same private state; a continuation appends only after an exact
HTTP206Content-Range confirmation, then verifies the entire archive. Wrong ranges,
oversize, hash mismatch and changed installed version preserve work and refuse a
positive result. A non-overlapping state lock prevents concurrent archive writers.

`dpkg-deb --fsys-tarfile` reads at most128MiB/40seconds; the tar reader hashes only
regular declared Incus files, refusing traversal, symlinks, duplicates and excess
entries. No archive contents are executed or extracted to live paths. The manifest
pins the complete Incus public directory from signed package bytes, never the live
filesystem; the existing daily observer must then bind its actual running image.
Maintain one bounded current package cache/receipt; unknown partial work is not
pruned. After receiving confirmation, only the byte-verified disposable archive
may be retired while preserving provenance metadata and selected/rollback records.
Cache admission stops at its fixed capacity; no blanket package/image cleanup.

Debian13's `sqv --cleartext` requires a new output file and does not interpret
`--output -` as stdout. Use its authenticated output in a disposable private
directory, retaining only the bounded parsed metadata. The first receiving
attempt lacked `gpgv`; the corrected existing-sqv route verified the actual
signed index and17,590,192-byte installed package, yielding five source hashes.
Neither attempt installed or restarted Incus. Keep source qualification distinct
from the subsequent loaded-image observation.

Source/fixture qualification does not establish real package provenance or a
loaded fix. Record the actual signed-index/archive qualification and later daily
observer outcome separately. Dependency authenticity, imported code and exposure
remain distinct from this selected-package image association.

Actual receiving bound all five declared Incus files to the existing running main
image without restarting it. The complete daily occurrence verified13selected
deployments on the host/four guests, with no unselected units, preserved all13
service identities and finished in40seconds at234967040bytes peak. The collector,
helper and existing timer were unchanged; only the host manifest reference was
added under the existing configuration lock. The disposable17,590,192-byte archive
was hash-verified and retired after receiving confirmation. Current/rollback and
signature/provenance metadata remain. Coverage stays partial; the same coverage
incident advanced to revision6 without replacing its original source/history.
