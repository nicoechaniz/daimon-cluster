# Selected application inventory without package execution

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
