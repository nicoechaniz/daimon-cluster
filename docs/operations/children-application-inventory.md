# Selected application inventory without package execution

Invoke `python3 -B -I -S tools/children_application_inventory.py --units NAME.service`
through the bounded native read job. It reads explicitly selected systemd main
processes. It binds executable bytes to the actual running PID, then checks the
service is still active with that PID. It captures executable path/SHA, not
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
