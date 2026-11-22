# Children's host daily maintenance

The maintained Security handoff is Shared Resources
`docs/services/children-host-security.md`. Full daily maintenance remains
unfinished. The first deterministic phase is `tools/children_daily.py`; it
collects the selected host and four guests and matches Debian package evidence.
The Debian matcher itself installs no packages. The currently selected optional
phases include bounded compiler cleanup, no-wake browser metadata and
[selected application inventory](children-application-inventory.md). The existing
reviewed package coordinator is a separate declared dependency. No phase starts
a model or opens a browser for a health check.

## Inventory and Debian advisory phase

Use the receiving operator's private configuration and selected source digest:

```
python3 tools/children_daily.py --config CONFIG
```

The closed configuration schema is `cluster-children-daily/v1`, with `state`,
`scanner`, `scanner_sha256` and the explicit five-entry `targets` list. The
configuration selects the existing host and child guests; it cannot accept an
arbitrary shell command. The scanner is the Debian-maintained debsecan payload
from a signed APT package index, checked by exact package and executable hashes.
Extracting that payload does not install its maintainer scripts, cron or mail
configuration. Resolve actual locations from the private receiving record.

The collector uses the official trixie debsecan feed, verifies its compressed
format, then runs the vendor matcher against each observed dpkg status file.
No package list is uploaded. A new feed is matched against the entire current
inventory, so changed advisories and newly installed packages are reconsidered.
It includes unfixed vulnerabilities. Distribution source-package findings need
triage: documentation-only binary packages and vendor backports can affect
applicability. See the [Debian manual](https://manpages.debian.org/trixie/debsecan/debsecan.1.en.html).
No finding count establishes exposure, exploitability or a loaded fix.

Each target records its OS, running kernel, available memory/swap, cgroup
allowances and filesystem observations. Filesystem availability is explicitly
not quota-aware; keep the existing independently verified Incus quotas and
storage observer. Offline guests, malformed inventory or unavailable feeds are
unavailable/unassessed, never healthy empty results. Raw stderr is not published.

Run through the existing visible tmux and a finite systemd service, with
900-second runtime, 512 MiB memory, 25% CPU and 64 tasks. Each inventory command
has a 20-second bound; local matching has 40 seconds. Capture is bounded at
8 MiB per inventory and 4 MiB per matcher, with a 4 MiB dpkg status cap. The feed
is at most 16 MiB compressed and 64 MiB expanded. One flock prevents overlap.

Private state keeps current inventory/findings and current/previous successful
resource receipts. Resource and aggregate summaries are capped at 256 KiB.
Admission refuses a state tree already above 384 MiB; the final cap is 512 MiB.
It never deletes findings, pending incidents or unfinished work to make room.
A capacity refusal needs operator reconciliation. This phase creates no growing
per-run archive or duplicate backup. Preserve actual native history separately.

Exit 0 means these Debian inventory/matching calls completed, not full security
clearance. Exit 2 records incomplete source/target coverage. The result always
marks the larger assessment partial. Its `phases` map reports current Debian
matching, application inventory, compiler cleanup, browser metadata and selected
public/known-exploitation advisory reads separately. Only the current selected
resources count: a missing or failed target keeps its phase incomplete, and an
unselected adapter is not observed success. Successful source collection with
pending applicability remains visibly pending; no empty result clears exposure.
The finite command now reports `observation_complete` and `needs_triage`
separately. Successful advisory reads with pending findings return0 for execution
health, while `coverage=partial`, findings and the daily-security coverage
incident remain open. A missing source/target, failed selected adapter or empty
inventory still returns2. Do not reinterpret the scheduled-job observer's
recovery as vulnerability remediation or completion of the separate coverage
incident.

Package transactions and incident delivery/missed-run supervision are marked as
external producers, because they have their own invocation/effect receipts.
This collector neither repeats those operations nor infers their completion.
The remaining general assessment gaps concern malicious releases and full
application provenance, loaded state and exposure. Do not repeat a successful
browser or cleanup operation merely to satisfy the retired static phase labels.
A successful oneshot does not prove those remaining capabilities or human reading.

## Receiving qualification and continuation

Focused tests exercise real subprocess timeout/output bounds, failed reads,
compressed-feed schema/truncation/expansion limits, redirect refusal, symlink
preservation, offline/unavailable coverage and preservation of an observed
inventory when the separate vendor matcher fails. Run:

```
python3 -m unittest tests.test_children_daily -q
```

The initial receiving run is a finite foreground qualification. The maintained
`deploy/systemd/children-daily-inventory.service` and matching timer run only this
selected finite phases daily at 05:00 UTC, with up to ten minutes of jitter and one
persistent catch-up after downtime. Copying the assets does not enable them.
The trusted operator must first select the checked immutable source through
`/opt/children-maintenance/selected` and install the private configuration/vendor
payload. The service's only writable persistent tree is its bounded daily state;
its disposable Incus client configuration lives in its private runtime directory.
It uses the existing local Incus operator route and grants no guest access to the
host. The hard timeout applies only to inventory/matching, never package writers.

Qualify the installed service once from the existing visible tmux, inspect its
actual result and all five targets, then enable the timer. Check the next elapse
and real service limits. Disable future runs with
`systemctl disable --now children-daily-inventory.timer`; this preserves receipts
and does not cancel a running read-only check. Stop that service separately only
when intended. Installation, enablement, exercised matching, alert delivery and
missed-run supervision are separate observations.

A finished, otherwise unreferenced systemd oneshot can be unloaded and lose its
transient `ExecMainStartTimestampMonotonic`/invocation properties. A zero value
is not proof that it did not run. For that case use the retained journal's same
boot and invocation: link the collector's exact five-target result to the unit's
completed job after the installation checkpoint. Do not rerun a successful
collector merely to replace an observation that systemd has reclaimed.

Continue the same source into the complete daily pipeline, with the scoped Alerts producer and
missed-run observation, supported activity-aware storage hygiene and actual
package/download policy. Keep host and four guest coverage distinct. The
stop path disables only its future timer, preserving receipts and any safe
active transaction. Never put a package installation under this read-only
collector's hard timeout or infer reboot/removal permission.

## Selected malicious-release observation

The existing OSV public-version matcher already includes the
[OpenSSF Malicious Packages source](https://google.github.io/osv.dev/data/).
The collector projects its verified `MAL-YEAR-NUMBER` record IDs or aliases into
`phases.selected_public_python_malicious`; it creates no second feed, network
request, scanner or timer. Only the existing explicit public PyPI names and
observed declared release versions are covered. Summaries never determine the
classification. Active no-fix/non-CVE reports remain pending, aliases deduplicate,
and withdrawn records retain their attribution without claiming remediation.

`observed` requires the current successful query, its exact version-query digest,
complete record and alias-group projection. Offline/stale-only source results,
changed queries, missing records/groups or malformed withdrawal timestamps stay
incomplete and fail execution health. A successful query with no matching
malicious report means no selected triage, not artifact authentication, loaded
code/exposure assessment or a clean-system certificate. Those limits and
malicious releases outside selected public Python versions remain explicitly
unassessed. The broader coverage incident is not resolved by this projection.

The native selected service, its900second/512MiB/25%CPU/64task bounds, current and
previous receipts,512MiB state ceiling and supported disable path are unchanged.
A source-only rollout retains the exact predecessor code/config and verifies a
fresh real occurrence through the existing service. It never repeats a package
transaction or starts a child model/browser for qualification.
