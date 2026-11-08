# Children's host daily maintenance

The maintained Security handoff is Shared Resources
`docs/services/children-host-security.md`. Full daily maintenance remains
unfinished. The first deterministic phase is `tools/children_daily.py`; it
collects the selected host and four guests and matches Debian package evidence.
It neither installs updates nor deletes files or starts a model/browser.

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
marks the larger assessment partial, with upstream/malicious-release coverage,
patch transactions, browser/cache cleanup, incident delivery and missed-run
supervision explicitly unassessed until their actual maintained adapters pass.
A successful oneshot does not prove those missing phases.

## Receiving qualification and continuation

Nine focused tests exercise real subprocess timeout/output bounds, failed reads,
compressed-feed schema/truncation/expansion limits, redirect refusal, symlink
preservation, offline/unavailable coverage and preservation of an observed
inventory when the separate vendor matcher fails. Run:

```
python3 -m unittest tests.test_children_daily -q
```

The initial receiving run is a finite foreground qualification. No recurring
daily timer is selected merely by copying this script. Continue the same source
into the complete daily pipeline, with the existing scoped Alerts producer and
missed-run observation, supported activity-aware storage hygiene and actual
package/download policy. Keep host and four guest coverage distinct. The
stop path disables only its future timer, preserving receipts and any safe
active transaction. Never put a package installation under this read-only
collector's hard timeout or infer reboot/removal permission.
