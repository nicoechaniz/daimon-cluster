# Bounded development storage retention

`tools/storage_hygiene.py` maintains explicitly configured incremental compiler
caches and explicitly retired, clean, integrated worktrees. It is a finite
oneshot, dry-run by default. It never traverses the host looking for arbitrary
old directories to delete.

## Configuration and execution

```json
{
  "projects_root": "/srv/projects",
  "allow_privileged_process_scan": true,
  "min_age_days": 14,
  "cache_min_age_days": 2,
  "max_cache_dirs_per_run": 100,
  "cache_roots": ["/srv/projects/example/workspace/target/dev-small/incremental"],
  "worktree_roots": ["/srv/projects"],
  "retired_worktrees": []
}
```

Run `python3 tools/storage_hygiene.py --config CONFIG` to inspect, then append
`--apply` to remove eligible caches. Retain the existing scheduled service rather
than adding a second producer. An hourly timer with a five-minute timeout, idle
I/O priority, and 128 MiB memory limit is sufficient for bounded passes; record
actual completion results separately from timer enablement.

Only `target/debug/incremental` and `target/dev-small/incremental` in a Cargo
workspace inside the configured Projects tree are eligible. Nested workspaces
are supported. Root configuration is validated before any deletion. Symlinks,
foreign-owned files, and any directory containing a member changed within the
retention window are retained. Executables, dependency libraries, release builds,
source, sessions, databases and snapshots are outside this cache policy.

The host process scan includes command arguments, cwd, executables, open file
references and mapped files. A project in use is skipped, and activity is checked
again before each removal. A failed activity scan prevents further cleanup.
Configure the privileged read-only scan on a shared host; it uses fixed isolated
Python code and never logs process contents. Deletion runs as the owning user.
This is conservative observation, not a global build lock: applications can start
between observations. Removed incremental state is rebuildable, and the compiler
may need more time on the next build. Do not use this tool to prune runtime files.

Worktree retirement requires `--retire-worktree PATH --repo REPO
--integration-ref REF`. It retains the original seven-day minimum and additionally
requires an unchanged branch/commit, integration ancestry, no ignored/untracked
files, no lock, and Git's own non-forced removal check. Age alone never registers
a worktree for retirement.

A per-configuration flock prevents overlapping cleanup runs. Each run reports
removed/skipped/error counts and before/after free space without private paths.
The count budget applies to cache removals; timeout can interrupt a pass. Inspect
its exit result and next pass instead of claiming that all candidates were removed.

## Placement, compression and capacity

Large test datasets and retained qualification copies belong on a data volume,
through their owning configuration. Keep small control state and selected runtime
paths stable. Never globally redirect `TMPDIR`, XDG state or Cargo target paths:
existing harnesses, Unix sockets and tests can depend on those paths.

For Btrfs, compression is filesystem-wide across subvolumes and must be persisted
consistently for every mount. Enabling it affects new writes; it does not reclaim
all existing files. Recursive defragmentation can break reflink sharing. Avoid a
whole-filesystem rewrite, particularly while Incus shares the same volume.
See the [Btrfs compression documentation](https://btrfs.readthedocs.io/en/latest/Compression.html).

Compression and cache retention do not provide unlimited capacity. Keep root and
data-volume availability separately monitored, preserve pending/uncertain work,
and record remaining staging/release/backup retention gaps in the owning issue.
Do not resolve a storage incident through acknowledgment or changed thresholds.

## Finite byte, entry and time budgets

`max_bytes_per_run` (default1GiB, maximum4GiB), `max_entries_per_run`
(default100000, maximum1000000) and `max_seconds_per_run` (default120,
maximum300) bound each pass in addition to its directory count. Eligibility
walks and final repeated validation consume the entry/time budget. An oversized
candidate is kept whole; earlier completed removals retain their measured byte
count (logical file bytes, not a guaranteed physical-space recovery). Flat
non-directory entries also consume the inspection budget. A byte/entry/time stop reports `budget_exhausted` and a nonzero CLI result,
never claims complete cleanup or evicts protected data. Explicit worktree removal
uses the same budgets and original clean/integrated/retired checks.

The programmatic `activity_scan` callback is an alternative to the existing own
or sudo process scan, not permission to supply a stale snapshot in production.
It must return a fresh complete projection on every call. `active_paths` remains
for controlled fixtures. A failed scan prevents subsequent removal.

## Children's own guest route

`tools/children_cache_cleanup.py` reuses this cleaner without granting `agent`
sudo. A finite root parent runs the existing fixed read-only process scan;
a forked worker permanently drops real/effective/saved identity to `agent`,
clears supplementary groups and environment, and performs the deletions. Inherited
bounded JSON IPC accepts only scan requests and final counts. The parent verifies
the actual child UID before scanning and returns only busy selected project
roots, never raw process arguments/paths or arbitrary privileged operations.
There is no new network listener, permanent broker or administrative login path.

The private root policy has schema`children-compiler-cleanup/v1`, user`agent`,
projects_root`/home/agent/Projects` (or a selected subtree for technical fixtures)
and max_bytes_per_run256MiB. Discovery checks at most64 immediate project entries,
2048 workspace entries and64 Cargo cache roots, one nested workspace level. Only
real Git/Cargo debug/dev-small incremental roots qualify. Hidden/symlinked or
unclassified trees are preserved. Future eligible repositories in this selected
tree need no per-pair cache ceremony; unknown cache classes are not inferred.

The guest policy removes at most32old cache directories/256MiB, inspects at
most20000entries and has a40s internal cleanup budget. The native unit has90s,
128MiB,25%CPU and32tasks. Its sandbox allows writes only to its private state and
own Projects; other home state is read-only. Each privileged read has10s/8MiB
bounds, IPC frames16KiB and at most34scan requests. Root state is at most1MiB,
current/previous successful report only. Existing bounded journals apply.
Profiles, executables, release artifacts, sources, original media, credential and
memory stores remain outside this policy. Browser-session lifecycle, other cache
classes and explicit worktree retirement stay separately unassessed; the wrapper
does not invent retirement records or close a human's browser.

The existing daily collector optionally selects `compiler_cleanup_enabled:true`.
It starts each own guest's `children-cache-cleanup.service`, reads the bounded
actual result, and keeps cleanup status separate from inventory/advisory evidence.
A failed cleanup degrades the collector exit without discarding real inventory.
The existing scheduled-job Alerts target therefore observes failure/missed runs;
no extra timer or producer is needed. Disable future cleanup by selecting false
in the same private collector config, preserving other phases, state and timers.

Actual qualification used a new isolated subtree under the own Projects tree and
an artificial age cutoff confined to that fixture; production uses real time.
A live own-user file holder kept its project intact; recent, symlinked,
foreign-owned, release and unfinished-source examples survived. Only one5-byte
old cache was removed. A1-byte budget kept an oversized candidate, and simulated
unavailable process observation prevented removal. The exact verified disposable
fixture was retired. This is not evidence of child participation or a production
browser capture, and it does not establish all broader cleanup acceptance.

Incus may load a generic `service.d/zzz-lxc-service.conf` that overrides
NoNewPrivileges from the base unit. The cleaner therefore installs its own
`children-cache-cleanup.service.d/zzzz-children-no-new-privileges.conf`, scoped
only to that finite unit. Keep the generic LXC drop-in unchanged. Receiving
qualification checks effective systemd properties and `/proc/self/status`, not
just the unit text. The production CLI refuses to clean unless its actual kernel
NoNewPrivs flag is1, and reports that observation alongside actual deletion UID.
Other LXC sandbox overrides remain explicit; a base directive is not proof that
the container's service manager enforces it.
