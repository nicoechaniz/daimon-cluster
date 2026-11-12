# Authenticated Cluster resource map

The existing Home gateway serves `/cluster/` and read-only `/cluster/api/fleet`.
Existing shared login and the dashboard's exact reader allowlist remain
Authoritative before and after I/O. Native admissions describe registered bodies,
not model activity. Placement remains operator metadata; a KVM has its own OS
scope and is not another physical host.

## Current foreground freshness contract

`/cluster/api/resources` is a separate authenticated resource/alert read lane.
It never resolves native admissions, scans token history or requests account
windows. The browser polls it every3seconds while visible, with one in-flight
request and a12second transport deadline. The existing private owner socket
accepts only an optional <=256byte `{"view":"resources"}` enum; callers cannot
select commands, paths, credentials or hosts. Legacy no-frame callers retain
the original full snapshot. Resources use a separate lock and replaceable
128KiB cache (1second reuse), never the slow usage lock. At most8configured
hosts/4parallel probes are allowed; each resource probe has4seconds and skips
onboarding job/service enumeration. No new service, timer or model is required.

The frontend labels each metric using its actual `reading.observed_at`, not the
HTTP response date. It ages those labels every second, even without another
successful fetch; after15seconds it visibly stops claiming a recent measurement.
A failed read preserves only the last real sample and its original date, marks
it unavailable, and does not turn a missing value into zero. Returning to a
visible page refreshes immediately. Native inventory/token/account data have
an independent30second browser cadence and retain their own source dates;
existing owner usage caching is60seconds. Slow or failed usage cannot freeze
disk/RAM/CPU or alert updates. These are sampled live readings, not an atomic
fleet-wide measurement or a promise of zero network delay.

Host summaries and expanded host details resolve alerts from the same current
projection by exact resource ID. Details include severity, summary, next action,
acknowledgment and source update time. A failed alert query remains visibly
unavailable, with any prior bounded rows dated; it is never presented as no
incidents. Both API lanes enforce the same exact Home human grant before I/O
and recheck it afterward. Authentication failure clears displayed private data.
No browser persistence or changes to incident acknowledgment/resolution occur.

Optional `observability` in the protected dashboard configuration accepts:

- `health_file`: absolute reference to a private atomic Pulso
  `computer-health/v1` report, maximum128KiB/eight targets. Use the maintained
  computer-health collector and existing pinned read routes. Collect only selected
  hosts; retain the original timestamp on failed reads. No collector or timer is
  installed by opening the page. This legacy file is dated source data; it cannot establish the live-lane freshness contract.
  A one-second CPU sample is not a trend.
- `alerts`: `base_url` (existing explicit loopback HTTP endpoint) and `token_file`
  (private receiving credential reference). The backend reads at most100open
  incidents/1MiB with a three-second timeout and no redirects/proxies. Pagination
  is explicitly partial. Existing receiving scope governs visibility; it is not
  fleet-wide coverage. Credentials and delivery records never enter the response.

Missing, stale or unavailable sources are unknown, not healthy. Acknowledgment
and producer resolution remain separate. The dashboard exposes neither control.
Do not reuse another being's private scope to claim unified coverage: qualified
per-host receiving adapters and current reader grants are required first.

Full inventory reads retain their three-second in-memory cache; resources use
the independent lane above. Both refresh only while visible. No private browser persistence, history store,
model wakeup, inbox read or additional background observer is introduced. Retain
one replaceable private health snapshot and the prior software selector for
rollback; do not restore application databases or incident journals.

Qualification includes credential/snapshot privacy, symlink refusal, actual HTTP
read-only filtering, partial lists, unavailable sources, existing access denial
and post-I/O identity recheck. Source tests, deployment and real device acceptance
are separate observations.
