# Authenticated Cluster resource map

The existing Home gateway serves `/cluster/` and read-only `/cluster/api/fleet`.
Existing shared login and the dashboard's exact reader allowlist remain
Authoritative before and after I/O. Native admissions describe registered bodies,
not model activity. Placement remains operator metadata; a KVM has its own OS
scope and is not another physical host.

Optional `observability` in the protected dashboard configuration accepts:

- `health_file`: absolute reference to a private atomic Pulso
  `computer-health/v1` report, maximum128KiB/eight targets. Use the maintained
  computer-health collector and existing pinned read routes. Collect only selected
  hosts; retain the original timestamp on failed reads. No collector or timer is
  installed by opening the page. Readings older than five minutes are dated.
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

Reads share the existing three-second in-memory fleet cache; the browser
refreshes only while visible. No private browser persistence, history store,
model wakeup, inbox read or additional background observer is introduced. Retain
one replaceable private health snapshot and the prior software selector for
rollback; do not restore application databases or incident journals.

Qualification includes credential/snapshot privacy, symlink refusal, actual HTTP
read-only filtering, partial lists, unavailable sources, existing access denial
and post-I/O identity recheck. Source tests, deployment and real device acceptance
are separate observations.
