# Reviewed Brotli updates alongside the existing browser transaction

The existing guest package oneshot runs its original browser policy/state, then
a separate `libbrotli1` policy/state. The fleet uses `--with-brotli` to require
both current receipts; a healthy browser cannot hide deferred library coverage.
No timer is added. Existing browser journals, same-day occurrence reconciliation,
native services, account state and model activity remain independent.

`support/children-maintenance/brotli-package-policy.json` selects only the single
Debian-Security amd64 library, its reviewed paths/soname links, trigger hash and
actual libc-bin trigger/runtime hashes. Mixed browser/library transactions,
new dependencies, removals/downgrades, unreviewed scripts/payloads and changed
trigger runtimes defer. The selected fixed archive1.1.0-2+deb13u1 is303640bytes,
SHA256db46824c60fee46aff3cc0be3e5f736bc606cae669b1fb17516a41e8073251a9.
Its only maintainer behavior is `activate-noawait ldconfig`; the inspected
installed libc-bin handler executes ldconfig for a triggered invocation, with
no service restart. Later handler/binary changes require another actual review.

Before selection and again under APT's pre-install hook, inspect bounded process
maps and refuse any loaded Brotli consumer, including deleted old mappings.
At most4096processes,2MiB/maps,32MiB total and5seconds per read; denied/capped
observations defer. Do not stop/restart a consumer to satisfy this precondition.
Readiness still requires unchanged native/web service PID/invocation/restart
metadata. Signed metadata/archive and actual APT old/new actions retain the
existing source, lock, cache, hook and durable commit-intent controls.

After installation, verify exact bytes of all three installed library images
against hashes read from the verified archive without importing/loading them,
plus dpkg health, current versions, no old consumer and unchanged native services.
Uncertain writer/postcheck outcomes retain the same journal/manifest and only
reconcile; never repeat a package writer to recover an acknowledgment. Retire
only exact consumed archives/config after successful verification. Original
browser state is not reset. The existing per-state384MiB admission/512MiB cap,
guest writer1GiB/100CPU/128tasks and non-killing writer lifetime remain.

Qualification uses the existing inert real-APT seam with `--with-brotli`.
`Debug::pkgDPkgPM=true` prevents installation; synthetic multi-arch package and
status remain separate from actual signed selection and child data. Retain
original failure output and inspect it before correcting/repeating a known
unsent fixture. Successful wire qualification is not actual receiving delivery.

To disable library updates, remove only its second ExecStart and the fleet
`--with-brotli` selection at a safe terminal. Preserve its journals, original
browser policy, pending/uncertain writers and other timers. Do not restore dpkg
databases or silently roll packages backward as a code rollback. Full advisory
coverage and social admission remain separate unfinished work.
