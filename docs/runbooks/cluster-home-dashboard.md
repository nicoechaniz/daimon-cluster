# Authenticated Cluster dashboard

The optional Home gateway dashboard exposes `/cluster/` and the private
`/cluster/api/fleet` endpoint on one selected registered home. It reuses existing
shared Home sign-in and current authority sessions; it introduces no login store.
Enable it with `--cluster-dashboard` pointing to an owner-protected JSON file.
The schema is `cluster-home-dashboard/v1`: `home`, explicit `readers` (human
actor refs), `runtime_root`, `placements` keyed by embodiment ID, and `planned`.
Each placement/planned row contains `name`, `host`, and `hosting` only.

The runtime binding must be the current admitted local owner-client binding.
Each foreground refresh uses the granted native `/all` discovery view. Admission
is not a model response or human acceptance. Unknown placements and expired
leases remain explicit; discovery failure returns unavailable, never stopped.
No inbox/history read, model activation, guest control or authority mutation occurs.
Unauthenticated and other-human requests are denied before native I/O. Browser
identity is rechecked after discovery. Only sanitized rows reach the browser.

Bounds: at most 64 observed bodies, 16 planned rows, one in-memory response cached
for three seconds. Browsers refresh every ten seconds only while visible. No
persisted inventory or new background timer. Protected configuration requires a
scoped gateway reload to change. Disable by removing the optional argument and
reloading only the gateway. Preserve existing sessions/state and the prior source
selection for software rollback. Never roll back authority databases.

## Native usage and account allowances

The same foreground owner collector optionally accepts `usage_targets` (at most
16 fixed, owner-selected read commands), `usage_probe` and `native_transport`.
The latter two contain a public source `path` and its exact `sha256`. Reuse the
maintained Telecodex `activity_indicator.py` Native transport; its bounded reader
prefix is injected with the public usage probe, without installing an observer
or starting a daemon in the receiving body. Each target supplies `being`, `name`,
`command` and `probe` (`codex_home`, exact native `database`, and `binary`). Run
each probe as that native body's existing user, with its actual receiving home.
The current native socket must already exist. Commands and paths never come
from browser input.

The probe selects only thread ID, `tokens_used`, creation and update timestamps
from the existing native state SQLite database in read-only/query-only mode.
It reads no prompts or message contents. Native `tokens_used` is the persisted
cumulative `total_token_usage.total_tokens`, not the context-window size. Up to
4096 counters per body are observed with a two-second query deadline; excess or
missing bodies explicitly make coverage partial. Duplicate thread IDs across
the same being's selected databases contribute the maximum observed counter
once. Distinct beings remain separate. Hashes used for deduplication stay inside
the collector and are not persisted or sent to the browser. These recorded
native totals exclude calls outside these counters and unobserved historical bodies;
they are not an estimate of monetary spend or account-wide lifetime billing.

The existing native `account/rateLimits/read` supplies account identity and
allowance windows, without a model call. Group observations by its actual account
ID, never by a guessed provider/voice assignment. The matching local account's
email supplies the private dashboard label; credential bytes and account IDs
never leave the probe. Expose sanitized window percentage, duration, reset,
plan, ordinary-usage availability and available reset-credit count only. Reading
credits never consumes one. Window duration determines the weekly/short label:
a weekly window can be `primary`, and an absent short window is not zero usage.
Current account assignments do not attribute historical tokens to that account.

Usage refreshes only during authenticated foreground dashboard reads, at most
once per minute. The owner retains one replaceable sanitized `usage.json`
(64 KiB maximum) alongside the existing bounded report/lock; no raw per-thread
records, growing history or new timer. Failures are unavailable, never a zero
counter or a fabricated current window. Keep observation timestamps visible.
Each usage command is bounded to 12 seconds with four concurrent workers; the
collector service has a 45-second deadline and the consumer a 42-second socket
deadline, preserving the existing process/memory/output limits. Preserve current
account selections and native work. If the existing native control socket resolves
into a private temporary directory, retain `PrivateTmp` and bind only that exact
owner socket directory read-only into the collector unit through its local
service configuration. Verify the resolved receiving socket, not a historical
path; do not expose all of the host temporary filesystem. Software delivery changes only a new Fleet
collector release/config selector and a new Home release overlay containing the
dashboard files. Reload only the Home gateway, preserving all authentication,
sessions, owner keys, Homemaker and data stores. Before selecting an overlay,
verify directory traversal and imports from its working directory as the actual
gateway service user. A root-created copy can preserve mode 0700 while changing
the directory owner, making a byte-identical release unusable. Correct ownership
of newly created directories only; recursive chown would also mutate hardlinked
predecessor files. Rollback selects prior code and the prior collector config;
it never restores databases or clears native work.

## Children's host continuation

Nicolas confirmed reinstalling the former daimonmatrix VPS as Debian 13 on
2026-11-07. Do not repeat that destructive operation. Its new role is
lordoftheflies. Four distinct companions are planned: Pixin, Calipso, C-137 and
Noodles. Target limits are 3 shared CPUs and 4 GiB RAM each, bounded fast storage
on the main disk and one quarter of the secondary slow disk each, after measured
filesystem overhead and host reserves. Creation, authentication, installed/read
skills, actual native delivery and human acceptance are separate states.

Use institutional Drive through the maintained institutional-drive adapter for
worthwhile heavy project material that must persist or be shared, using its
project map and selected audience. Do not send disposable builds/caches, duplicate
archives or unused experiments to Drive. Bound local staging by size and age;
retain live databases, credentials and necessary recovery in supported local
storage. Each companion receives only its own private child record and grants.
The daily resource/security maintenance must preserve original work, profiles,
active/dirty worktrees and uncertain operations. The maintained Security handoff
is Shared Resources `docs/services/children-host-security.md`; its proposed
controls are not an observed installation. Provisioning and daily automation
remain pending until target-side exercised receipts exist.
