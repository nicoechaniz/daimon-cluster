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
