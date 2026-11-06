# Current shared review navigation

Current model viewers accept `?project=<32-character resource ID>` alongside
`display=work`. The authenticated reader catalog validates that candidate before
any model fetch. Successful child acceptance commits the project, remembers it
locally under the renderer resource, and updates the address without reloading.
A plain launch restores the last accepted project for that renderer when browser
storage is available. Denied or malformed candidates cannot select a resource.
Pinned historical/source reviews ignore both query and stored preferences.

This changes only startup/selection. Existing manifest integrity, current grants,
opaque child, acknowledgment, visibility and finite request lifecycle still apply.
No credential, new account, renderer duplication, agent watcher or global Stop
is involved. If storage is blocked, explicit project links continue to work.

Qualify with `tests/test_home_live_review.py`, then actual authenticated browser
readback on a fresh project URL. Preserve the previous immutable gateway release
and activate through the existing service override; do not modify releases in
place or restore old publication/state data during software rollback.

## Publication authority latency

Owner publication validates the current signed actor catalog once per authenticated
request and reuses that request-local lookup for all selected recipients/resources.
It never caches the catalog across requests; a recipient revoked before the next
request must still be rejected. This avoids repeatedly replaying the same signed
authority reconstruction until the native publisher times out.

If owner sync times out, inspect the actual request/service outcome before retrying.
The native publisher retains local immutable state on a lost sync, so retry the
identical publication with reuse-identical after repairing the owning path. Do not
create a new audience, restore a database, widen access or replay printer actions.

## Reader request performance

GET/HEAD routes reuse successful verified public identity bindings, authority
histories and actors only inside that request. The scope is lazy and context-local;
threads and nested scopes do not share it, errors do not populate a successful
result, and it is reset in `finally`. The next request reads current sources.
Shared-login routes run before this scope: external login exchanges and session
mutations must keep their fresh post-I/O checks. POST/owner operations are unchanged.
Relationship authorization views, current time, human rosters, resource registry
and sessions are never memoized by this scope.

The current viewer retains at most three child-accepted decoded galleries in one
mount. Its conservative 48 MiB accounting includes wire expansion and vertex/face
arrays; this is a retention budget, not a browser heap or GPU limit. Oversized
models remain renderable without retention. Every switch first fetches the
protected current manifest with `no-store`; reuse requires the same resource,
version and gallery digest. A denied resource evicts its retained data. Child
validation/acknowledgment still precedes committing a switch. Page exit/disposal
releases retained galleries; no browser storage, public cache or grant cache is
introduced. Cloning to the opaque child and GPU work still occur on warm switches.

Use `tests/test_home_owner_authority.py`, `tests/test_home_gateway.py` and
`tests/test_home_live_review.py` for these boundaries. The closed Homes CI profile
also covers shared login, passkeys, resource policy and the viewer bridge.
Measure authorized catalog/manifest responses and cold plus A→B→A browser journeys
separately from device acceptance. Server identity-encoded transfer timings do not
measure phone rendering. Keep the preceding immutable gateway release for a
source-only rollback through the existing service override; preserve the current
config, credentials, session/resource databases and Homemaker source selection.
