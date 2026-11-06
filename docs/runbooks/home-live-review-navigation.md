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

Installed public assets (the exact home CSS, viewer/access/style JavaScript,
enabled passkey JavaScript and installed font routes) validate the same home,
Host and Origin without resolving ambient identity. Their bytes do not depend
on a session, so an authenticated reader must not replay authority proofs to
download them. GET and HEAD use the same path; private data, status/identity,
personal style, publication, SSO and content authorization retain their existing
checks. This is not an extension-based static allowlist, a new audience, a
session cache or permission to cache private responses. Login-host assets remain
owned by their preceding shared-login dispatcher.

## HTTP transport qualification

`tests/test_home_gateway.py::test_slow_connections_expire_without_blocking_authorized_reads`
starts two disposable loopback listeners with the real viewer/owner handlers and
the existing fictional authority/session fixture. Six clients leave headers or
a small POST body incomplete; sixteen other GETs run with four concurrent readers.
The viewer reads use an actual fixture session. Owner GETs must remain 404.
The test observes handler completion at the existing real 30-second socket
inactivity timeout and closes every client/server afterward. It uses no live
credentials, production load, daemon, scheduler or remote service. Allow about
31 seconds for the actual timeout check rather than replacing it with a mock.

The first local run passed in 30.76 seconds. This establishes isolation from six
idle incomplete requests and eventual cleanup for that fixture; it is not an
HTTP throughput benchmark, a production percentile or a hundred-client capacity
claim. The socket timeout measures inactivity, not a total request deadline.
Continuous slow input, an arbitrary number of concurrent handlers and a blocked
upstream therefore remain separate cases. Do not infer a worker-count cap or a
whole-request deadline from this test. Assess the existing Caddy edge and actual
upstream streaming behavior before adding a second queue, changing transport or
selecting bounds that could interrupt valid uploads/large-model downloads.

Current production servers use daemon handler threads; test listener shutdown
and source rollback do not establish completion of any live client request.
Keep the receiving operator's bounded response and browser-stage measurements
alongside this test. Cluster #405 retains the remaining device, large-model and
transport qualification work.
