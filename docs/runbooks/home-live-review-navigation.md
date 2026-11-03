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
