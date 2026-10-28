# Same-resource live model review

The isolated artifact cannot discover a later immutable publication by fetching
relative files. Its trusted work-view parent provides the update route. This
extends the existing gateway; it creates no application, identity or model store.

A current work iframe can subscribe with `home-artifact:live-review` and a boolean
`enabled`. Repeating an enabled subscription requests an immediate check (the
renderer uses it for **Reload models**). Parent-owned frame metadata selects the
resource; child-supplied paths, resource IDs and credentials are never accepted.
Pinned historical views do not install the bridge.

The parent checks fixed `review-live.json`, validates its schema/hash, and reads
only `gallery.json` at the returned immutable native version. It sends validated
bytes as `home-artifact:review-update`. `home-artifact:review-current` acknowledges
a successful check with the publication version, including unchanged versions;
`home-artifact:review-error` reports a generic failed check. A current-publication
acknowledgment is not proof the child accepted its geometry. The renderer retains
its previous model and fingerprint when it rejects a payload.

One request may be pending. Manual requests during a pending request coalesce
into an immediate next check after cleanup; they never create concurrent reads.
The normal interval is10seconds, bounded failure backoff60seconds and request
timeout20seconds. Hidden/unloaded views abort requests and timers. Manifest size
is limited to16KiB and gallery bytes to25MiB, including streaming responses.
No model wakeup, agent watcher, reader-presence history or recurring server job.

The shared renderer owns per-scene content fingerprints, visible short model
versions, copied selection context and in-place camera/control preservation.
See AlterMundi/Skills3d-design-and-fabrication reference interactive-review.md.
Projects must preserve normalized scene versions when rewriting gallery JSON.

Run affected `test_home_live_review.py`, `test_home_gateway.py` and
`test_home_work_bridge.py`, then qualify a sandboxed real renderer: unchanged
manual check downloads no geometry; a changed model preserves document, camera,
controls and selection; rejected models retain their accepted version. Source
publication and fixture success do not mean the receiving gateway is activated.
Follow receiving live-cutover consent/review and same-plan GO. Preserve the
selected runtime, configuration, session/authority stores, grants and other apps.
