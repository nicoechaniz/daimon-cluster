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

## Reader-filtered project selector

A current work frame may request `home-artifact:review-catalog`. The parent reads
its ordinary same-origin `/catalog.json`, already filtered by the current reader
policy. `model_review:true` marks HTML artifacts with both fixed `gallery.json`
and `review-live.json` files. It grants nothing: every later manifest/gallery
read still uses existing per-resource checks, including revocation after listing.
Only marked artifacts, at most64 resources, are projected as resource/title pairs
to the isolated child; links, recipients, paths and unreadable metadata are absent.
Catalog responses are bounded at1MiB/2048entries and20seconds; no persistent cache.

The child may send `home-artifact:review-select` with a resource from that returned
list. Arbitrary resources/URLs/files are rejected before reads. The parent aborts
superseded loads, reads only that resource's fixed manifest and version-pinned
hash-verified gallery under the existing16KiB/25MiB/20second limits. It posts a
candidate with `switching:true` and a bounded request ID; it keeps its accepted
resource/version until the child returns `home-artifact:review-applied` matching
that request/resource/version with `accepted:true`. The renderer stages validated
geometry and waits for matching `home-artifact:review-commit` before applying it;
`review-cancel` drops a superseded/hidden/timed-out candidate. This prevents a
hide/cancel race from relabeling the previous project. Invalid geometry retains the
previous project; the live subscription subsequently follows the accepted one.
Same-project old renderers retain their preceding opt-in bridge behavior. Pinned
historical views offer no selector. Hidden/unloaded pages abort pending work.

The universal renderer contains only its initial permitted gallery. Other model
bytes cross from the authorized parent on selection, rather than being embedded
in the six-reader shared artifact. Project selection resets framing; updates to
the same project preserve the existing view. Copied selection context includes
resource, scene fingerprint and immutable publication version, avoiding ambiguous
identical scene IDs from different projects. No login, user list, service, audience
expansion, background agent attention or model-store duplication is introduced.

Source/browser qualification and receiving activation are separate. This selector
extends the earlier same-resource cutover; its deployment needs its own recorded
review and same-plan GO under repository AGENTS, not inferred from PR343's GO.
