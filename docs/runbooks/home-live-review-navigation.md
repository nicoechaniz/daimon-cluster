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

## Repeated packed meshes

The packed decoder shares vertices/faces for repeated meshes within one decoded
gallery. A reuse requires matching coordinate origin, scale and counts, a digest
match, and an exact encoded-byte comparison against already validated geometry.
Different metadata remains on independent part objects. Existing whole-buffer
integrity, expansion, coordinate and face-index limits are unchanged. No new
wire schema or child protocol is required: structured clone preserves these
aliases while the renderer reads the same arrays. Source CAD and published
gallery bytes remain unchanged. The lookup exists only during that decode;
the existing conservative cache accounting still counts every scene/part and
does not increase its retention allowance because meshes happen to be shared.

Qualify identical meshes, different geometry/coordinates, independent metadata,
forced digest collisions and alias preservation through structured clone with
`tests/test_home_live_review.py`. Compare actual-child switching through the
post-commit painted frame, not only its earlier validation acknowledgment.
An instrumented browser may time the copy/receive stages without changing live
service code; label that as an experiment until exact receiving deployment.

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

## Frozen viewport notes and loading feedback

The opt-in3D renderer advertises `imageCapture` and its current source through the
existing review-adapter capability response. Mark view asks that bound adapter to
confirm the rendered model/camera and capture the2D viewport, then opens a modal
frozen-image drawing surface. The opaque renderer never receives login credentials.
Pointer strokes support touch/pen/mouse and undo, bounded to256strokes/20000points.
Done attempts clipboard PNG export in the click gesture and independently saves
through the existing authenticated parent home. Clipboard refusal leaves a usable
saved link and an explicit retry/open-image path. An uncertain save retains its
exact operation/payload for deduplicated retry; do not edit/re-author a failed save
silently. Closing the workflow releases its retained image/canvas/strokes.

`POST /review-notes` requires current shared identity, exact browser Origin and
current plus pinned-source resource permission. It stores a PNG≤3MiB/2million
pixels plus≤64KiB snapshot; the model remains immutable. Each home retains at most
128notes/128MiB combined PNG/metadata. Notes remain until their author explicitly
deletes them; full storage refuses new saves without discarding older references.
The note page provides author-only deletion (also permitted after model access is
lost). GET page/image/metadata always checks current source and historical-version
access; links grant nothing, public model access alone cannot read a saved note
without authentication. No annotation list or new public catalog is created.

The existing session SQLite owns the additive `review_notes` table. Code rollback
ignores that table and preserves its data; never restore an old session database.
The only larger body allowance is the fixed note-upload route (5MiB); other POST
limits are unchanged. Only the work-preview page permits data images for the local
frozen-canvas workflow; auth and other page CSPs retain their earlier policy.

Project selection paints a viewport-centered live status immediately, including
model-only/fullscreen mode. Parent stages report access check, download and
preparation without invented percentages. Before synchronous child validation,
two animation frames allow the loading status to paint. Matching commit clears
busy state; error/timeout briefly explains that the previous view was kept;
hide/cancel/exit clear pending visual state and superseded preparation cannot stage.
There is no new polling, model attention, grant, or background service.

## Optional bounded HTTP transport

`python -m clusterctl.homes.service --http-transport cheroot` selects the pinned
Cheroot11.1.2 adapter. The default remains `legacy`; source qualification alone
never changes a receiver. Install the existing `requirements-homes.txt` in the
qualified release environment, not a running signed native runtime. Retain the
existing service arguments, stores, credentials, shared proxy and model versions.
Only socket/request adaptation changes: GET/HEAD/POST policy, proof scopes, login,
private static assets, note routes and streaming stay in their existing handlers.

Both listeners remain loopback-only. Viewer/owner thread pools are fixed at8/4,
with accepted queue bounds24/4 and1s admission wait, backlog64/16 and idle keepalive
limits8/2. No worker grows per connection. Active accepted sockets have30s read
and write timeouts; partial headers/bodies occupy bounded workers until completion
or timeout. Queued work is finite but has no per-request wall-clock deadline.
Continuous client/backend progress can exceed30s. This is not a hundreds-reader
capacity claim or a correction for the variable remoteHTTP3 path.

Header limits are32KiB. Viewer body parsing permits5MiB for the existing note-upload
contract; existing policy keeps64KiB for every other POST, and the owner listener
has a64KiB parser bound. Input/output stream through socket files, without a
persistent request archive. The existing route chunk sizes and note retention
remain unchanged. Public TLS/HTTP2/HTTP3 remain Caddy's job. HTTP keepalive/framing
belong to Cheroot; proxy-header identity rewriting is not enabled.
Underscore-bearing header names are dropped by the request reader before WSGI
normalizes names. Otherwise a client spelling such as `X_Daimon_Vpn` could collide
with the canonical proxy-controlled `X-Daimon-Vpn`. Real HTTP regressions cover
both conflicting-header orderings; the pinned upstream underscore reader is not
used because its byte-name handling is incompatible on this interpreter.

The adapter requires raw `REQUEST_URI`, never decoded `PATH_INFO`, preserving
encoded path checks. Missing raw-target support refuses503. Repeated response
headers, HEAD, byte ranges, CSP and versions remain the handlers' responsibility;
request-local proofs close before a pool thread handles another request. A failed
stream terminates the response instead of acknowledging a complete body.

A discarded Waitress3.0.2 draft passed input/authority tests but its active-output
high-watermark wait had no timeout: a non-reading client could retain workers
indefinitely. Do not revive it merely because its partial-input tests passed.
Qualify stalled-output release as well as partial-input expiry on any successor.
The checked Cheroot source uses its accepted socket timeout for writes; the real
non-reading-client regression observes worker release at30s without closing the
client. The small `ClosingConnection` compatibility class explicitly closes the
response file after upstream socket closure: this prevents Python3.13 finalizers
retrying buffered output on a closed descriptor. It does not swallow request
errors or extend timeouts. The stalled-output test also passes with unraisable
exception warnings treated as errors.
See the maintained [WSGI server API](https://cheroot.cherrypy.dev/en/latest/pkg/cheroot.wsgi/)
and [HTTP server contract](https://cheroot.cherrypy.dev/en/latest/pkg/cheroot.server/).

Run the closed Homes CI profile including `tests/test_home_wsgi.py`, then verify
actual authorized gateway and browser reads before claiming receiving adoption.
Rollback selects the prior release/transport while preserving current SQLite,
notes, publications and grants; never restore an old state database. Only the
shared Homes service needs restarting, not native/Matrix/bot/Interaction.

## Opt-in per-scene loading

The gateway advertises `reviewScenes: true`; only a child that explicitly sends
`home-artifact:review-scene-support` selects this path. All other combinations
retain the existing complete gallery fallback. The optional `scene_index` in
`dm.review-live/v1` pins `scene-index.json` and its SHA256. Its
`dm.review-scene-index/v1` entries retain complete ordered selector metadata,
initial scene ID, fixed `scene-NNN.json` names and individual SHA256 digests.
Each packed file decodes exactly one scene whose canonical quantized scene and
part metadata must match the index. All reads use the existing authorized
immutable resource/version route, including pinned views and cache hits.

Limits are64scenes,256parts per scene,256KiB index and existing25MiB file bound;
the producer separately bounds the combined index/scene files to25MiB and retains
a full legacy gallery. Parent decoded retention remains3entries/48MiB estimated
geometry. Large uncached scenes remain usable. The child keeps selected geometry
plus transient candidate; inactive scene entries become metadata-only stubs.
No browser storage, grant cache, new endpoint or arbitrary asset URL is added.

Scene preparation uses the existing staged update/apply handshake and an extra
`review-committed` acknowledgment before parent resource/version/cache advances.
Selection, restore, visibility and publication changes share the child's intent
generation. A cancellation matches its in-flight/staged request ID; cancellation
of a superseded validation cannot cancel the newer selection. Snapshot restore
validates before fetching and again before synchronous state application.

Run the existing parent tests and the paired portable Chromium fixture in Skills
`3d-design-and-fabrication/scripts/test_review_bridge_browser.py` with explicit
installed parent JS, Playwright, Chromium and private work directory. The fixture
intercepts only synthetic origins, bounds its temporary stage to1MiB and runtime
to100seconds, and retires its stage on exit. It covers32selectors/one initial
scene, restore, late response and acknowledgment-phase supersession, revoked
cached data, failed downloads, hidden views, publication changes, pinned views
and full legacy fallback. Production publication and actual device performance
remain separate receiving checks. Rollback selects the previous gateway and
project publication; never restore application databases or change grants.


## Opt-in bounded iframe JSON text

The parent advertises `reviewJSON:true`; only a source/origin-validated explicit
`home-artifact:review-json-support` enables `galleryJSON` in existing update
messages. All envelope fields, current authorization/digest checks, model
validation, intent cancellation and two-phase commit remain unchanged. Children
without this capability receive the original `gallery` object. Updated children
reject ambiguous object+text, malformed/oversized text and unsupported senders,
retaining the previous view.

Before stringify, the parent counts actual JSON punctuation, escaped UTF8,
metadata and finite numeric representations. It stops at the negotiated ceiling,
four million nodes
or32levels; unsupported values and negative zero fall back without losing original
semantics. Repeated references count each serialization. A final allocation-free
UTF8 consistency check guards the result. No serialized-string cache or new
endpoint exists. Children advertise `maxBytes` in their existing support message;
missing values retain the legacy4MiB allowance, malformed explicit values disable
text, and valid positive integer allowances are capped at32MiB. Old parents
remain4MiB senders; old enabled-only children never receive larger text. The
32MiB ceiling bounds the decoded iframe representation, not source downloads.
It is serialized size, not a heap/GPU bound; JSON loses
shared-array aliases. Existing3entry/48MiB conservative retention stays.

Qualify Unicode/control escapes, fractional/exponent numbers, repeated references,
negative zero, oversized/deep metadata and exact boundary behavior. Run the paired
opaque-child fixture with full ordered geometry/metadata equivalence, malformed
text, legacy fallback and existing revoked-cache/cancellation/restore races.
Actual browser before/after must separate authorization, body transfer,
serialization/parse and visible render; small synthetic geometry alone does not
establish a production improvement. Existing published renderer HTML needs its
explicit compatible refresh; selecting a parent does not upgrade old artifacts.

### Verified public-proof reconstruction

The shared gateway's `NativeAuthority` retains only successfully constructed
public proof objects, keyed by constructor kind and exact canonical constructor
input. It reads protected sources again before looking up the cache and still
checks current origin, source forks/pins, actor revision, sessions, relationship
cards and roster expiry. This is not a cached permission decision or a TTL grant.

Each authority instance has a private synchronized LRU: at most16entries and
16MiB of conservative accounting (64times canonical input bytes plus64KiB per
entry). Oversize proofs bypass retention. Accounting bounds retained eligibility;
it is not a process peak-heap guarantee. Returned proof objects are defensive
copies because SDK frozen dataclasses contain mutable nested state. Exceptions
never populate a successful entry. No disk cache, credential storage or new
worker/timer is introduced; restarting the gateway drops this disposable cache.

Qualification must exercise changed controls/history with unchanged manifests,
invalid/unreadable sources after warming, current-source forks/pins, time-based
and revoked authorization, nested caller mutation, concurrent access and byte/
entry eviction. Compare actual authorized manifest response times before/after;
constructor microbenchmarks alone do not establish browser or network latency.

## A related work from an isolated study

The trusted work frame advertises `relatedWork:true` with its existing
`home-artifact:capabilities` message. A selected study may then offer one action:

```js
addEventListener('message', event => {
  if (event.source !== parent || event.data?.type !== 'home-artifact:capabilities'
      || !event.data.relatedWork) return;
  parent.postMessage({type:'home-artifact:related-work',
    resource:'0123456789abcdef0123456789abcdef', label:'Open 3D viewer'}, '*');
});
```

Use an actual selected same-home resource ID. The parent accepts only its own
opaque child, an exact lowercase32-hex resource ID and a nonempty plain-text
label of at most80characters. It renders at most one ordinary link in the trusted
outer header. Messages never click it or navigate automatically; a user click
opens `/view/RESOURCE?display=work` on the same Home. That destination performs
its normal current identity/audience checks. Offering a link grants no read,
changes no permission and exposes no session or owner API to the child. External
URLs, API paths and another frame's messages cannot select a destination. A new
child load clears the previous action. Fragment and selected-download behavior
remain unchanged; the sandbox remains exactly `allow-scripts`.

This is useful for one evolving study with one link to its existing model viewer.
Do not create another renderer or a card per model revision. The artifact's old
`target=_top` link remains blocked; use the advertised action instead. Keep the
previous immutable gateway source for software rollback, preserving all current
publication, auth, session and resource state. Qualify the opaque-child request,
ordinary click, destination refusal and mobile layout separately from actual
human-device acceptance.

## Stable Apps launches and interface versions

Shared and author-dependent web cards advertise `/apps/open/<publication-id>`
on their owning Home. This alias reads the current authorized publication on
every navigation and redirects to its selected target; updating the existing
publication ID updates the destination. It is not another version registry.
Unknown, withdrawn, denied or ambiguous selections return404. Query parameters
cannot override the destination. Existing paired receiver routes remain unchanged.
Keep meaningful application query parameters in the publication target; do not
publish cache-busting release queries as the canonical user entry.

The shared Apps, Cluster, Homemaker and artifact-view shells display a small
`ui` hash derived from their selected interface bytes. This identifies that
interface, independently of the displayed project's model/content revision or
backend release. Immutable work bytes and private grants are untouched.
`/app-build.css` uses the existing appearance roles; the fullscreen label does
not capture pointer events. A public Apps reverse-proxy projection must include
this stylesheet; aliases use their owning Home rather than forwarding sessions
through the anonymous aggregate host.

Qualification: gateway/launcher/Fleet/Homemaker and build-label tests, followed
by actual catalog/alias/stylesheet readback and a browser at desktop and phone
widths. Preserve the current immutable gateway release, SDK, configuration,
Homemaker selection and state during a source-only overlay/rollback. A passing
fixture or an own-being browser does not establish a human phone's acceptance.

### Local Guitar entry

`assets/guitar-entry.html` retains the existing public navigation-only page.
Its `/guitar/` alias remains stable; the controller still runs only on Legion
at localhost18879 with the Beacon attached. Do not contact that listener or
move hardware to qualify this page.

For the existing inline Caddy entry, render the selected template through
`build_label.stamp(template.read_bytes().rstrip(b"\n"), build_label.digest([template]))`.
Caddy quoted response strings do not decode JSON newline escapes: keep this
inline body on one line instead of publishing a literal trailing `\n`.
Only replace that exact inline response, preserving its matcher, status,
no-store policy and every other route. Validate with the actually selected
Caddy executable/environment, guard the current configuration digest, reload
Caddy and compare the actual HTTPS body/hash and version stylesheet. Preserve
the preceding exact configuration for a guarded source-only rollback. This
updates navigation UI, not the local controller or hardware acceptance.

Do not use anonymous sign-in pages as proof of a private application's build.
Record authenticated UI/source evidence and the audience denial separately.
Qualification-only own-service publications are not human-facing Apps coverage.

HTML applications published as artifacts (including standalone Oca/School and
evolving study pages) also show `v` in that same small line. This is the exact
selected publication revision, labeled independently of the common viewer's
`ui` build. It changes when the selected page changes and remains pinned for
an explicitly historical review. It is not a backend/program-code digest.
The outer trusted shell supplies both labels; immutable child bytes, audiences,
resource history and draft/promotion rules remain unchanged.
