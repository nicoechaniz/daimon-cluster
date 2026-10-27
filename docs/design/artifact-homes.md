# Artifact homes — access and delivery contract

Owning epic: AlterMundi/daimon-matrix#318; Skills#46/#51/#52 and Cluster#199.
Design alignment reviewed against Daimon Field D003 and the human-selected
Resonancia study: cyan orbital orientation, segmented instruments, licensed
self-hosted Space Grotesk, semantic amber/cyan/mauve and readable mobile controls.
The approved direction is distinct from accepting future spatial/group behavior.

## Shared starting place and access authority

Each human/daimon pair uses its home for selected ideas, files and experiments
before creating project-specific infrastructure. Resource identity and grants
survive later URL or placement changes. The normative shared contract is
[Matrix resource access](https://github.com/AlterMundi/daimon-matrix/blob/main/docs/resource-access.md).
One revisioned registry and evaluator serve all homes; local publisher metadata
is a submitted projection, not a separate access authority. Content remains in
its existing owner-local store. Serving requires an exact match with the
registered projection; incomplete publication synchronization fails closed.

## Ownership

Matrix owns verified being identities, current signed tribe history and pairing
source bindings. Cluster owns the home access service, placement and delivery
fences. Skills owns the portable publication contract and optional artifact
helper. The access service issues only home-scoped **read** sessions; neither
Cluster execution scopes, Matrix custody nor Nexus table cookies are inherited.

The binding adapter reads the current signed public catalogs and the existing
operator-selected human/bot contacts, without reading their bearer token files.
It validates the exact active body origin. Native being membership is evaluated
through `RelationshipStore.authorization_view()` with actual event/card
verification, preserving terminal decisions across forks and clock rollback.
Missing current evidence denies identity-dependent grants. No runtime is loaded,
relationship initialized/ingested, inbox consumed or model started.

Human pairing is not native tribe membership. A verified tribe founder may
explicitly accept a shared human-reader roster, recording its authority,
revision, founder reference, readers, revocation and optional expiry. All homes
consult that same roster. This is a resource-access projection, not a new Matrix
membership event. It starts empty; contacts do not populate it automatically.

## Five independent audiences

Public is readable anonymously; dedicated VPN is readable through its observed
network fence. Tribe grants require current being membership or the explicit
human-reader roster. Individual grants select resolved stable subjects. The
paired-human grant resolves the current pairing on every request. These are
independent audience sets, never cascading roles. A session identifies its
subject and binding revision; it retains no membership decision.

All catalogs, previews, direct files, dependencies, HEAD and media ranges use
the same current grant. Unknown/denied object paths return404 without revealing
private names. HTML views and JSON projections agree; public views have no private
titles, counts, actor/recipient sets or source paths. No state-changing browser
operation selects an actor or approves a grant.

## Browser identity

Reuse the existing request/proof/approval mechanism through a distinct home
contract. An expiring public code correlates a browser request; its HttpOnly
proof cookie is required to redeem an owner-local approval from the trusted
conversation. Actor identity comes from the actual receiving binding. Exact
home/origin and actor revision are bound to the redemption. The same approved
browser can retry a lost response without creating another grant or reviving a
revoked one. Session credentials are hashed at rest and use host-only Secure,
HttpOnly cookies. Logout revokes the session, rather than only hiding the UI.
Provider-signed Telegram launch data may establish the human's provider subject,
but never adds an artifact grant. Ordinary browser access remains supported.

Keep publication/owner operations local or under a separately scoped owner
client. Reader credentials cannot publish, approve another subject, modify a
roster, run commands or provision bodies. Actual human acceptance is reported
separately from operator/fixture checks; existing pairing data is not re-requested.

## Content and history

Published active HTML/SVG must be isolated before adding login cookies. Enforce
opaque-origin sandboxing on both direct views and previews; forbid network
exfiltration and reject null-origin authenticated reads. Keep source bytes and
standalone-download behavior intact. Home UI scripts never evaluate uploaded
content or trust its messages as identity or commands.

Retain original selected artifacts and immutable revisions. An audience change
updates the serving projection atomically; old-version URLs must satisfy both
the current grant and that revision's selected grant. Moving private work to
public does not automatically publish earlier private revisions. Unpublication
removes all serving projections while retaining owner-local recovery history;
already downloaded public copies cannot be recalled.

## Provisioning and deployment

Extend existing accepted-body onboarding with the maintained preservation and
commit-pinned install helpers. A home is owned by a selected being, operated by
its accepted body; label/default-route changes do not replace another owner.
Keep original source/state outside public roots and large artifacts on existing
durable storage. Retries preserve artifacts, receiving instructions and sessions.
The web-ring is an explicitly selected set of public homes, not discovery or an
implicit social grant. Prepare exact service/config candidates with retained
history and compatible rollback, and qualify a coherent candidate once.

Home delivery follows the existing Matrix admission boundary, independently of
later human conversation acceptance. The adapter reads the Root worker's
committed progress, matches the approved owner and complete plan digest, and
requires the validated completed-step prefix to include `matrix`. The provider
also verifies the current host grant, environment and admitted runtime presence;
its verified being must be the selected home owner. Missing evidence waits or
refuses delivery. It never repairs or executes admission to satisfy this gate.
Overall onboarding `active` remains false until its own acceptance completes.

The optional `--home-placements` hook reconciles committed admission before an
acceptance tick as well as after newly published progress. A later acceptance
failure therefore does not prevent an already admitted body from receiving its
home. Declarations retain exact source, skill and receiving-file hashes; retries
preserve native sessions, instructions and artifact history.

When the qualified worker uses older body dependencies, use
`tools/build_home_worker_successor.py` with explicit full `--base-commit` and
`--source-commit` selections. Its manifest identifies every resulting file and
the bounded overlay: home modules, worker hook, host observation and installer.
All other base files, including Matrix/Telegram/SDK pins, remain unchanged.
Reuse the qualified dependency environment after checking the resulting worker
against its existing configuration. The normal worker unit installer owns the
unit replacement and predecessor backup. Do not update immutable body capsules
or upgrade a bot merely to install the home provider.

No terminal, desktop, administration-path change, native-session replacement,
autonomous publication, peer attention or model wakeup belongs to this increment.

## Shared passkeys

Enable the optional gateway adapter with `--passkey-rp-id` and the pinned
`requirements-homes.txt`; body/worker environments and receiving config remain
unchanged. The parent-domain RP serves exact configured public home origins;
WebAuthn never accepts a wildcard origin or an isolated artifact origin.
A passkey binds a random opaque user handle to the current human actor/revision
in the existing shared session store. It establishes identity, not resource access.

Enrollment and revocation require a browser cookie from an approved code ceremony
still inside its fifteen-minute proof window, or a passkey-verified browser
session less than fifteen minutes old. General read/bearer sessions cannot enroll
keys. Registration and discoverable login require user verification; the phone
may use biometrics or its PIN. Challenge/proof/operation/origin/expiry, actual
signatures, RP hashes and user handles are verified. Credential counters and
session issuance are atomic; zero counters from synced keys remain valid.
Revocation closes every session issued by that key across all homes. Existing
resource and child-content checks continue to enforce current grants.

`/access/keys` manages a human's keys; `/access/passkey` logs in. The normal approved
code route remains recovery. Cancellation and unsupported browsers keep that
route usable. Credential creation/get are denied on isolated content responses.
No external scripts, native-model activation or biometric data collection is
involved. A virtual-authenticator check qualifies WebAuthn behavior, not the
human's actual biometric hardware. Retain that distinction in delivery evidence.

### Opt-in live 3D review

A current isolated work may opt in with the `home-artifact:live-review` message
(`enabled` boolean). The parent accepts only its actual opaque-origin iframe;
it derives the existing resource from trusted frame metadata. No child URL,
resource ID or path is accepted. Explicit historical-version views stay pinned.

The parent reads the fixed `review-live.json` from the same authorized resource.
The manifest must declare `schema=dm.review-live/v1`, `gallery=gallery.json` and
a SHA-256. `X-Home-Version` identifies the already checked selected backend
version; the gallery is fetched through that immutable version and digest-checked
before `home-artifact:review-update` is posted to the child. Revocation/current
and historical grants still apply to each read; no identity enters the iframe.

Limits:16KiB manifest,25MiB streamed gallery,20second timeout, one request in
flight and one10second visible-page timer. Errors back off to60seconds. Hidden
pages, pagehide and explicit unsubscribe cancel the request and timers. No
agent process, presence log or new login/store is involved. Only a subscribed
viewer containing the matching live client uses this bridge; ordinary artifacts
and selected media downloads keep their existing behavior. The renderer owns
mesh validation and state-preserving replacement, not the authority boundary.
