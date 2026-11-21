# Own Home HTTP service deployment (candidate v1)

This source candidate adds opt-in backend publication to the existing Home
publisher. It is **not installed or enabled by merging it**. Homes owns receiving
selection, capabilities, transport, gateway configuration and actual acceptance.
No Matrix SDK, identity, native harness, existing goal or login change is needed.

## Owner command

Install the qualified Cluster modules in the existing owner tool environment and
provide a small `daimon-home-service` entry invoking
`python -m clusterctl.homes.service_publish`. Retain the existing Home publisher
and binding, using their actual installed paths:

```sh
daimon-home-service --publisher /path/to/installed/home.py \
  --binding /path/to/own/binding.json --request /path/to/own/deployment.json
```

This is one finite foreground command (300 seconds maximum network budget), not
a scheduler or another login. It calls the authenticated owner adapter, uses the
existing publisher's `link --app` implementation and sync, then finalizes the exact
Registry resource/version. A complete result identifies code digest, URL and App
version. A retained complete result describes the original deployment; it is not
a claim that a later process is still running. No human/device use is inferred.
Do not put detailed operator outcomes in the normal application interface.

The request is closed JSON:

```json
{
  "schema": "dm.home-service-deploy/v1",
  "service": "workshop",
  "request_id": "workshop-release-1",
  "package": {
    "resource": "EXACT_32_HEX_OWN_RESOURCE",
    "version": "EXACT_64_HEX_HOME_VERSION",
    "file": "package.tar",
    "sha256": "EXACT_64_HEX_ARCHIVE_DIGEST"
  },
  "previous": null,
  "audience": {"visibility": "human", "recipients": [], "tribes": []},
  "app": {
    "title": "Workshop",
    "summary": "The paired human's workshop.",
    "decision": "Selected for my paired human."
  }
}
```

Publish the immutable package through the **own existing Home broker** before
selecting it. Use its committed exact resource/version, not `current`, an external
download URL or a path on the gateway. Historical own versions remain selectable
while that package resource is still registered. The gateway derives Home,
owner, origin, receiving host, prefix, ports and command from authenticated
identity and the operator capability; none is accepted from this request.

## Package

An uncompressed USTAR archive contains regular files only, with `service.json`
and the complete vendored application. No directories as archive members, links,
special/sparse files, PAX headers, traversal or writable/setid files. Files are
copied explicitly; `tar.extract` is never used. There is no npm invocation,
install hook, dependency download or package-supplied shell/argv/environment.

`service.json` has schema `dm.home-service-package/v1`, `service`,
`runtime: "node24-http"`, relative `entry`, `state_schema`, `health` containing
an absolute local HTTP `path` and exact response-body `sha256`, and `files`:
`[{"path":"main.js","sha256":"..."}, ...]`. The inventory lists every file
except `service.json`. Its canonical stored bytes and complete inventory are
verified with the existing receiving release verifier. The archive SHA covers
the original archive. Archive limits are 32 MiB, 128 MiB unpacked, 4096 files and
32 MiB per file. Entry/file paths use ASCII letters/digits/underscore/dot/slash/
hyphen with no empty, dot or parent components. Use JSON health bodies without
timestamps or other variable bytes.

The selected runtime is an operator-pinned **Node 24** executable, not a PATH
lookup. The application listens on `HOST` / `PORT` and writes persistent data
only through `STATE_DIR`. State schema must equal the capability's schema.
Automatic data migrations are outside v1; code rollback never restores a DB.

## Receiving activation contract (Homes operator)

Supply a protected `--service-deployments` JSON file to the existing Homes
service. Existing configuration and SDK import environment stay selected; this
argument is additive and absent by default. Top level:

```
schema: dm.home-service-capabilities/v1
state: operator-owned deployment journal directory
grants: at most 32 explicit service capability objects
```

Each grant contains exactly:

- `receiver`: the closed receiver object below;
- `prefix`: one reserved non-core lowercase path, e.g. `/workshop/`;
- `upstream`: the exact private numeric gateway-facing `IP:port`;
- `auth_backend`: the existing Home viewer loopback origin;
- `command`: a fixed operator-owned argv route to the receiving executor;
- `route_command`: a fixed operator-owned argv route to the privileged gateway
  route executor; the unprivileged Homes HTTP process never edits Caddy itself;
- `routes`: existing Caddy `Routes` configuration (`config`, distinct per-service
  `state`, `anchor`, optional existing `maintenance`).

The argv receives a bounded JSON envelope on stdin. Use the existing scoped
host/guest writer or restricted fixed executable transport; never accept a
caller-provided SSH destination, shell script, command, unit name or root argv.
Do not expose a shell or the gateway publication credential to a companion.
The executor command is:

```sh
python -m clusterctl.homes.service_runtime --config /operator/own-service.json
```

The gateway-side route command is
`python -m clusterctl.homes.service_routes --config /operator/own-service-route.json`.
Generate that protected declaration using
`service_routes.declaration(grant, actual_home_public_origin)` at receiving
activation. It binds Home/being, route key, origin, prefix, upstream, auth backend
and existing Caddy writer configuration. Its stdin accepts only the declaration's
digest, not paths, commands or route text. The existing scoped operator transport
owns privilege; the Home owner credential alone acquires none. The route helper
has a 180-second hard deadline and its calling transport has 185 seconds. The
overall owner command also has a hard 300-second alarm, including local locks.

The receiving config is independently protected at that destination. Its exact
canonical digest is the capability reference; a different owner, profile or host
cannot reuse it. The digest binds a declaration; it is not a secret or an
authenticator. Actual execution authority comes from the authenticated Home
operation and the existing restricted operator transport. Make the fixed
privileged helpers callable only through that transport, never a broadly
writable command endpoint. Fields:

```
schema: dm.home-service-receiver/v1
home, owner, service: existing exact Home/being and service identifiers
placement: native | kvm | container
machine_sha256: digest of actual receiving /etc/machine-id bytes
profile_file, profile_sha256: protected actual receiving profile and exact digest
node, node_sha256: immutable actual Node24 executable path and digest
root: private 0700 operator-owned receipt/control root for this service
code: separate operator-owned 0750 code directory, group selected application GID
data: separate existing 0700 application-UID-owned persistent state directory
unit_dir: actual operator-owned system unit directory
uid, gid: existing non-root service identity
port: selected receiving loopback port (1024..65535)
state_schema: current compatible state format identifier
memory_mb: 32..4096
cpu_percent: 1..200
tasks: 8..256
state_bytes: 1MiB..16GiB
quota_probe: fixed operator-owned argv for the existing storage quota observer
```

The quota observer must report exactly
`{"path":"SELECTED_DATA_PATH","hard_bytes":SELECTED_LIMIT,"enforced":true}`.
A size measurement or declaration is not quota enforcement. Provision the real
quota with the owning storage writer; lack of it refuses before selection.
The executor/config/root/code/runtime/profile/unit ancestors must remain operator-
owned and non-writable by the application. Do not put root custody below a
publisher-writable home. Symlink paths are refused. The application UID/GID is
existing; this tool creates no account or credential.

Before activation, resolve the **current** native/KVM/container route from the
receiving placement. The executor does not create networking. Retain the
existing restricted edge socket for a KVM; do not replace it with a container
proxy. Container/private listeners are likewise explicit preselected operator
resources, not public binds. Grant collisions for service, private receiving
port, code root and own prefix are refused. Reserve the requested path with one
exact Caddy insertion anchor ending in `s-<key>`, where key is the first 24 hex
characters of SHA256 of canonical `{home, owner, service}`. Place it **before**
applicable catch-all handlers. Existing differing prefixes/marked blocks refuse.
The existing finite Caddy CAS/reload journal is reused, with no whole-gateway
replacement. Changing a route capability requires explicit owning reconciliation;
it does not silently overwrite an existing block.

The code directory is deliberately separate from private receipts: the service
UID must be able to traverse and read its code without reading control state.
Use actual paths outside the systemd protected Home/tmp surfaces; retain the
private externally stored application data through its supported storage writer.

The fixed generated unit is `dm-home-service-<key>.service`. Initial deployment
refuses an existing unknown unit; successors require the exact retained unit.
The selected own unit is enabled for boot and started. The service runs as its
selected non-root identity, with read-only system and inaccessible home,
no privileges or capabilities, fixed writable state, 32MiB private tmp, bounded
memory/CPU/tasks/restarts and rate-limited journal output. Node readiness requires
the actual manager PID/entry, generated unit bytes, PID-owned loopback listener
and exact health body. An unrelated occupied port is preserved before selection.
The receiving invocation has a 95-second hard deadline including lock acquisition;
the gateway transport has a 100-second deadline.

The gateway's new `/service-access/s-<key>` is a **read-only forward-auth**
decision under existing browser identity. It checks current capability, exact
committed own App version and current audience on every request. Missing, foreign
or revoked identity is denied for a personal audience. Unsafe browser methods
require the exact Home Origin. Signed-out document navigation returns through existing shared SSO to only the
capability's local path; unauthenticated API access returns401. It mints no
identity or session. Node receives no
owner Authorization token or caller-supplied actor headers. Authentication is
enforced by the route rather than a package's assertion that it handles login.
Direct private listener access must remain restricted to the selected edge.
The route forces private/no-store responses independently of package cache headers.

## Continuation, rollback and bounded retention

The existing OperationJournal records the full exact request and capability;
another request cannot replace pending work for the same service. A transport
timeout is uncertainty. Retry the **same** request. Its receiving journal is
observed first; a retained dispatch is never restarted again. If the receiving
writer proves the operation absent under its lock, the identical idempotent apply
can proceed. Failed/unknown startup remains unconfirmed for owning recovery; the
tool does not invent success or automatically restore application data.

Runtime-ready alone is not publication completion. The owner command publishes
the ordinary own App link, then finalizes exact resource/version/URL/audience.
An interrupted link/sync uses the existing publisher's exact idempotent retry.
Until finalization the new route remains closed. A newer pending deployment
also closes access rather than serving code under stale audience metadata.
No family invitation or live microphone/model is needed for technical checks.

For compatible rollback, select a retained previous package with a **new** request
ID and `previous` equal to the actual current code digest. State schema and data
directory remain unchanged. Unknown unit/route replacement is preserved. Keep
current, predecessor and one candidate release (at most 384 MiB code); verified
older code is pruned on later selection. Pending dispatches prevent pruning.
Receiving receipts stop at 128 (at most 2 MiB per receipt); central journal stops
at 128 operations. At the limit the owner gets a retained failure and Homes must
use the owning retention path before new work; do not reset history or operation
identities. Ordinary own Home publication history keeps its existing policy.

## First receiving cases and remaining acceptance

Oliva's already running service is not proof that this candidate selected it.
Homes must bind its actual immutable package, KVM profile, Node24, external state,
enforced storage, restricted socket and prefix to this writer. The candidate
never takes over an unknown active unit or starts a second listener to replace
it. Any necessary first unit handover belongs to the existing scoped service
writer and must preserve the original state and practical rollback. Original
Sites publication stays untouched.

Eko and each child use the same operation only after their own selected
capability and actual native/container transport are installed. Shared availability
does not copy Oliva's grant, account, code choices or private data. Install this
guide's owner command/pointer with each receiving publisher through the current
shared tool update route, rather than leaving the procedure only in chat.

Source tests cover package validation, real receiving file writes and immutable
selection with a simulated manager, exact retry after a lost manager reply,
rollback preserving data, Caddy composition conflict, authenticated owner scope,
actual Registry closure and actual Home HTTP own/foreign/anonymous checks.
These are not production systemd/Caddy, KVM/container transport or family-device
acceptance. At receiving selection, use the one real own service journey to
verify those boundaries, including no-auth/foreign denial and authorized serving.
No new approval quorum, provider call, background worker or enrollment is needed.

V1 supports public, paired-human, individual and Tribe audiences. A VPN-only
service route is explicitly unsupported and refused; it is never downgraded to
public. Existing static VPN publication remains unchanged. The owner command
also refuses a same-ID App entry pointing elsewhere or using a different
audience/application mode, preserving an original Sites or other publication.
Resolve an explicit audience move through the maintained publisher's audience
writer; do not create a duplicate or overwrite unrelated content implicitly.

Distinct App readers behind a shared Host-routed upstream remain separate maintenance
targets. The same proxy address must not collapse their independent live voice locks.

### Gateway with NoNewPrivileges

Keep the existing Home sandbox. A gateway with `NoNewPrivileges=yes` cannot
acquire privilege through `sudo`; successful operator-shell execution is not a
receiving transport test. For a local privileged worker, use the fixed systemd
`Accept=yes` Unix socket transport and `clusterctl.homes.service_socket --socket
/run/daimon-home-services/SELECTED.sock`. The protected socket/service unit fixes
the entire executor argv and config; the client supplies only the existing
bounded JSON envelope, half-closes stdin, and reads at most16KiB. Root owns the
socket and nonwritable parent directories; grant socket group access only to the
existing gateway user. Preserve worker deadlines/resource bounds and its exact
runtime/route capability. Do not accept commands, paths or service selection on
that socket. A disconnected reply remains uncertain; inspect the existing
journal and retry only the same retained request. No gateway sandbox or broad
sudo/login policy change is needed.

### Dedicated remote operation access

A remote worker uses a dedicated locked-password transport principal and key,
never an existing administrative login. The forced command
`clusterctl.homes.service_remote.forward` accepts only an installed operation
name; root's separate closed declaration fixes its runtime/route configuration
or protected host wrapper. A narrow sudo rule names each exact permitted
operation. Shells, arbitrary commands, port forwarding and unknown services are
not part of this route. Keep existing administrative principals, keys and SSH
admission unchanged. The transport key remains operator-only; local fixed Unix
workers provide the existing sandboxed gateway with this transport.

Maintenance forwards the existing finite guard stream, but matches its public
bootstrap and exact configured application, script digest, uid and health URL
before running the installed protocol as that application's user. It never runs
caller-supplied source or accepts a different application target. Host/container
wrappers select one exact instance and its own protected operation declaration.

When rotating only protected operator transport metadata, preserve original
operation IDs and receipts. A new explicitly identified attestation request may
bind the same exact immutable package to the new capability. The receiver verifies
its current files, selected unit and health and does not restart healthy identical
code. An already complete exact Caddy block can be observed against the actual
loaded configuration without another reload, even when operator guard metadata
has rotated; conflicting or incomplete operations still fail closed. Keep current
state and compatible rollback, and qualify the actual dedicated transport and
cross-service refusals before declaring adoption.

### Prepared route and refreshed maintenance coverage

A new service can reach a healthy receiving runtime while the shared Caddy writer
correctly refuses a missing current web/voice maintenance target. Keep the exact
service request, package digest, ready runtime and prepared route; do not start a
new request or reset the journal to hide that refusal.

The route writer accepts refreshed protected operator guard metadata only while
the operation is `prepared`, the actual Caddy file/live configuration still match
the original preimage, and the generated candidate bytes plus adapted
configuration are exactly unchanged. It retains the original prepared checkpoint
under its old pin digest, within the existing16-receipt bound, before binding the
same candidate to the new metadata. Fresh authorization and every current
maintenance guard still apply before any file write/reload. A changed route,
concurrent file edit, dry run, revoked authority or `reload-intent`/unknown effect
cannot use this path. Observe an uncertain reload; never rebind or dispatch it.

Update only the affected protected declaration and its receiving capability,
using actual current health/source/owner metadata. An existing live target is not
permission to start, enroll, update or otherwise activate a held companion.
Repeat the original deployment request through the ordinary owner command after
that technical correction. The central deployment writer reconstructs the old
grant hash by removing exactly one newly added maintenance target from the
current protected declaration; every other grant byte and the exact request
must match. This proves a strictly additive guard correction without rewriting
the original immutable intent, creating a new target operation or weakening
finalization/access checks. Removals, replacements, multiple edits and receiver,
transport or route changes refuse. A healthy existing runtime retains its PID
and invocation rather than restarting during this recovery.

The finite route executor's task bound must cover every selected maintenance
guard plus its transport processes and the Caddy control CLI. Qualify the
actual bound: eight guarded receivers required 96 tasks on the Holodeck
receiver; 32 caused a kernel-confirmed fork rejection before the reload reached
the Caddy admin API. Preserve the original reload intent. Operator recovery
requires exact candidate/preimage pins, observed unchanged live configuration
and reacquired guards before finishing that selected reload; a lost reply alone
is never evidence that another reload is safe.

## Delegated maintenance of one shared engine

A service owner may explicitly authorize a different existing Home owner to
maintain its engine. This is a protected operator declaration, not publication
ownership, ordinary native co-creation or a second receiver grant. Add optional
`delegations` to the existing capabilities configuration; leave `grants` and the
receiver/route declarations byte-identical. Each delegation is closed JSON:

```json
{
  "home": "EXISTING_DELEGATE_HOME",
  "owner": "EXISTING_DELEGATE_BEING",
  "revision": "CURRENT_AUTHORITY_ACTOR_REVISION",
  "target_home": "EXISTING_CENTRAL_HOME",
  "service": "holodeck",
  "resource": "EXACT_32_HEX_CENTRAL_APP_RESOURCE",
  "version": "EXACT_64_HEX_CENTRAL_APP_VERSION"
}
```

Resolve identities through current authority and the original owner's authorized
operator writer. A declaration grants no other service or target, shell, state
migration, audience change or account access. The delegate authenticates with its
own existing publisher credential. Package publication and exact version lookup
use only that delegate's Home. Its deployment request uses the ordinary v1
schema, the existing service ID, exact current archive predecessor and the
central App's unchanged audience/title/summary. Missing or changed central App
version, disabled/revised delegate, different owner or foreign package refuses.
Registry resource ownership is not transferred.

The same finite `daimon-home-service --request request.json` command applies the
fixed central receiver and route, then finalizes against the already committed
central App. It never calls the delegate's link/sync writer or creates another
Apps card. The request journal binds both the unchanged receiver grant and exact
delegation, and records the actual delegate as actor. A changed declaration or
operator cannot take over an uncertain request. Retry only its exact original;
revocation preserves applied/pending work for owner recovery. Revoking maintenance
authority does not revoke ordinary readers' access to the central service.

`daimon-home-service --request request.json --inspect` authenticates the same
scope and observes the latest retained operation through the fixed executor,
without applying code. It reports its health observation, operation state and
`previous_requested`; this predecessor is NOT a verified rollback file. Explicit
`rollback_verified: false` prevents interpreting journal metadata as recovery
qualification. The existing receiving operator must inspect current/previous
protected runtime records and retained packages before a rollback selection.

Receiving adoption is separate from source tests: select these modules in the
existing gateway composition (preserving current Matrix imports), install the
matching owner command in the delegate, and apply only the authorized explicit
declaration. Verify own authenticated inspect and unrelated-owner denial before
any separately selected candidate deployment. A source PR or fixture does not
establish installed delegation, served code, human use or healthy physical audio.
Do not change the running engine to qualify the grant. Current/previous code,
external state, service/App identity, reader audience and native routes remain
under their existing owner contracts.
