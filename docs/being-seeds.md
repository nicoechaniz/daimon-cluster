# Portable being seeds and private intake

Cluster owns receiving environments, resources and observed effects. Matrix
owns authenticated identity and relations. A portable seed carries preserved
context; it is neither custody nor proof that an embodiment is running.

Both entry paths use the same archive and receiving contracts:

- **Continue an existing being:** export its authorized interference pattern
  from Hermes, Codex or explicitly selected mixed sources. Preserve SOUL, full
  authorized memory, historical skills, relationships, sessions and project
  references with provenance. Declared partial coverage remains partial.
- **Start a new being:** provide a name and initial SOUL. Cluster generates a
  standard archive and prepares it through the same receiver. Its history is
  explicitly empty; no existing being's autobiography is copied into it.

## Export on the source machine

`scripts/being-seed` needs only Python 3.11+. It uses the exact Matrix exporter;
installing Cluster's Matrix SDK or running a daemon is unnecessary. Source
files are not mutated. Supported harness adapters are `hermes`, `codex` and
`mixed`; multi-profile homes require an explicit source-selection file.

```sh
python3 scripts/being-seed discover \
  --selection source-selection.json --output export-plan.json
# Review the source plan and stop only the selected writers for a final snapshot.
python3 scripts/being-seed export --plan export-plan.json \
  --output eko.tgz --writers-stopped
python3 scripts/being-seed verify --archive eko.tgz --sha256 EXPECTED_SHA256
```

For a single-being home, `export --being NAME --harness hermes|codex|mixed
--source-home HOME --output ARCHIVE --writers-stopped` provides the existing
discovery adapter. An agent should discover effective homes and ownership;
the human chooses the portable coverage. Do not export harness authentication,
browser cookies, private keys or signed runtime custody. Native histories are
preserved with origin; conversion into another harness's resumable sessions
remains future adapter work.

The three files under `support/being-seed-tools/tools/` are byte-for-byte copies
from Matrix commit `4d4ccd5e9eaf4092e62cbdefa9fbc6288d2cbcd8`; provenance and
hashes are recorded alongside them and enforced on invocation. This is a
preservation-tool snapshot, not a change to Cluster's reviewed Matrix SDK pin.
Update these tools together after upstream review; do not fork their archive
parser. No code from an incoming archive is executed.

## Private web delivery

Open `/v1/onboarding` on the host's HTTPS address. The same URL supplies the
tools, instructions and private access request. Enter a workspace name such as
`ani` or `sai`, request access and give the host the displayed name and
verification code. Keep that browser page or agent request alive. The host
confirms who made the request and approves that exact pair locally:

```sh
python -m clusterd --config CONFIG --access-pending
python -m clusterd --config CONFIG --access-approve CODE --owner ani
```

The original requester then receives access directly. A workspace label alone
confers no authority. There is no public approval/listing endpoint and no token
to relay manually. Requests expire after 30 minutes, are rate/capacity bounded,
and require a private random proof key. The server retains only its SHA-256.
An approved claim succeeds once; a lost API claim response requires a new
request and approval. The machine guide below describes the complete API flow.

Access lasts three days, is revocable and has exactly `fleet:read` and
`seed:write` for the approved owner. API agents receive a bearer once. Browsers
receive a Secure HttpOnly SameSite=Strict cookie restricted to the intake
routes, resume on refresh and can sign out to revoke access. Cookie mutations
require a matching Origin. No credential is placed in a URL, localStorage or
sessionStorage; public views contain no owner data or external scripts.

The previous operator issuer remains available under Advanced access:
`POST /v1/seed-access` requires an operator-owned `*` bearer with `seed:write`.
A participant cannot issue or widen access. Never hand out the operator token.

An existing verified export, local receiving context and valid participant
access remain usable. Read existing deliveries before creating another record;
resume uploaded/prepared packages without re-exporting or re-uploading them.
Only a requester without valid access needs the new owner/code approval flow.

1. Choose import or new, the environment name, being label and browser option.
2. Import: upload the `.tgz`/`.zip` and the SHA-256 from the source exporter.
   Verification proposes a receiving selection. Review its SOUL, memory stores,
   historical skills and `owner-selected` or `complete-authorized` declaration.
3. Prepare: originals, provenance and native histories remain preserved; selected
   writable memory copies and Codex context are prepared separately.
4. Deliver the bot token, numeric Telegram destination/topic and public SSH key
   through the separate private form. Provider login happens freshly in the
   receiving environment. Bot credentials never enter the portable archive.

Uploads are authenticated and ownership checked before reading their bodies;
they stream to mode-0600 files in mode-0700 directories. The initial upload
limit is 512 MiB; the upstream expanded limit is 5 GiB. Intake checks available
working space, limits pending slots per owner and does not accept chunked framing.
Incomplete and failed preparations remain private and need operator attention;
they are not overwritten or automatically restarted. Exact preparation retries
return the original result, preserving later receiving memory writes.

Stored connections are visible only as **data supplied**, never as accepted
connections. No secret value is returned by the API, dashboard or audit view.
The storage is local, owner-only plaintext: use an encrypted host/volume where
required, and include it in the host's existing private backup policy.

## CLI and API share the same implementation

### One URL for humans and daimons

`GET /v1/onboarding` returns the visual interface by default. Send
`Accept: text/markdown` for the authored agent guide or `Accept: application/json`
for structured requests, limits, retry behavior and a generated intake-only
OpenAPI subset. Tools that cannot set headers can use `?format=markdown` or
`?format=json`. Explicit formats take precedence over media preferences. The
HTML and HTTP alternate links advertise these representations; responses are
uncached and vary on `Accept`.

All three views use the same authenticated REST endpoints. Public metadata
contains no owner records or connection secrets and grants no API access. A
daimon requests limited access here, receives it after host confirmation and reports context
preparation separately from actual body activation. No browser automation or
additional MCP server is required to deliver a packet through this API.

The visual interface uses the [Daimon Matrix interface direction](interface-design.md),
self-hosted licensed typography and a staged continuity workflow. Its state
cards describe observed preparation and pending acceptance; they never simulate
an active body. Publish `clusterd/assets/` as `/assets/` on the HTTPS frontend.

`clusterctl seed --owner OWNER` supports `create --spec FILE
--idempotency-key UUID`, `upload NAME --archive FILE --sha256 SHA`, `discover
NAME`, `prepare NAME --selection FILE`, `connections NAME --file FILE`, `status
NAME` and `list`. For a new seed, `prepare NAME` takes no historical selection.
Connection values belong in a private file, never command-line arguments.

API: `POST /v1/seeds`, `POST /v1/seeds/{seed}/archive` with
`X-Archive-SHA256`, `GET .../selection`, `POST .../prepare` with
`{"selection": ...}`, `POST .../connections`, and owner-scoped paginated
`GET /v1/seeds`. Metadata exposes coverage, initial verified counts, preparation
phase and pending steps. Paths, identity prose, native messages and secrets are
excluded. The existing dashboard has a seed progress card.

An additive intake service can run `python -m clusterd --seed-only` with a
dedicated private state directory and loopback port. This mode serves only
intake and liveness routes, without initializing a Matrix client or exposing
fleet operations. A host proxies `/v1/onboarding`, `/v1/seeds`, `/v1/seeds/*`,
`/v1/seed-access`, `/v1/seed-access-requests`, `/v1/seed-access-requests/*` and
`/v1/seed-session` from
its HTTPS frontend. This permits intake deployment without upgrading an
existing Cluster/Matrix runtime pair. Do not replace the existing fleet service
or retarget its SDK pin to install this feature. Live installation follows the
repository's exact-plan deployment and administrative-access rules.

### Verify access from outside the host

Caddy's public HTTPS listener needs its own web ingress. The host firewall
template permits TCP 80/443 for TLS/HTTPS and UDP 443 for Caddy's HTTP/3 on
`ens3`; select the actual public interface for another host. Keep the intake
backend on loopback and proxy only its routes, including `/v1/seed-access`.
The web rule does not widen container access or expose the control-plane port.

When extending an existing host, add only the web service rules and retain its
existing rules and administrative access. Do not replace its complete policy
with this template or flush Incus-managed tables. Verify the persistent
candidate before applying it and verify the public URL from an independent
network. A successful request from the server itself cannot establish external
reachability: its traffic may bypass the public ingress rule through loopback.

## Optional graphical browser environment

The seed's browser checkbox requests **Chromium + Xvfb + Kimi WebBridge** with
a fresh private profile per environment. Eko and Oliva should select it. Browser
code preparation and actual acceptance are separate; the checkbox alone does
not claim an enabled browser.

Install the Debian packages `chromium xvfb xauth openbox fonts-dejavu-core` in
the selected new environment. The host supplies only an audited WebBridge
binary and extension directory, with their SHA-256 values. Use
`clusterctl.browser.extension_digest` for the deterministic extension inventory
digest. No Source browser profile or login is copied.

As the dedicated environment user:

```sh
python3 -m clusterctl.browser prepare --daemon CODE_FILE --daemon-sha256 SHA \
  --extension CODE_DIRECTORY --extension-sha256 TREE_SHA
# Apply the reviewed code-only preparation into this user's fresh home.
python3 -m clusterctl.browser prepare --daemon CODE_FILE --daemon-sha256 SHA \
  --extension CODE_DIRECTORY --extension-sha256 TREE_SHA --apply
python3 -m clusterctl.browser run
python3 -m clusterctl.browser status
```

Launch keeps the Chromium sandbox, uses a private X display with TCP disabled
and binds WebBridge to container-local loopback. Each separate container can
use its own port 10086. It does not install startup hooks or stop an existing
browser/daemon. Foreground shutdown cleans only processes it launched. Acceptance
requires the real extension connection plus a human-requested page operation.

## Continue from prepared context to an active body

Preparation does not create a VM, install live identity, initialize/re-embed
imported HMK, enroll Matrix, start a bot or call a provider. The remaining host
steps are: allocate the qualified native image and durable home; install the
selected context and trusted native HMK binding in the actual receiving user;
reconcile the existing being's root and authorize its distinct hosted body;
configure dedicated SSH, fresh provider login and a single bot consumer; verify
ordinary CLI, older/recent memory retrieval, native resume, permanent Telegram
responses and steering. New beings need an initial memory store and their own
root ceremony; imports preserve existing identity and declared coverage.

Record those effects through the owning runtime/resource workflows. The seed
view always labels unperformed runtime, browser, SSH and bot acceptance pending.
Do not infer readiness from a checkbox, a process ID or merely possessing bot
data. Cross-host writable HMK reconciliation remains a separate operation.
