# Preventive Sysops through the existing heartbeat

Sysops is preventive maintenance, independent of incident arrival. Cluster owns
fixed fleet operations; the existing heartbeat owns cadence/admission/pause and
reads selected result fields. Do not create another model poller or infer fleet
health from an active timer. Normal version, freshness, quota and known-operation
decisions are programmatic. A new unresolved change, applicability question or
failure may need an attributed model diagnosis; repeated unchanged checks do not.

## Finite existing-owner executor

`python3 tools/preventive_sysops.py --config PRIVATE_CONFIG` runs one bounded pass.
Its closed `cluster.preventive-sysops/v1` configuration selects `state`, `paused`
and at most16 explicit `targets`. Each target has a stable `id`, fixed receiving
`transport` and `jobs`. Transport selects local, existing Incus or pinned SSH;
there is no incident-supplied command, target, URL or payload. SSH proxies and
arbitrary local shell prefixes refuse. Access remains with the existing operator.
Private configuration and state must belong to its effective UID, mode0700/0600.

A job selects `id`, exact `.service` unit, `scope: system|user`,
`interval_seconds` (3600..604800), SHA256 of actual `systemctl cat` bytes and
`action: observe|start-if-due`. At most64 jobs are configured. Qualification binds
an existing oneshot definition, not an arbitrary future command under that name.
A changed definition needs owning qualification; unknown/on-demand service state
is not permission to launch it. Do not register daemon restarts as oneshot work.

Each pass reads OS/kernel, selected filesystem availability, native package
versions, index freshness, a real `dpkg --audit`, and selected executable
locations including Codex, Antigravity, Node/npm/Corepack/pnpm, uv/pipx, Incus and
Docker. Finding an executable does not qualify its version/source/update route;
manually managed tools require their owning immutable release/update receipt.
The loaded custom Codex harness is not interchangeable with an npm stock binary.
Missing components/metadata remain explicit. Filesystem reads are not quota proof;
package-database consistency is not a vulnerability clearance.

An admitted due operation does not require an incident. A running job is retained.
Dispatch intent is durable before `systemctl start --no-block`; subsequent passes
observe that same operation. Lost replies never authorize resubmission. Later
systemd start/invocation evidence can confirm that the selected job executed;
actual producer receipts still establish its useful work. Unknown/reclaimed unit
metadata stays uncertain. Confirmed failures back off exponentially, up to six
hours and three failed retries per day. No reader deadline kills APT/dpkg writers.
A changed transport/unit binding cannot take over pending work.

Bounds: sequential target reads,30seconds/128KiB each; at most two dispatches per
pass,10seconds/8KiB per dispatch;300second CLI ceiling. One nonblocking flock
prevents overlap. One replacing `CURRENT.json` is capped at2MiB, with at most64
pending/failure entries; it does not create per-pass archives or delete pending
work for capacity. Set `paused: true` to stop new work while preserving intents.
The existing scheduler's pause disables future admission, not an active package
transaction. Rollback restores selected code/config, never old runtime databases.

## Maintenance coverage and owning operations

Maintain explicit per-target coverage for all living hosts and bodies. Initial
receiving targets are ITACA/CompAII, MEDUSA/Eko, Lordoftheflies, its four children,
and the existing Oliva/Emma KVMs. A host observation does not substitute for its
guests. Other catalog resources retain their own permission/workload boundaries;
Mona is not a generic Sysops target under broad infrastructure permission.

- OS/security: reuse signed indexes, maintained Debian/Ubuntu policy, existing
  daily vendor/advisory matching and the guarded package coordinator. Its reviewed
  Chromium-family scope is not authority to install all other candidates. Inspect
  real advisory/audit output, qualify applicability and concrete remediation,
  preserve package transactions and verify loaded fixes/reboot dependencies.
- Non-system software: map each actual distribution, custom harness, runtime,
  dependency environment, manual/vendor tool and app to its maintained update
  writer and trusted source. Source publication, installation, loaded process
  and real behavior are separate. Do not run unreviewed installer text, npm
  lifecycle hooks or substitute package managers just to obtain a newer number.
- Auth/access: use current selected native account/workspace, held original
  sharing grants and current secure custody. Check access/expiry and renew before
  failure. Rotation requires its actual account authority; never refill budget
  or silently substitute another account. See [login recovery](codex-provider-login.md).
- Resource/data: reuse existing bounded storage/memory observers, hygiene and
  owning backup/restore-readiness receipts. Do not create another backup archive,
  delete sessions/media/originals or perform new restore drills to make a check
  green. Existing old-host shutdown/cleanup holds remain authoritative.
- Certificates/keys/grants/configuration: map expiry/source/revision and actual
  renewal/verification writers. A check with no registered renewal adapter is a
  coverage gap, not successfully maintained access. Preserve custody and audience.
- Apps/shared guidance: use owning compatible deployment, voice/busy fences,
  current installed skills and actual receiver readback; defer disruptive work
  with its exact maintenance dependency, rather than inventing a human gate.

The first finite pass is not complete scheduling/adoption. Heartbeat must consume
the existing result and its stable semantic state, without clocks or per-pass
invocation IDs triggering model attention. Initial inventory, durable action
mechanics, registered remediation coverage and actual recurring useful execution
must each have receiving evidence. Unsupported adapters remain unfinished work.

## Model family upgrades

Workload owners select a model family and a compatibility contract. Keep the
concrete serving revision in the existing owner configuration, alongside the
last verified revision. Record the account binding, provider endpoint, model
family, required reasoning effort, modalities, tools, and isolation controls.
Each workload can follow its family or retain an explicit pin. Preserve existing
pins, including experiment controls and outstanding operations.

Use the existing preventive Sysops cadence to evaluate trusted OpenAI release
metadata against each receiver's own model catalog. Order known versions inside
the explicitly declared family. A model name, release note, or availability on
another account cannot establish a valid successor. Unknown versions and
alternative modalities remain visible candidates until the adapter establishes
compatibility. Report an unchanged catalog as a no-op.

Use the receiving owner's prepare, apply, and status operations. Prepare against
the exact source/config revision and real receiver, checking the existing CLI,
effort, endpoint, capabilities and access. Qualify affected behavior with
bounded fixtures or a scoped canary when authorized. Apply a previously qualified
candidate to eligible receivers through their existing owner writers and recheck
loaded configuration and successful use. Bind the receipt to the predecessor and
candidate. A stale preimage or unresolved dispatch stops that receiving change.

Start with a compatible receiver that can adopt safely. Expand through the same
qualified contract. Switch new work at its normal admission boundary and let
active turns finish with their original model. Each existing operation keeps its
original account, identity, budgets, input, request digest and policy. Leave a
known-good revision available for future work if the new revision fails. A failed
or uncertain request stays with its journal and is never automatically replayed.
Pause new admissions through Sysops while preserving already admitted work.

An example is native DMK review, which follows Sol at low effort with tools and
native memory disabled. An otherwise supported Sol release is ineligible until
that receiver has a suitable CLI and tool-disabled catalog. This contract is a
design for existing owner adapters. It does not schedule new polling or imply
that automatic selection is already installed.

The finite pass accepts an optional absolute `model_evidence` path to an
operator-owned 0600 file of at most 128 KiB. The `cluster.model-family-evidence/v1`
document binds each workload and candidate to a receiver, route, family and
owner-supplied compatibility contract digest. The adapter provides explicit
three-part release ordering and current availability with its UTC epoch-second
observation time. Entries more than 24 hours old or from the future are ignored.
A qualification must name the exact current model. Ties require resolution.
The pass emits `model_upgrades` plus stable semantic states. It makes no provider
calls and cannot apply a model selection by itself.

## Initial receiving evidence —22November2026

The finite pass actually observed all nine selected targets in5.4seconds. Each
ran a real package-database audit with exit0 and no pending dpkg recovery output;
OS/package/index/filesystem/manual-tool locations were retained separately.
This does not establish that no vulnerable packages or stale software exist.
The configured ITACA hygiene job was fresh, so it was not repeated. No new timer
or model execution was created; the broader cadence/adaptor coverage is pending.

A separate same-account repair recovered the four children's existing native
provider access from a currently valid source permitted by their original
protected shared-account grant. Exact native workspace/account, provider quota,
new model catalog and unchanged Codex/Matrix/Conversation process identities were
verified on each body. No device login, account substitution, goal control or
failed-input replay occurred. Consumed private ITACA credential staging was
retired after all four verifications; original source/receiver stores remain.
The generic authority/empty-cache helper is tested here; complete recurring
source discovery/expiry/renewal and real scheduling are separate unfinished work.

Native Sol6.2 defaults were then written through the existing version-checked
native config writer on all eight bodies, retaining prior effort/provider and
all other effective configuration. Loaded/used models and persisted per-session
selections retain their own independent migration evidence and open work.
