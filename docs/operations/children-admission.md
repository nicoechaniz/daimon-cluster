# Children's physical admission

Keep Matrix identity, physical holder enrollment, a running canonical admission,
Tribe membership and human application acceptance separate. A signed public
identity or registrar profile alone proves none of the later stages.

Use the existing `FirstCustody.admission_coordinates`, target
`admission-prepare`, `onboarding_admission.profile` and target
`admission-enroll`/`admission-check` operations. Each receiving holder creates
its own physical key in its own virtual machine. The registrar receives the
public holder/proof and verified native coordinates; its private key stays at
the existing central authority. Preserve each existing Matrix identity and
physical holder key. Never replace an uncertain enrollment with a new identity.

The central profile operator must select code that validates the exact approved
plan, including optional resource limits. Retain its qualified public source
and reuse the existing dependency environment; do not remove fields from the
plan or change the shared running worker just to sign one profile.

Proof-of-possession requests expire after 60 seconds and default registrar
enrollments after five minutes. Prepare, validate, sign, transfer and enroll in
one finite operation once the receiving route is ready. If a known-unattempted
profile expires, obtain a fresh proof from the SAME preserved holder and sign a
fresh profile; retain the prior artifact and its expired/unattempted status.
An uncertain network result instead requires the maintained enrollment check,
not another identity, key or blind request replay.

## Complete the usable onboarding path first

Nicolas clarified on8November2026 that the promised short onboarding must be a
real reusable receiving path. An earlier Eko/Oliva deployment or green component
fixtures do not establish that a fresh companion on another host can be used.
Close the first actual companion through the existing native conversation
backend and shared login, then repeat the same supported route for the remaining
companions. Basic Conversation does not wait for full Tribe membership, Escuela,
Drive qualification, voice or Avatar polish. Preserve signed identity and actual
per-pair privacy grants; do not manufacture admission or bypass an active social
transaction to claim Matrix readiness. Keep the full delivery scope, but do not let optional
polish or preparatory work displace that first usable result. Report incomplete
links as implementation work rather than handing technical chores to the human.

## Cold web Conversation, independent of social admission

A fresh guest needs the shared native Codex engine as well as the Conversation
receiver and web process. A healthy web shell or `presentation` read only proves
the adapter, not that its first model request can reach the engine.

Reuse `onboarding_telegram.native_supervisor_code(base, selected)` and
`install_native(home, codex, code, budget=...)` for the existing
`daimon-onboarding-codex.service`. The legacy module name does not require a bot.
Keep its qualified supervisor, selected Codex binary, own `HOME`/`CODEX_HOME`,
provider cache and original histories. Do not rewrite an immutable base to add a
missing helper: select the already qualified runtime containing it. Observe an
existing singleton before starting it; an observation timeout never authorizes
stopping or replacing it.

Configure the Conversation receiver with `telegram.enabled = false` and
`codex.shared_app_server = true`, its own database/control socket and explicitly
allocated local human/chat/topic coordinates. These local coordinates are not
Telegram identities. Use the exact registered shared `human_ref` and stable
application UUID for the web binding; no placeholder bot or adult actor.

Readiness is model-free: check the existing daemon's `app-server daemon version`,
initialize its shared proxy, then use a supported metadata read when an own
retained thread already exists. The maintained Native observer permits its
`status(existing_thread)` read; it rejects `thread/loaded/list` before RPC.
The receiver's read uses both cursors:

```sh
telecodex --control "$RECEIVER_CONFIG" presentation list 0 0
```

A newly started service may report active before its control socket exists.
Use one finite readiness deadline and retry only the read against that same
process while the socket appears. Keep the original failed probe and inspect
the service/socket when the deadline expires; do not restart an already healthy
receiver to clean up a readiness result.

Do not create a synthetic human message or a new native thread to prime the cold
entry. Its first real human input owns ordinary conversation creation. Preserve
own prior task threads independently. Shared Home registration/login, native
engine readiness, canonical Matrix running admission, Tribe membership and human
device acceptance retain distinct evidence. Full social admission, a publication
broker, Escuela, Drive and voice workshops do not gate basic Conversation.

## Outbound visibility remains separate from admission

Current `onboarding_group_admission.publication_recipe` requires a new group
participant's first visibility installation to contain Telegram token/proof-key
references and an actual `dm.messaging.telegram-qualification/v1` probe. The
selected Matrix loader checks those references and constructs a Telegram
transport. A downstream App text projection or registered web Home does not
satisfy that native proof. These checks belong to the existing outbound
publication path, not signed membership or base native admission. Do not copy
an adult bot credential, fabricate bot or probe identifiers, or report outbound
messaging as released merely because membership was signed.

The existing portable successor is owned by
[Matrix496](https://github.com/AlterMundi/daimon-matrix/issues/496) and
[App452](https://github.com/AlterMundi/DaimonApp/issues/452). Its actual
first-install publication/proof contract must be integrated into the outbound
cohort route and qualified on the required receiving readers. Preserve existing
adult policies, pending originals and old proofs. Neither that implementation
nor a child's ability to view Telegram/Tribu gates admission. Use the explicit
membership-only path below for the original identities and jobs; after its
observed completion, continue actual receive-side application grants/readers
and outbound publication as separate effects. Keep prepared unsigned intent
within its original validity window; expiration is not permission to extend an
accepted operation or replay a partially executed one. Basic web Conversation
remains independent of this unfinished publication work.

## Finite School preparation in an existing companion

Install the selected exact kit and only that companion's reduced learner
profile, own signed identity reference, tool bindings and private media settings.
Verify the package manifest and exercise its finite foreground heartbeat without
inventing achievements, participation or capture grants. A successful installer
is not evidence that the companion model read the kit or that Drive works.

When the human has authorized actual receiving-model preparation, use one
bounded native task thread with explicitly operator-authored context. Keep it
separate from the child's first ordinary conversation. Preserve the chosen
provider, account and native history; read local selected material only and do
not enable background attention. Retain both the process outcome and the
model/tool results. A completed turn can honestly report that no files were
read: it is not successful adoption.

The finite operator invocation needs headroom for native tool-process bursts
inside the guest's unchanged task limit. The receiving continuation uses
`TasksMax=128`, `MemoryMax=1G`, `CPUQuota=200%` and a 540-second deadline, with
at most1MiB stdout and64KiB stderr retained. An earlier64-task invocation could
finish its model turn while every local tool failed with `EAGAIN`. Inspect
actual cgroup/command evidence before changing a bound. Continue that same
native thread after the concrete failure is corrected; do not create another
identity or repeat the successful companions' preparation. Preserve earlier
failed results. Model reading, private Drive roundtrip, family device acceptance
and capture agreements remain separate facts.

## Existing authority over the selected network

When the selected central authority is already reachable on the host's private
network, reuse it. The maintained `children-cluster-admission.socket` listens
only on the children's host loopback. The matching standard systemd relay
forwards to the operator-selected existing authority, without creating another
authority, registry, credential store, chat transport or model process.

The private root-owned `admission-proxy.env` supplies exactly the selected
`CLUSTER_ADMISSION_ENDPOINT=ADDRESS:PORT`. A root-owned service drop-in must
allow that exact address with `IPAddressAllow=ADDRESS/PREFIX`; the base unit
denies other network addresses except loopback. Do not place private addresses,
keys or tokens in source. Verify the installed binary's supported flags, unit
syntax, destination restriction and actual signed admission responses on the
receiving host. A listening socket is not end-to-end acceptance.

For each approved local Incus body, reuse the existing `onboarding-admission`
proxy contract: instance-bound guest loopback to host loopback, using the
profile's selected port. Preserve any conflicting device rather than replacing
it. This exposes only that fixed admission service and gives the guest neither
the Incus socket nor host files, administrator credentials or other resources.
The existing signed holder/authority protocol still authorizes each request.

The relay has at most 16 connections, 64 descriptors, 32 MiB memory, 10% CPU and
16 tasks. It exits after five idle minutes; socket activation remains available.
Use the already bounded host journal. Qualification must distinguish idle
standby, running relay, unreachable destination and refused signatures.

Disable future activation by stopping/disabling only this socket. Stop its relay
separately only when intended; dropping a live admission path can stop admitted
bodies through their existing lease supervisor. Do the stop test before live
body work, preserve all receiving state, and never turn it into global Stop.

Retain one current and one previous public request/profile per companion, plus
one bounded receipt (at most 64 KiB); cap this dedicated preparation at 512 KiB
per companion. Keep one checked public operator package within 8 MiB and retire
its byte-verified disposable transfer after consumption. Preserve pending or
uncertain operations rather than deleting them to admit more work.

Enrollment is not `Registry.adopt_running`: that requires actual admitted native
presence with matching body/embodiment/incarnation. Complete the existing
protected cohort and membership route before claiming Tribe delivery. No child
participation, media capture or external workspace/Drive grant follows from
this technical preparation.

## One controller across a selected Incus host

Keep a new Incus guest distinct from a relocated native body. A retained native
placement deliberately bypasses completed onboarding; it must not be used to
pretend that an unfinished container job is complete. When the canonical
controller runs elsewhere, use the existing `HostBackend` execution injection
with `RemoteIncusRunner`. Its protected per-plan locators select one parent,
project and exact instances; foreign plans or mixed physical hosts refuse.
Inventory/mounts still describe that Incus host. Guest commands and finite owner
sessions reuse the same parent/instance/guest checks and remote clock rebasing.
No local Incus fallback, second registry or receiving model is introduced.

For these retained read-only Incus mounts, the controller and physical host must
resolve the same selected absolute code, input and view paths. A byte-identical
base at a different controller path does not prove that the physical mount is
correct. Reuse its verified bytes at the retained mount path, preserving the
sealed release and separate file ownership; do not substitute a symlink or change
an existing guest device to a controller-only path. Qualify actual inventory,
all frozen/runtime/public mounts and an own-UID/OS command through HostBackend
before selecting that controller. Keep staging separate from canonical running
admission and Tribe membership.

The operator supplies a publication callback that invokes the existing
`onboarding_mounts.prepare_matrix_public` on the selected physical host, with
its qualified existing interpreter/code. Reuse the same validated plan and
immutable documents, preserve conflicting files, and read back exact hashes
before returning. Local publication alone cannot prove a remote read-only mount
is ready. Bound the helper's runtime, CPU, memory and output and retain uncertain
writes under their original operation. Stop only that task-owned helper.

A controller handoff preserves exact original job bytes, stage, operation IDs,
input manifests, grants, custody and public proofs in protected receiving state.
Verify all bytes/owners/modes and original signed coordinates before selection.
Staging is inactive: it authorizes no job retry, new key or admission. Serialize
actual ownership selection and retain conditional restoration for only unchanged
operation-owned changes. Keep the original authority/registry and living peer
state; do not reset jobs or copy virtual machines and private histories merely
to move their small controller records. Retire the verified disposable transfer,
keeping required operational state and unfinished work.

For local contract tests, select an existing interpreter with the repository's
actual declared Matrix commit. Independent test dependencies may be supplied
without shadowing that SDK. Verify its installed provenance; do not fake package
metadata or reinstall a shared development SDK to make a mismatched test pass.

## Shared audio seed bank in child contexts

Scheduled daily inventory supervision and its scoped stop/recovery route are
maintained in [children-daily-observation.md](children-daily-observation.md).
Execution health does not establish complete security coverage or native/Tribe
admission; neither is a prerequisite for the already delivered basic Conversation.

The existing `audio-seed-bank` skill and its transcription/institutional-Drive
dependencies belong in each child companion's own skill/context installation.
The stable shared viewer is https://apps.dmn.homes/seeds/ .
Preserve each being's identity and use its own authorized invitation/binding;
copying a workflow creates no bank or Drive grant. Record installed hashes,
actual native access and model reading separately. Human-selected seed audio
retains original bytes, attribution, audience and transcript uncertainty.
Ordinary voice commands are never automatically archived or transcribed again.
Nexus owns table grants and Homes owns the canonical Apps publication; reuse
those maintained services rather than another bank or child-specific app.

## Receiving institutional Drive access

Use each companion's existing institutional connection and private learner folder
from the maintained project map. Inspect its actual account selector/schema and
verify `institucional@altermundi.net`; leave unrelated accounts untouched. An
operator read, installed skill or prepared folder reference is not receiving access.

The selected Codex singleton uses Unix WebSocket, including its stdio proxy.
Reuse the owning socket with a Unix WebSocket client, bounded `app/list` pages
and a deadline compatible with the native 90-second limit. Suppress irrelevant
`app/list/updated` notifications; selected-connector discovery is not a complete
catalog observation and requires no model turn or daemon restart.

Use normal file-aware tools for upload. In Core15 `0dee30e37`, manual
`mcpServer/tool/call` bypasses the model-tool handler's `openai/fileParams`
preparation. Retain a failed reply; it does not prove remote absence. For one
tiny operator marker without child content, reconcile the exact name/parent
before any write, then verify identity, private permissions and recovered bytes
against the original. An unmaterialized download reference can be followed by
the connector's supported inline-content read; do not repeat a successful upload.
Keep actual tool/byte evidence separate from the model's final report.

A resumed School thread may retain its reading-only permission profile. A live
`thread/resume` can ignore configuration overrides. For an explicitly authorized
Drive task, use the already selected own-virtual profile through
`thread/settings/update`, read back the effective settings before provider input,
and restore/read back the original settings at the physical terminal. This grants
no external access and must not override an actual external approval decision.
Preserve rejected/uncertain attempts and original operation IDs; no new thread,
identity, helper, account or background attention is needed.

After verification, update the own private Drive binding and Escuela `media-config`
check reference. Keep family capture/voice/publication agreements unchanged and
completed kit-reading/heartbeat jobs intact. Retain only the tiny selected marker
and bounded evidence; qualification is not recurring ingestion or backup.

## Retained members on different hosts

A guest owner may select its existing private `host_config` and canonical
`host_config_sha256` together. The existing complete owner-record digest binds
that choice. Recheck it before effects and require its original explicit native
or VM placement and plan authorization. Use that owner backend for lifecycle
preparation and finish; never copy adult administrative grants into child state.
Omitting both fields retains the original primary-host behavior. This repairs
the full Tribe coordinator; it is not a prerequisite for basic web Conversation.

## Remote Incus public-code transfer dependency

The existing `IncusBody` carrier sends a verified public code generation through
host SSH and `incus exec ... rsync`. The **receiving guest** needs the `rsync`
executable; having it only on the controller or Incus host is insufficient.
Include it in the guest's normal Debian tooling baseline. If an existing guest
lacks it, inspect its actual package state and signed-repository install plan,
then install the selected package through the normal native package writer.
Preserve active package operations and companion services; a disconnected
observer must not kill dpkg or cause an uncertain install to be replayed.
The rsync daemon is unnecessary for this carrier; preserve an existing service
selection, and keep newly introduced daemon service inactive for a CLI-only tool.

After correcting the dependency, resume `prepare_code` with its retained
fingerprint and stage ID. Inspect the actual partial candidate before retrying;
never create another identity, enrollment or transfer generation to hide failure.
`HostBackend.runtime_available` resolves the same registered physical carrier
for a remote Incus placement and uses its `prepare_code` / verified-file route;
a controller-local Incus code mount is not an availability prerequisite. This
code-placement resolution preserves the original guest service profile.
Keep candidate installation, normal own-UID CLI qualification, live code selection
and signed social admission as separate observations. Retire only the consumed
private package download cache; preserve the original job and native journals.

## Plain admitted Matrix code update

`ManagedRuntime.update_native_code` selects an already installed immutable code
candidate for an explicit `native-admission-only` body. Use the original host,
job, admission profile and a single retained operation UUID. It takes the existing
job locks, authenticates the current admitted process, freezes its exact unit and
runtime-bundle preimage, and delegates validate/quiesce/select/start to the
existing `GuestServiceBootstrap` unit writer. It changes only Matrix ExecStart;
Conversation, credentials, identity, native stores and controller grants stay in
place. There is no group, visibility or Telegram prerequisite and no enrollment
or grant renewal. A different operation/candidate is refused while the retained
per-body update exists; reconcile that record before selecting a later update.

Lost effects are resumed under the same root bootstrap request. The final
observation verifies the unchanged runtime bundle, admitted origin, selected
unit and actual successor process. This proves code selection and native
presence only, not signed membership, readable group selection, messaging
release, device acceptance or model reading. Keep these later observations
separate, and never use a code update to extend an expired social recipe.

## Signed membership without messaging publication

For an already admitted original body, a protected receiving operation may
select exactly `membership_only: {"schema":"cluster-native-membership-only/v1"}`
in its intended transition. Keep its original job/plan and owner bindings,
verified public authority closure, current native governance and fixed social
recipe. `GroupCoordinator.advance` then calls `advance_membership_only`, which
reuses `CohortController.admit_membership_only` and the existing signed native
invite/accept/ingest sequence. It does not enter controller bootstrap, group
publication, native-conversation priming, Telegram or technical speech.

The physical caller owns scoped maintenance of the actual Matrix units and
forward recovery. Before governance mutation, the coordinator opens every
required owner's qualified finite CLI under that owner's existing exclusive
native writer. A running Matrix daemon refuses that same kernel lock. The
coordinator keeps all writer sessions alive throughout the signed phase and
checks their liveness before every missing effect. Historical stopped receipts
cannot replace these writers. The original full messaging path keeps its old
revocation/lifecycle/publication requirements; unmarked old preparation intents
cannot acquire admission-only effects. Admission-only rejects publication or
communication scopes in the same intent.

Native requests and fixed acceptance timestamps remain in their original
journals across lost acknowledgements. A completed social result is historical,
with receiving readiness unobserved; it does not reopen writers or repeat
signatures. Preserve expired/unattempted social drafts rather than extending or
replaying them. Use actual current native state for the next authorized missing
admission, and retain an uncertain original under its exact request identity.

After signed membership, retain each owner's approved public verification
context with the existing `membership-authorities` owner operation. Complete
actual serving-code/context adoption and receive-side grants separately. Group
receiving qualification, outbound visibility and messaging release retain their
own truthful states and obligations. No child Telegram account is required.

A current shared application's bootstrap `relationship_events` can include
signed history for retired Tribe refs. Select governance by the **actual
selected target `tribe_ref`**, then verify that subset and its current membership.
Keep other histories in their owning original artifacts. Do not relax
`membership_recipe` to accept unrelated Tribe events, extend an invalid draft's
expiry, or invent a new invitation to hide a preparation error.

An explicitly selected membership-only operation becomes terminal once its
retained native signed result is verified. This frees the same Tribe target for
the next original entrant. It does not complete general onboarding or assert
running readers/visibility; an exact completed retry returns that same result
without opening writers or issuing another invitation.

The independent read-only writer initializations run concurrently (at most
eight), within the same finite owner lifetime. Every actual writer must be held
before any governance mutation. Serial bootstrap otherwise spends the first
owner's lifetime loading later owners as the small cohort grows; increasing
ceremony or replacing an already signed invitation does not resolve that cost.

For a plain admitted body, use the existing `admitted-running` observation and
compare its authenticated base `loaded_runtime.qualified_startup` with the
selected code. `--current-native --require-loaded` is the preserved **group**
observer: it requires an actual signed group selection. Requiring it for a plain
body would reintroduce the group-publication dependency admission just removed.
Serialize ordinary host approval lookups that share the protected approval
store; this is separate from concurrent native writer initialization.

### Receiving a signed group with outbound closed

For an owner-approved group application with no visibility installation yet,
the receiving runtime can use `receive_only_application_view`. It verifies the
ordinary signed application and retains its native incoming transport, canonical
relationships and scoped client. Under the existing native writer, initialize
only the closed controller's registered catalogs through the SDK's explicit
versioned migration, then validate their authentication before listener startup.
Loading an application alone does not perform that catalog migration.

This mode never installs visibility or enables outbound release. A retained
visibility installation, an already released base controller, or additional
outbound applications must not be silently downgraded into this mode. Preserve
the early/late signed-selection comparison and current owner-context guards.
Receiving readiness still requires actual installed application grants, native
listener startup and authenticated reads; a fixture result is not deployment.

### Keep the receiving context current

Nicolas's explicit requested outcome supplies the operational authorization.
Apply the existing owner writers and held signing/grant route directly; an owner
conversation's response or a review quorum is not another admission prerequisite.
If a procedural adapter demands that repeated approval, repair it. Missing
verification metadata and expired profiles remain technical work with truthful
signatures and effects; they are not requests for the human to authorize again.

After genuine native admission and signed membership have been observed, carry
each body's own dated observation into its existing mutable operational context.
Do not rerun the original context/memory stage or rewrite its selected SOUL.
Preserve the entire installed instruction prefix and compare its exact digest
before appending one bounded replaceable status block. Bind the observation to
that body's actual runtime bundle/origin and original acceptance; this is a
local context pointer, never another identity registry, authority or grant.

Read back the resulting private files as the actual receiving user. Preserve
the runtime bundle and running Conversation/Codex process identities. Installed
guidance is not proof of model reading: no model turn, service restart, peer
attention or recording activation is needed to deliver this context update.
Keep group readers/outbound release and real family/device acceptance explicit.
