# Relocate an existing body to a native host

This is a physical move of one retained body, not fresh embodiment enrollment.
Preserve its signed being, embodiment, incarnation, custody, authority history,
native conversations/goals, memory, bot/topics, accounts, skills and application
state. A historical host component in body_ref does not select current physical
placement. Resolve actual hosting through the maintained resource record.

Use the human's selected native host. Do not introduce Incus on the destination
when the requested result is host administration. Scope any shutdown to the
moving body; migration never authorizes global Stop or interruption of its peers.
Inspect existing persistent transfers before starting another. Transfer directly
from the stopped source, preserving all files, metadata, hardlinks and explicit
UID/GID mappings. Retain complete source system files separately from the native
host OS. Do not silently exclude state outside home or create a large intermediate
archive on a pressured source filesystem.

Reuse successful transfer checksums and compare the complete tree. Independently
verify critical native/memory databases with their WAL companions and behavior
configuration. Preserve receiving probe changes before restoring original data.
If a receiving filesystem cannot represent original metadata, retain the exact
original values and content proof separately; do not rewrite a failed literal
comparison as success.

## Whole-host preparation and an Incus-managed VM

When the human selects a complete host move, inventory the Cluster control plane,
shared services, user and system units, sockets, timers, storage mounts and all
bind-mounted state as well as each daimon. Copying one home or a container root
is not complete: custom home volumes and immutable code mounted from elsewhere
must remain recoverable. Preserve the original UID/GID, ACL, xattr, hardlink and
symlink metadata and the source mount map. A native target must keep its own
boot, network and administrative access rather than blindly replacing its OS.

Classify unit activation separately from copying unit files. Do not restart every
unit that was active in an earlier inventory: a per-connection service needs its
owning socket, a timer-triggered worker should retain its timer, and a historical
one-shot timer can run its old action again when restarted. Preserve original
files and enablement as evidence, but keep retired bodies, qualification fixtures,
completed one-shots and on-demand applications unselected. A historical unit that
is inactive yet enabled must not silently become a receiving boot activator.
Keep receiving distribution/boot/network units authoritative. Refresh application
unit bytes at the final delta and reapply only explicit receiving adaptations;
installing an earlier candidate over refreshed files can undo later deployments.

Before selecting host-service data, compare each consuming account's numeric
UID/GID with the receiving OS. Package installation can allocate the same number
to a different service. Inspect the actual daemon process credentials as well
as systemd's `User=`: daemons may start as root and drop privileges internally.
For example, the receiving ZeroTier account differed from Source even though
its unit did not select a user; copying numeric ownership alone assigned its
private node identity to the receiving DNS service. Translate only the selected
ZeroTier state and verify that the actual receiving daemon account can read its
unchanged identity, without starting a duplicate node. The receiving Caddy
account also occupied Source's
Cluster UID/GID. Preserve receiving accounts and administrative admission, prepare
only missing non-login service accounts, and translate ownership on explicitly
selected service-owned paths with rsync's user/group maps. Keep the archived
original metadata. Never replace account databases, globally chown staging, or
assume `--numeric-ids` alone establishes correct receiving access. This mapping
is for host services; retain each body's independently verified UID/ACL mapping.

Include private executable directories in that same mapping. An old numeric
Cluster group can now name the receiving web-service account: unchanged code
then fails before startup with a working-directory permission error. Verify the
actual service identity can traverse its selected working directory, read its
pre-start helper and load the selected interpreter/config with the unit's
environment and supplementary groups before fencing Source. Translate only
selected metadata; keep original metadata and code bytes, rather than making
private releases world-readable. Use the installed CLI entrypoint and explicit
receiving config for probes; a root-only import or an unrelated historical
credential does not qualify the consuming service.

Translate explicit local UID references in selected configuration together with
their service-owned stores. For example, `consent_uid` names the receiving intake
service account; copying its old numeric value after mapping the seed store to
the new account makes `HostConfig.load` refuse the worker. Preserve consent,
plan and grant record bytes. Validate the actual selected config and completed
native/VM routes in the intended mount view without running intake or ticking
jobs; an unmounted placeholder is not that view.

When merging Source control state with an already active receiving VM, retain
its current qualified local locator instead of overwriting it with the Source
remote route. Use `NativeBody.load` and the config's canonical placement digest;
a JSON file's byte hash is a different representation. Preserve both provenance
and the receiving binding, without re-enrollment or duplicate activation.

When the canonical admission authority moves, update its actual consumers too.
A healthy authority endpoint does not prove a running native Matrix holder can
renew through its configured route. Prefer the existing authenticated local
endpoint for a co-located holder, preserving the pinned authority, holder key,
identity and history. Write admission configuration through the owning canonical
JSON format; an equivalent pretty-printed document is deliberately refused.
After the handoff, verify the affected holder's real lease renewal and selected
runtime, then one genuine signed receiving journey. Reuse earlier unchanged
qualification. Preserve failed attempts and current journals; do not recreate
identity, replay messages or revive Source to clear a refusal.

Relocate health observation with the runtime. Keep old observation history and
use distinct placement target IDs when the physical resource changes; do not
report new-host health as recovery of an old-host failure. Verify the actual
finite probe and next timer trigger on the receiving manager. An enabled timer
can be elapsed without a next trigger after restoring old scheduling state;
starting the existing finite probe once while its timer is active can restore
its configured cadence without adding another scheduler. Check the resulting
scheduled execution rather than treating enablement as coverage.

Initial direct copies from a running source are staging, not a coherent final
snapshot. Keep them private and outside active service paths. Bound transfer
runtime, retained partials/logs and destination headroom; retain exact jobs and
resume their existing destinations after interruption. Keep source writers and
production routes active until the human's selected cutover boundary. Never run
two copies of a bot, VPN node, signed writer or paid worker to test a move.
The final writer fence, consistent delta, receiving activation and DNS switch
remain separate from initial preparation. Preserve uncertainty and paused work.

A fenced body's final delta takes disk priority over this migration's background
bulk seed. Set priority on the actual reading transfer child, not only its parent;
an explicit launcher can otherwise restore the lower priority. Inspect real I/O
advancement before treating a quiet checksum log as a stall. Adjust only the
identified task processes and preserve their retained jobs and destinations.

For a source `incus exec` tar stream, disable its unused stdin explicitly and
use GNU timeout `--foreground` in the task-owned tmux pane. A separate timeout
process group can stop on terminal control while its parent session and remote
reader remain alive. Inspect actual process states and transfer advancement;
a live tmux handle alone does not prove bytes are moving. Terminate only a
verified stopped task group before resuming the retained inert destination,
preserving its previous terminal result and partial bytes.

A final stopped-container delta can use a readonly view in a task-private mount
namespace with the existing pinned SSH/rsync-to-VM route, without a source archive
or restarting the old body. Reproduce the complete original disk mount map,
including bind mounts inside home; copying only the underlying home volume can
replace mounted admission inputs with empty protected directories. Inspect each
volume's actual physical ownership and retained Incus ID map separately: an
unshifted root and shifted custom home must not receive the same translation.
ID-mapped readonly mounts preserve the source filesystem rather than chowning it.
Before fencing, compare UID/GID/mode and symlink metadata against the live guest
namespace. Preserve symlinks as links; following an absolute link from the host
view can escape to an unrelated host path. Keep these mounts private, bounded to
the transfer, and unmount them on exit. Never exclude mounted code by applying
an implicit one-filesystem copy restriction.

For a selected KVM guest, first qualify host virtualization and an Incus storage
pool on the data filesystem. Reuse `clusterctl create` with a pinned **local VM
image**, followed by the ordinary journaled `start` when a blank guest may boot.
Incus derives the virtual-machine type from a local image's metadata; an absent
`--vm` flag in Cluster's adapter does not prove a missing creation capability.
Confirm the imported image fingerprint and type before creating, and independently
read the created instance type afterward. A named alias alone is insufficient.
Use an existing profile for explicit CPU, memory, disk and autostart bounds.
Keep the receiving resource operation journal; creating a blank generic resource
is not Matrix enrollment, identity adoption or control-plane migration.

Debian separates QEMU features into packages. Incus may install successfully yet
VM start can fail without `qemu-system-modules-spice` when recommendations were
omitted. Read the retained operation's actual `last_error`, correct its concrete
runtime dependency and use `clusterctl repair --operation-id` for that same
operation. Do not recreate the VM or mint another operation to hide the failure.
A running QEMU process alone does not establish agent or application readiness.

Do not import a container's device/configuration map unchanged into a VM.
Filesystem disks can use virtiofs/9p; verify ownership and access as the actual
consumer. VM proxy devices support NAT mode only, with a static guest IP and the
host as gateway. Container loopback/Unix proxies and host TUN passthrough therefore
must be translated by the owning receiving backend, preserving each original
application's audience and grant. Extend that existing composition if its VM path
is absent; do not claim that container-device validation proves VM readiness.
This is not permission to expose an unauthenticated service or invent another
Matrix transport. Retain originals as migration evidence.

Check filesystem visibility inside the actual VM, not only its Incus device
map. With the qualified Incus6.0.4 Debian13 guest, a newly hot-added read-only
directory was not visible; the same device was mounted on cold boot and its
file checksum matched the host. Removing that active mounted device also
failed; the guest shutdown was then observed waiting on the filesystem unmount.
The identity-free blank guest required a force stop, followed by repair of the
same Cluster stop operation and offline device removal. Do not apply that
blank-guest recovery to a running body or infer production interruption consent.
Stage the required disks before first body
activation and verify them as the consumer. A configured device is not proof
of an accessible code path; never restart an active body solely to conceal
that distinction.

Incus source behavior and device contracts:
[image-derived type](https://github.com/lxc/incus/blob/v6.0.4/cmd/incus/create.go),
[VM proxy restrictions](https://github.com/lxc/incus/blob/v6.0.4/doc/reference/devices_proxy.md),
[disk sharing](https://github.com/lxc/incus/blob/v6.0.4/doc/reference/devices_disk.md).

## Runtime capability and startup

When the migrating native turn is itself executing the cutover, do not ask its
daemon to drain and then wait for that same turn to finish. The operator cannot
finish while it is waiting, and the draining daemon refuses recovery admissions.
Finish the operator turn before a graceful stop, or use the explicitly authorized
body-scoped process boundary with an independently managed coordinator and return
timer. Inspect the actual daemon cgroup; a TUI-owned daemon is not supervised by
an unrelated service merely because that service adopted its control socket.
Retain native files and WAL companions, and never use this body operation as a
global Stop or replay an interrupted input.

Correlate return evidence to the current arm time and operation. A previous
partial return file is historical while the newly armed timer has not fired;
it must not terminate observation of the current return. Preserve both outcomes
and observe the actual service/native continuation before calling recovery
complete. An attachment-queued receipt alone proves neither model continuation
nor delivery to the human.

Disabling Telegram or the bridge's goal-recovery loop does not make a retained
native goal store inert. Resuming a native thread can continue its active goal.
Resolve the single coordinator before admitting the original native home; use
the separate preview for preparation without loading the original goal store.
If a receiving goal has already continued, preserve that live branch and attach
its existing turn rather than activating another copy or overwriting its state.

Keep divergent native branches attributed and complete. Freeze and retain the
final Source rollouts, native SQLite/WAL state and recorded counters separately
from the live receiver. Preserve the same goal identity and creation time; retain
the shared-base counters and each branch's later counters so their aggregate
does not count the base twice. Do not manufacture usage or merge native stores
with ad-hoc SQL. A resumed conversation may have appended thread-settings
metadata: prove the exact common conversation prefix, inspect every later record
and preserve both full files. Equivalent settings with different timestamps are
not missing dialogue; new human/model records require actual reconciliation.

Migrate companion receipts with their consumer. Some activity/title receipts bind
the database path, device and inode, which change during a coherent move. After
proving the same original journal and bot/human binding, explicitly adopt the
receipts for the receiving physical file using the owning adapter. Preserve their
items, uncertainty and preimage; resetting them can repeat an ambiguous external
effect. Probe the effective unit, including dropins, and observe its real heartbeat.
`Type=simple` startup alone does not establish socket or HTTP readiness.

Use one finite startup deadline through admission launch, all composed views and
SDK reader restoration. A selected SDK that supports `startup_deadline_ns` receives
the remaining shared envelope; legacy SDKs retain their existing API and limits.
Do not give every layer a renewed timeout or cancel valid signed-history recovery
with an independent five-second view subwindow. Keep live-control freshness and
credential validity separate. Closed recovery stage/code diagnostics can identify
deadline, storage and verification failures without logging private exception text.

A matching Python version alone is insufficient. Test the actual primitives used
by the receiving implementation before opening custody. Eko's 2026-10-26 move
found CPython3.13.5 builds without `os.pidfd_open`, which cannot provide Cluster's
kernel process observation. Do not replace that observation with a weaker check.
The retained original interpreter was ported with its required private libraries;
the native OS interpreter and global libraries remained unchanged. Its original
ensurepip wheel also matters: an unrelated host pip can lack the SDK verifier's
dependency-check API. Preserve mutable interpreter-binding preimages, verify the
actual qualified SDK startup, and keep immutable application/dependency artifacts.

Public helper staging and private SDK preparation are separate existing steps.
Before selecting a new helper/SDK entrypoint, run the selected
`clusterctl.onboarding_target sdk-prepare` as the actual receiving owner, using
the retained native interpreter and exact runtime/base/plan pins. This prepares
the content-addressed private environment and closed runtime-import tree; it
does not start a model or select a service. Public `NativeBody.prepare_code`
alone does not perform it. `admitted-serve` intentionally observes those prepared
artifacts rather than installing dependencies during startup. A missing SDK
directory therefore needs this preparation, not another transfer, identity
enrollment, provider login or service-restart loop. Preserve and inspect any
existing preparation attempt before resuming its supported idempotent operation.

Let the selected systemd supervisor start Codex. Observe readiness through its
existing native version/control RPC and verify the actual daemon and updater
cgroups. A second launcher outside systemd can steal singleton ownership.
Retain native histories and uncertain inputs; readiness recovery is not input
replay. Provider login acceptance is separate from a running daemon: verify native
account/quota operations, preserve the selected account and request its existing
device-login procedure when the provider has revoked those credentials.
After a completed external CLI device login, reload the existing daemon through
`account/read` with `refreshToken:true` on its authenticated native connection.
Verify the retained selected account and an actual `account/rateLimits/read`
response before reporting provider acceptance. A persisted `codex login status`
alone is insufficient; a cached empty account before this reload does not mean
the new login failed. This recovery needs no daemon or conversation restart.
Run a private diagnostic helper from an owner-readable task path, not an
operator-only directory the receiving user cannot traverse.

## Matrix, shared services and receiving activation

A phased move can make a shared service authoritative on the receiving host
before the native primary or remaining applications move. Release only that
service's Source writer, transfer its coherent current state, and preserve its
actors, grants, credentials and browser origins. The old edge can forward to the
same receiving writer during DNS cache convergence. After public receiving
admission, recovery uses current receiving data; restarting an independent old
authority or restoring its old session database would lose accepted work.

Record those adopted stores and receiving units in the existing migration
checkpoint. Exclude them from subsequent Source home deltas and preserve their
receiving configuration during bulk unit selection. Earlier whole-host scripts
that assume no receiving writers are now historical preparations, not a safe
continuation. Retain their evidence, revise only the affected remaining actions,
and keep already adopted services running.

For shared home/login authority, validate its consumed public identity
projections against the currently served signed Root, not only the runtime
bundle. A cached public actor authority can remain stale after an otherwise
successful Matrix rollout. Refresh only that verified descendant projection;
preserve identity, owner credentials, grants and session ancestry. Read the
actual gateway's authorities, actors and tribe view before selecting it. A
public page returning HTTP200 does not establish coherent authorization.

Preserve the existing membership group and deliberately directed lanes. No new
per-pair enrollment is required. Keep common services with their established
owners, preserving application authorization and scoped file grants. Keep live
native/Matrix/memory databases local to the body. Verify shared files as their
actual consumer, including parent-directory traversal and selected write grants.

Cross-host delivery must retain live shared dependencies, not just snapshots of
their former bind mounts. Reuse the established per-actor restricted SFTP/SSHFS
route for research clients/outboxes and the same-audience presentation cache,
keeping read-only and write grants distinct. Use the moving body's own scoped
key; do not copy another being's key or weaken administrative SSH admission.
Retain private local copies before selecting remote mounts. Pin the actual
receiving service SSH host key before a later shared-host move, preserving the
old pin during the phased transition; do not replace the new host's administrative
SSH identity to make existing client pins work.

Resolve messaging endpoints from the actually selected application and running
listeners. An absent listener plus a restarting service is unavailability, not
proof that the selected route became obsolete. The existing native compatibility
address/socket-proxy composition can retain old private endpoints. Keep that
loopback address separate from the VM's real gateway, preserve peer application
authorization, and verify signed receiving delivery after activation. A socket
relay is physical routing, never per-pair enrollment or proof of group readiness.

For retained local health journals, use the owning Alerts monitor's explicit
`--relocate-to` transition after the final coherent copy. Preserve its original
authority, incidents and uncertain outbox; select whole-OS memory observation
for a full VM/native OS and independently verify receiving samples. A system
slice alone excludes other consumers and is not full VM memory coverage. Do not erase the observer database
to bypass its binding check. See [the maintained observation relocation contract](https://github.com/AlterMundi/daimon-alerts/blob/main/docs/runtime-health.md#move-a-retained-local-observer-to-a-different-physical-boundary).

Retain the original VPN node only on the selected active host. Preserve compatible
old ingress during DNS cache expiry. Verify dedicated receiving HTTPS before
changing only the moving body's DNS records; unrelated wildcard/private records
and shared login authority remain unchanged. A network connection or Telegram
echo does not prove Matrix receiving delivery.

Inspect the actual receiving gate after startup. A retained revoke/disabled intent
must not be silently overwritten by an older positive record. The human-authorized
move may require a new explicit owner activation. Use the existing receiving-owner
prepare/apply controls with current process/head and signed-roster CAS; reuse only
still-valid compatible reader qualifications under unchanged authority and wire
artifacts. Retain the exact request and receipt. Do not edit gate tables or invent
receiving evidence. A failed or ambiguous speech attempt keeps its original ID.
Only the supported explicit recovery profile may recover a known-unattempted
expired carrier; it preserves the original speech/publication.

Require real directed and group journeys with signed receiving receipts. Then one
scoped managed Matrix restart should recover the selected readers under the new
host's stable binding without a second activation or model turn. Preserve the
before/after process and recovery evidence. These contracts already exist; a new
messaging protocol is unnecessary.

The current Matrix `dm.receiving-release/v1` declares one shared `matrix_sdk`;
its per-receiver artifact overrides explicitly exclude that key. Do not fabricate
a mixed-SDK v1 manifest or simply remove its revision checks. For an authorized
body-specific owner repair involving different SDKs, qualify coherent releases
for each selected SDK and verify their common wire/authority requirements before
the current owner controls. Preserve that explicit repair's exact mixed vector;
it does not establish completion of a uniform-SDK `CohortController` rollout.

## Full-OS VM maintenance placement

A retained body in a full Incus-managed VM uses the same native OS code
adoption and owner-control contracts as a dedicated host. The historical
`native_by_name` selector also accepts a protected
`cluster-incus-vm-body-placement/v1` locator: exact approved `plan_digest`,
local Incus `project`, `instance`, `instance_uuid`, host and guest machine-ID
SHA256 values, `bootstrap_python` and `/home/agent` home. The instance name must
be the existing plan's `dm-<name>`; the actual Incus type and UUID are checked
before agent execution or transfer. A replaced container/VM is refused.

The locator uses the local agent when the operator's machine identity matches
the pinned parent host. During a phased move, an optional `incus_host_ssh` map
can retain the existing authorized parent-host `host`, `port`, `ssh_user`,
`identity_file`, `identity_uid`, `known_hosts` and `bootstrap_python` references.
A different operator host must use these validated private references. The
remote launcher independently checks the parent machine identity before Incus
checks the VM type/UUID; the guest launcher still checks its own machine identity.
After the control plane moves to that parent, the same locator uses the local
agent without requiring obsolete Source SSH files. No admission keys change.

Qualified public-code transfer from another operator uses the existing rsync/SSH
route directly into the Incus guest's protected stage, then the same inventory
verification and atomic publication. No third public-code cache or private-key
copy into another being is needed. The receiver guest needs `rsync` for this
remote path; a container package inventory does not prove it is installed.
Prepare the distro package and dependencies before selecting the remote
maintenance route, using verified offline packages if staging egress is fenced.
The same retained preparation resumes after
uncertainty; do not change its ID or treat a transport timeout as no effect.

This locator reuses Incus agent transport, not another SSH admission.
The same command validation, receiving clock rebasing, UID selection, original
request input and uncertainty behavior remain in force. Only qualified public
code is copied into retained staging, independently verified and atomically
published inside the guest. Existing code is verified rather than replaced.
Private home, sessions and authority are separate migration data, never code
preparation inputs. No model, service or conversation starts during preparation.

Physical lifecycle stays in the ordinary Cluster resource journal. The OS
maintenance placement does not run container initial-enrollment reconciliation,
recreate a home volume or hot-mount successive SDK generations. Source host
proxies/shared-service composition must still be translated and verified under
their actual audience and grants before production cutover. A passing transport
qualification does not establish that integration or receiving acceptance.

## Physical ownership and maintenance frontier

Update the resource catalog, receiving capability maps and consumed agent context.
Retain old placement as history and rollback, never as a live local container.
Observe the actual native application slice rather than the old container limit.
Preserve incident/outbox revisions when explicitly reconciling monitor placement;
do not delete journals to clear its binding guard. Local monitoring, off-host
availability observation, consistent backups and tested restore routes are
separate receiving responsibilities.

Host configuration may select a protected `native_by_name` placement locator for
an existing approved plan. Each row pins `placement` and `placement_digest`, so
changing a referenced placement cannot redirect a retained maintenance operation.
The `cluster-native-body-placement/v1` record retains
that plan's digest, pinned SSH host/port/user, local identity and known-host file
references, receiving machine-id SHA256, home and qualified bootstrap interpreter.
It contains references only, never credential values. Resolve exact private
placement from the receiving operator record. Existing administrative access is
used only for authorized foreground operation; a new SSH service requires its own
dedicated identity under the repository's administrative-access rule.

`HostBackend.execute_body` selects real native execution or the existing Incus
backend. Native maintenance copies only qualified public code, independently
verifies receiving bytes and invokes the existing target, owner-control and
service contracts. It neither models a native host as an Incus instance nor
creates fake mounts. Native Incus operations are refused. Native owner commands
retain a closed system search path including `/usr/local/bin`, where an
administrator-installed Codex launcher can live. They never inherit arbitrary
SSH environment or user-writable PATH entries. The owner-control
deadline is rebased to the receiving kernel and time namespace, bounded by both
the sender's remaining interval and original wall expiry; remote process and
admission proofs still come from the actual receiver. Timeout preserves the
operation's uncertain effects and never implies permission to replay it.

The protected native placement explicitly selects the native Matrix service
inspection profile. It preserves root-owned `99-native-*.conf` additions for
network readiness, required mounts, the application slice and the executable
search PATH. Executable/identity overrides remain rejected, and the existing
bootstrap operation freezes every accepted drop-in's exact bytes before any
service effect. Incus receivers retain their existing stricter guest profile.
Candidate native unit arguments keep the placement's qualified bootstrap Python;
they must not fall back to the host's unrelated `/usr/bin/python3`. These are
extensions of the existing named-unit bootstrap, not another update mechanism.

An old instance name must not select the stopped source or cause a VM restart.
Preflight every native receiver's qualified artifact, interpreter, authenticated
owner and current selected state before cohort revocation or activation. Until
the adapter and placement are actually adopted, that receiver remains an explicit
maintenance gap; source code alone is not fleet update convergence. This transport
does not change Matrix identity, signed authority or message semantics.

## Retained operator recovery access

Nicolas reiterated on2026-10-28 that CompAII remains the authorized operator
and recovery backstop. A relocation must preserve that existing administrative
reach alongside Nicolas and each daimon own access. Do not remove keys, narrow
existing operator grants or make recovery depend only on the migrated bot or
provider login. Reuse existing admissions; this instruction grants no new
custody, identity, cross-being data access or global Stop.

## Rollback

After native placement is accepted, an old worker/configuration pair is not a
safe rollback if it restores retired Incus reconciliation. Preserve its bytes
as history, but keep only the onboarding worker stopped on an uncertain failed
maintenance adoption and recover forward using the native placement and a
compatible worker. A software rollback must retain the native-source exclusion;
it never authorizes starting the stopped origin or restoring old job databases.

Keep the source stopped and retain its original configuration/data. Before moving
back, stop the selected receiving writer and observe release of its admission.
Return current state and history with inverse ownership mapping; preserve all new
accepted authority and journals. Restore compatible interpreter bindings from
their retained preimages or provision the exact selected runtime on the source.
Disable retained forwarding before reusing old listeners. Reverse only the moving
body's DNS records. Never start both copies or restore a stale zone/database over
newer accepted work. Keep private bindings, keys, addresses and raw evidence in
the receiving operator record rather than this runbook.

### Retain owner credentials across a current authority update

A registered home owner credential retains its original home, being and binding
revision. Advancing the being's current authority must not silently rebind that
key or require a new browser login. After the shared gateway's current public
projections are verified, the trusted host operator can accept the current
revision for that existing home:

```sh
python -m clusterctl.homes.host accept-owner-authority \
  --config CONFIG --reference HOME --previous-digest CURRENT_CONFIG_SHA256
```

Use the actual gateway owner's interpreter and protected configuration. This
operation validates the selected native authority and exact config, keeps the
original key/owner binding and accepts only the same existing owner/home. It
changes no browser session, scope, actor or key. There is one current acceptance
row per credential, rather than another entry on every update. It is a host
provisioning command, never an owner-local or browser operation. A later authority
revision is denied until the authorized rollout accepts that current revision;
revoked credentials remain denied. Verify an actual owner-local read afterward.
