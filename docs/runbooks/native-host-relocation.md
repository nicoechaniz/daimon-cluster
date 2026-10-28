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

Initial direct copies from a running source are staging, not a coherent final
snapshot. Keep them private and outside active service paths. Bound transfer
runtime, retained partials/logs and destination headroom; retain exact jobs and
resume their existing destinations after interruption. Keep source writers and
production routes active until the human's selected cutover boundary. Never run
two copies of a bot, VPN node, signed writer or paid worker to test a move.
The final writer fence, consistent delta, receiving activation and DNS switch
remain separate from initial preparation. Preserve uncertainty and paused work.

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

Incus source behavior and device contracts:
[image-derived type](https://github.com/lxc/incus/blob/v6.0.4/cmd/incus/create.go),
[VM proxy restrictions](https://github.com/lxc/incus/blob/v6.0.4/doc/reference/devices_proxy.md),
[disk sharing](https://github.com/lxc/incus/blob/v6.0.4/doc/reference/devices_disk.md).

## Runtime capability and startup

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

Preserve the existing membership group and deliberately directed lanes. No new
per-pair enrollment is required. Keep common services with their established
owners, preserving application authorization and scoped file grants. Keep live
native/Matrix/memory databases local to the body. Verify shared files as their
actual consumer, including parent-directory traversal and selected write grants.

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
