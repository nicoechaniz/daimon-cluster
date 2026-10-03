# Owner-local Cluster body observations

The optional `clusterctl.owner_body_reader` process exposes one configured body
observation to one local UID. It delegates to the installed MatrixHostAdapter
and its authenticated production-fence verifier. It has no registration,
lifecycle, signer, custody, inbox, model or effect-execution endpoint. A missing
or stopped registry origin refuses; starting this reader does not establish
physical body admission.

The native owner CLI's historical direct reader and its exact source pins remain
unchanged. An external harness needs an explicitly admitted socket client which
checks the server UID and validates the returned closed snapshot against its
current signed Matrix binding. A generic JSON result or successful service start
is not that admission.

## Profile and ownership

A profile is an existing regular file owned by root or the reader UID, with no
group/other write permission. No symlink components are accepted. Its fields are
closed; duplicate keys and non-finite values refuse. An illustrative profile is:

```json
{
  "schema": "dm.cluster-owner-body-reader-profile/v1",
  "socket_path": "/run/daimon-cluster-body-reader-example/reader.sock",
  "socket_mode": "0666",
  "caller_uid": 1234,
  "origin": {
    "body_ref": "codex:example:compaii",
    "embodiment_id": "embodiment:11111111-1111-4111-8111-111111111111",
    "incarnation_id": "incarnation:22222222-2222-4222-8222-222222222222"
  }
}
```

`0600` supports a same-owner client. `0666` explicitly admits a connection from
another UID, while SO_PEERCRED rejects every caller except the configured UID
before reading its request. The client must independently verify the server UID;
no bearer credential is sent. A parent directory must be root/reader-owned and
unwritable by other accounts. The unit template creates a service-owned0755
runtime directory outside the private Cluster state root; it does not change
registry ownership, supplementary groups or existing state-root access.

The origin selector is operator configuration, not being membership authority.
Matrix still verifies its signed current binding, exact origin, observation time
and native launch controls. A new incarnation requires an explicitly updated
profile consistent with the supported Matrix/Cluster lifecycle.

## Wire and process boundary

Each connection carries one four-byte network-order unsigned frame length and
one UTF-8 JSON object, bounded to65536bytes. Requests have exactly `schema`,
`body_ref`, `embodiment_id`, `incarnation_id`, and `evaluated_at_ms`; schema is
`dm.cluster-owner-body-read/v1`. The evaluation instant is Matrix's integer
instant. Unknown fields, bool/negative/oversized instants, duplicate keys,
oversized frames, unlisted origins and invalid snapshots refuse. Success has
exactly `ok:true` and `snapshot`; refusal has `ok:false` and one fixed error code.
No diagnostic details, private paths, registry dump or keys cross the socket.

The standalone entry point first checks the existing host's genuine pinned
Matrix dependency. It never imports ambient fixture fences or creates a missing
production fence database. Native verifier transactions are query-only; its
existing startup permission checks may apply0600 to DB/WAL/SHM and SQLite may
manage WAL/SHM files. The unit therefore cannot mount the entire state root
read-only. This behavior belongs in the approved preflight; no registry rows,
fence positions, clock high-waters or signed history are modified by queries.

An occupied socket, including a stale socket, refuses startup and is not removed.
Shutdown unlinks only the inode published by that reader; a replacement file or
socket remains intact. A client can delay one request for at most the transport
read deadline of five seconds shared by header and payload; incoming bytes do
not renew it. Response writes have a separate five-second bound. Native SQLite
operations have their own existing bounded waits; the unit allows thirty seconds
for cooperative shutdown across these stages.
No automatic retry, polling, timers or independent events are installed.

## Deployment and evidence

Use `configs/owner-body-reader@.service.example` only as an uninstalled template.
Before any live activation, freeze the immutable release/dependency, exact
profile/socket/caller/server owners, current signed origin, existing production
fence readiness, lifecycle registration, startup/status probes and rollback.
Obtain that plan's explicit approval. Preserve the existing fleet host and
original Cluster body; neither this card nor a fixture authorizes a restart or
new body.

Qualify the server and owner CLI together through real sockets and the current
production backend. Record whether the crossing used different actual UIDs.
Same-UID fixtures and rejected UID expectations do not prove deployed crossing.
Verify missing/stopped/substituted origins, source/profile/socket drift, refusal
before native spawn, clean shutdown and unchanged registry/fence tables.

## Existing owner-hosted process admission (opt-in v2)

The closed `dm.cluster-owner-body-reader-profile/v2` keeps the v1 fields and
adds `process`, containing exactly integer `uid`, `pid`, `start_ticks` and
canonical UUID `boot_id`. These are Linux kernel metadata, not Matrix IDs.
The profile must remain root/reader-owned and nonwritable by other users.
An approved preflight must bind the process to the selected owner service and
its actual runtime listener (unit MainPID equals socket SO_PEERCRED PID/UID),
record the kernel start ticks and current boot ID, and preserve the current
signed Matrix origin. A process name or PID by itself is insufficient.
No runtime path, custody, capability key or private payload goes in this profile.

Explicit enrollment uses the coherent pinned release:

```sh
venv/bin/python -E -s -m clusterctl.owner_runtime \
  --state-root /var/lib/daimon-cluster \
  --profile /etc/daimon-cluster/body-readers/example.json
```

This command changes the native registry and requires live approval. It checks
physical presence before atomically enrolling the supplied existing origin; it
mints no IDs and preserves the fleet. Exact active replay is a no-op; conflicting
body/embodiment/incarnation, retired/ended records and reused incarnation IDs
refuse. If the reply or final process observation is lost after commit, accepted
history stays accepted; an explicit exact retry rechecks liveness without adding
a record. Do not rewind this history as a rollback.

The existing reader unit accepts this v2 profile. Each query opens a kernel
pidfd and checks owner, boot and start ticks before and after the native registry/
fence observation. Dead/zombie/reused or inaccessible processes refuse; missing
Linux pidfd support refuses. No process signals, agent wakeups, polling loop,
runtime requests or automatic registry mutations are installed. Reads preserve
registry and native fence rows. A v1 profile retains its prior behavior and does
not claim physical process validation.

After process loss the saved logical incarnation is not silently ended or
replaced: observations become unavailable. An explicitly approved new profile
can rebind a restarted process to the same still-active native origin; Matrix
must separately prove that the origin and authority are still current. An
incarnation ended by an explicit native stop cannot be reopened. A future
root-authorized incarnation needs its normal lifecycle authorization.

Every registry writer must first adopt the coherent shared-lock release under
the approved writer cutoff. An older writer ignores the lock. The enrollment
command and reader neither stop/start the owner's service nor authorize Codex
launch, capability renewal, Matrix events, memory adoption or model inference.
Retain a recovery plan for accepted registration; remove a reader/profile only
under its approved cutoff, and preserve other bodies and resource fences.
