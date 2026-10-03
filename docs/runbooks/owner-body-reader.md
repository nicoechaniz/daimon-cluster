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
