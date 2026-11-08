# Children's host Alerts observation

Use the receiving capability-map `host-daimonmatrix` entry for current access;
its current role is lordoftheflies. The existing private Matrix network carries
a fresh host node. Its original Source node remains on ITACA. Configure actual
VPN addresses, pins and credential references privately.

## Receiving route

The existing ITACA Alerts core keeps its database, actors, delivery records and
receiving adapter. Add one purpose-bound host actor using the core's maintained
configuration contract. Select `publish`, `observe`, `status`, the exact producer
IDs and existing operator receiving scope. A host producer receives neither
incident-reading, acknowledgment nor delivery grants. Keep its token root-private
on the target. Do not reuse another being's producer credential.

Core ingress uses a restricted encrypted reverse link because the existing core
binds loopback. A fresh service key and independent listener belong to the new
`cluster-alerts-link` account. Bind that listener only to the selected Matrix VPN
address. Its public-key file and server host key are independent service assets.
Keep the service account password unusable (`*`), shell `nologin`, and the listener
public-key-only with `UsePAM no`. The latter avoids creating interactive PAM/motd
sessions for a forwarding service.

The qualified server permits only remote forwarding to loopback8796. Shell/TTY,
agent/X11/tunnel/direct forwarding and other listening ports are denied. The
client has a private `-F` configuration, independently verified server pin,
`ExitOnForwardFailure`, eight-second connect and15s/two-miss keepalive bounds.
Systemd bounds both endpoints to64MiB/10%CPU and16/32tasks. Client restarts are
limited to six per five minutes. The management SSH configuration and existing
administrative keys retain their previous bytes.

Qualify the actual listener: accepted status through the tunnel,403incident
read with the producer token, forced command refusal, forbidden reverse-port
refusal and actual direct-channel denial. A closed socket alone does not prove
why it closed. In the controlled SSH client, VERBOSE logging exposes the explicit
administratively-prohibited result; ordinary service logging stays ERROR. Retain
safe booleans and exit outcomes, without raw credential-bearing diagnostics.

Stop only `children-alerts-link.service` on the operator and, when appropriate,
`children-alerts-listener.service` on the new host. Keep producer journals and
pending delivery identities. Inspect retained outcomes before restoring that
same selection. No goal, provider or Matrix control follows from link recovery.

## Filesystem producer

Reuse the qualified `storage_monitor.py` and `client.py` from the existing
Alerts operator release. The initial source is Alerts8a7d669, selected on ITACA;
record exact script hashes in the receiving installation record. Stage only
these public files, then run the finite monitor under an immutable code path.
The private configuration selects the actual system, fast-pool and cold-disk
mounts, not guest home traversal. Missing mounts are unavailable observations.

The selected policy warns at82%used/inodes or<15GiB available and is critical at
90%or<7GiB, with3percentage-point/2GiB recovery margins. These are host/pool
thresholds, not small-guest filesystem defaults. Guest quota/memory/native
readiness require their corresponding scoped runtime observations.

The finite service has64MiB/10%CPU/eight tasks and a20second deadline. Its
existing storage monitor contract uses a10second inactive interval to keep the
core's30second observation freshness; this performs only statvfs and bounded
HTTP/SQLite operations. It creates no models, directory walks or cleanup. Keep
its owner-private journal and original binding. The outbox freezes uncertain
projections until exact acceptance, while the replaceable status row remains
bounded. Configure an independent external availability observer as well.

Actual initial installation: tunnel status200 and forbidden incident read403;
all three selected filesystems observed healthy; first observer update accepted,
outbox0; finite service exit0 and timer enabled. Durable fault/recovery delivery,
failed-link/missing-source checks, runtime/guest quota coverage, daily assessment
and bounded cleanup remain separate required qualification. An active timer is
not proof of those outcomes.
