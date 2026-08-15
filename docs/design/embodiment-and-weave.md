# Embodiment lifecycle and Weave runtime

Status: normative Cluster design.

Cluster realizes bodies. A body creation gets a stable `body_ref` and
`embodiment_id`; each start gets a fresh `incarnation_id`. More than one
embodiment in the same administrator-installed being manifest may run at the
same time. Cluster does not prove that they are one being.

## Registry

`state_dir/embodiments.json` records each body, embodiment, current state, and
complete incarnation intervals. Restart closes the prior interval and opens a
new one only when Matrix has a signed authority-epoch successor. Cloning state
creates a new body and embodiment; relocating the same body preserves the
embodiment and opens another incarnation.

Lifecycle records are exposed to Matrix through the closed
`dm.cluster-body-snapshot/v1` callback and to operators through a redacted
dashboard. Presence is routing and observability metadata, never an
exclusivity fence. Matrix owns the evaluation instant and supplies it to the
Cluster callback, so an honest read cannot become “future” across a clock
tick.

`GET /v1/weave/status` calls the owner-local authenticated Matrix client and
reports Matrix-process availability, owner-local ledger integrity/queue state,
and peer reachability/difference state separately. A clean local queue never
means a peer is reachable or caught up. A row can therefore say local-clean +
peer-offline, or local-clean + peer-available + known-differences, without
collapsing either into “healthy”. Per-embodiment process failures are explicit
and do not erase observations from other embodiments.

Raw redacted differences are available only from the bounded snapshot endpoint
`GET /v1/weave/differences?embodiment_id=...`. Both status endpoints omit
payloads, routes, endpoints, requests, secrets and private paths. The old
Cluster `weave/` runtime is not an alternate status source. The complete read
contract is `docs/contracts/read-models-v2.md`.

## Resource fences

`resource-fence/v1` records live in the existing guarded registry directory.
Each record names one exact `resource_ref`, holder embodiment, signing key,
generation, acquisition time, TTL, and signature. CAS rejects another holder
only for that resource. Different embodiments and different resources do not
conflict merely because they share a being.

Park, snapshot, wake, and transfer retain their quiesce, integrity, rollback,
and audit guarantees. A body-volume transfer renews the fence for that volume;
it does not establish or move being identity.

## Matrix-hosted Weave

The exact installed `daimon-matrix` artifact owns the per-embodiment SQLite
ledger, origin/incarnation chains, heads/deltas, decisions, projections,
authority epochs and `/we` fan-out. Each embodiment has a distinct owner-only
root, socket, signing authority and capability. Cluster neither vendors nor
reinterprets those bytes.

Peers prove a common root-authorized being and accepted manifest history.
Tribe Bridge authenticates/encrypts transport; Matrix validates event origin
and meaning. Import adds known signed history only. Adoption needs a local
decision event and projection receipt.

Memory/configuration adapters expose preview and receipt APIs. Secret values
are rejected. Identity/access/external effects require the appropriate local
authority; resource-writing effects bind a current Cluster resource-fence
position and are replayed only while observed effect truth still agrees.

## Portability and custody

Cluster snapshots only a quiesced Matrix root, hashes every included regular
file, and excludes sockets, locks, WAL temporaries and host-local clusterd
client material. Restore targets must be new owner-only directories. The
encrypted Matrix custody and canonical ledger travel; the least-authority
clusterd capability is reprovisioned on the destination host. Root/recovery
seeds never enter Cluster. Tribe keys remain transport keys, not being
identity.
