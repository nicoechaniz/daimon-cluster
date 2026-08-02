# Embodiment lifecycle and Weave runtime

Status: normative Cluster design.

Cluster realizes bodies. A body creation gets a stable `body_ref` and
`embodiment_id`; each start gets a fresh `incarnation_id`. More than one
embodiment in the same administrator-installed being manifest may run at the
same time. Cluster does not prove that they are one being.

## Registry

`state_dir/embodiments.json` records each body, embodiment, current state, and
complete incarnation intervals. Restart closes the prior interval and opens a
new one. Cloning state creates a new body and embodiment; relocating the same
body preserves the embodiment and opens another incarnation.

Lifecycle records are exposed to Weave and the dashboard. Presence is routing
and observability metadata, never an exclusivity fence.

## Resource fences

`resource-fence/v1` records live in the existing guarded registry directory.
Each record names one exact `resource_ref`, holder embodiment, signing key,
generation, acquisition time, TTL, and signature. CAS rejects another holder
only for that resource. Different embodiments and different resources do not
conflict merely because they share a being.

Park, snapshot, wake, and transfer retain their quiesce, integrity, rollback,
and audit guarantees. A body-volume transfer renews the fence for that volume;
it does not establish or move being identity.

## Weave

The `weave` package is an independent service boundary hosted in this repo. It
owns a per-embodiment SQLite ledger, origin chains, heads/deltas, local
decisions, projections, and `/we` fan-out. It never writes HMK SQLite directly
and never shares its database with another embodiment.

It loads a canonical `being-manifest/v1`. Peers must present the same
`being_ref` and manifest hash. Tribe authenticates/encrypts the transport;
Weave validates event origin and meaning. Pull adds `known` events only.

Memory/configuration adapters expose preview and receipt APIs. Secret values
are rejected. Identity/access/external effects require a human confirmation;
resource-writing effects additionally bind the current resource fence.

## Future Matrix boundary

Matrix will eventually replace the provisional manifest as cryptographic
being authority and issue body-bound embodiment credentials. Cluster will
continue to own bodies and resource fences. Tribe keys remain transport keys.

