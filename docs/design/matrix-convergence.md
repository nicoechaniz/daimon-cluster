# Matrix integration contract

Daimon Matrix supplies the canonical ontology and `dm.we.v1` bytes. Cluster
supplies bodies, embodiments, incarnations, resource fences, lifecycle audit,
and the hosted Weave process. Tribe Bridge supplies authenticated encrypted
delivery.

The first release deliberately has no Matrix daemon. An administrator installs
the same `being-manifest/v1` hash on every participating host. This is
operational trust, not identity proof. A future Matrix root attaches the
provisional history only through an explicit signed binding artifact.

## Cluster obligations

- New body means new embodiment; restart means new incarnation.
- Multiple embodiments for one being may run.
- Presence never excludes another embodiment.
- Fences are scoped to concrete resources and reject stale generations.
- Lifecycle and fence results are auditable and secret-free.
- Weave has an independent ledger and no direct writes into provider stores.
- HMK and configuration changes happen through idempotent projection adapters.

## Matrix obligations

- Preserve `/me` as the current embodiment viewpoint and `/we` as same-being
  plurality.
- Define origin-retaining event, head, delta, decision, and receipt schemas.
- Later provide root custody, recovery, body-bound credentials, revocation,
  and provisional-history binding without restoring single-body exclusion.

## Tribe obligations

- Carry typed Weave payloads over direct encrypted audiences.
- Authenticate each origin principal and preserve exact bytes and receipts.
- Keep founded-tribe membership separate from same-being membership.
- Never interpret receive as adoption or transport directory as Matrix truth.
