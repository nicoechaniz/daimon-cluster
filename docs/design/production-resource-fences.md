# Production resource fences

Status: production SQLite/Ed25519 admission is deployed. The bounded historical
event-retirement successor described below is a candidate, not yet selected live.

## Authority and boundary

Cluster is the only writer and signer of current resource-fence truth. Matrix
receives a closed `resource-fence/v2` record through the unchanged
`ResourceFenceStore.verify_current()` interface and converts it to Matrix's
own evidence contract. The hosted Matrix process opens a query-only
`production_verifier` backed solely by the database's public-key registry; it
cannot sign or rotate and never receives the Cluster private key.

`resource-fence/v1` JSON plus `FAKE:` signatures remains an offline fixture
format only. A production store never reads those files during acquire,
renew, release or verification.

## Holder authorization

Every mutation carries a short-lived
`resource-fence-holder-authorization/v2` signed by the holder's Ed25519 key.
V2 binds the requested fence TTL and the complete predecessor position in
addition to the holder, operation, resource and nonce; V1 is not accepted.
The signed payload binds all of:

- operation (`acquire`, `renew` or `release`);
- body, embodiment and current incarnation;
- exact resource and holder key id/public key;
- expected high-water epoch, proof and current/tombstone state;
- requested fence TTL (`null` only for release);
- issue/expiry times and a non-empty nonce.

Cluster verifies the authorization and registered holder key inside the same
transaction that advances the position. Replayed or concurrent credentials
therefore become stale after one winner commits. Holder-key revocation
atomically replaces every position held by that key with an owner-signed
revocation tombstone, then marks the key revoked; it can no longer mutate or
appear current.

Release recovery may request an authority-signed receipt for the verified
high-water tombstone only after a two-step proof of possession. The authority
binds a one-use challenge to the requesting session, exact predecessor and
successor, resource, release operation and `authorization_ref`, then verifies a
fresh signature by the enrolled holder key before consuming the challenge and
returning evidence. Public-only verifiers, session substitution and proof
replay cannot adopt the receipt; the observation cannot mutate or resurrect the
resource.

## Transaction and crash model

`resource-fences.sqlite3` is owner-controlled (`0600`), WAL-backed and uses
`BEGIN IMMEDIATE` with `synchronous=FULL`. One transaction commits:

1. the new current record or release tombstone;
2. the monotonic resource high-water and proof;
3. the signed event and any bounded historical retirement checkpoint.

Readers use query-only connections. Expiry is an observation, never a delete;
release creates a signed tombstone at the next epoch. Positions, tombstones,
public key history and the clock high-water are never retired. Arbitrary byte
restore stays disabled, so retirement cannot lower or revive a position.

Ordinary commits retain the latest256 events per resource. At most32 older
events are authenticated and retired in one transaction, alongside a cumulative
signed count/through-epoch/hash checkpoint. A legacy backlog drains in bounded
batches; it is not falsely reported as already within the new steady-state cap.
The checkpoint commits the actual retired bytes, but cannot reconstruct them and
is not an authority to restore a fence. Historical signatures may authenticate
retired-key evidence; current-position verification still rejects revoked keys.
Any failed batch rolls back its checkpoint, event removal and position update.

The owning `clusterctl.admission --retire-history` mode reuses its existing
state/signing/registrar arguments, with no socket/listener and no service restart.
`--retirement-seconds` selects1..60 seconds of batch work (default30). It prints
one bounded receipt with committed retired count and `complete`; incomplete or
failed work returns nonzero and can resume from the retained checkpoint using
the same command. Initial authority/configuration validation precedes that batch
budget. Maintenance lock waits are capped at100ms and SQLite scans observe the
batch deadline. No timer, lease extension, new holder or resource is created.
SQLite reuses retired pages; the command does not VACUUM or promise a smaller
database file. No raw SQL cleanup, history copy or new recurring process is needed.

SQLite serializes the short commit section. Contenders for one resource see
exactly one winner; operations on different resources do not conflict at the
resource position layer.

## Signing custody, rotation and revocation

`Ed25519Signer` accepts only a regular private key owned by the current uid
with no group/other permission bits. The caller supplies an explicit key id.
The database retains public verification keys and their `active`, `retired`
or `revoked` state; it never stores private material or exposes a key path.

Rotation first registers the replacement as active and retires the previous
key. Existing records remain verifiable while the previous key is retired.
Revocation is fail-closed. A safe rotation must therefore advance every live
record under the replacement before revoking a previous key needed by that
record.

`support_status()` reports only backend/schema, CAS mode, key id, readiness
booleans and migration state. A verifier-only process reports signer readiness
false while remaining production-ready for verification.

## Offline V1 migration

Migration requires `offline=True`, an empty production database and a
quiesced writer set. Malformed or unexpired V1 records refuse the migration.
For each expired fixture/high-water, Cluster writes a new owner-signed
`migration-retired` tombstone at `old_high_water + 1`. It does not authenticate
or promote the `FAKE:` record and it never imports an active holder.

## Rollback

Quiesce mutations and roll back Cluster code and database as one pair. Keep
the database, WAL and signing-key registry. Never copy out private signing
material, delete tombstones, restore an older database, or point a live host
back at the V1 JSON directory to recover an epoch.
