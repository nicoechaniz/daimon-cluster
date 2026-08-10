# Production resource fences

Status: implemented candidate for issue #64; not yet enabled on a live host.

## Authority and boundary

Cluster is the only writer and signer of current resource-fence truth. Matrix
receives a closed `resource-fence/v2` record through the unchanged
`ResourceFenceStore.verify_current()` interface and converts it to Matrix's
own evidence contract. Matrix never receives the Cluster signing key.

`resource-fence/v1` JSON plus `FAKE:` signatures remains an offline fixture
format only. A production store never reads those files during acquire,
renew, release or verification.

## Holder authorization

Every mutation carries a short-lived
`resource-fence-holder-authorization/v1` signed by the holder's Ed25519 key.
The signed payload binds all of:

- operation (`acquire`, `renew` or `release`);
- body, embodiment and current incarnation;
- exact resource and holder key id/public key;
- expected high-water epoch and proof;
- issue/expiry times and a non-empty nonce.

Cluster verifies the authorization and registered holder key inside the same
transaction that advances the position. Replayed or concurrent credentials
therefore become stale after one winner commits. Holder-key revocation
atomically replaces every position held by that key with an owner-signed
revocation tombstone, then marks the key revoked; it can no longer mutate or
appear current.

## Transaction and crash model

`resource-fences.sqlite3` is owner-controlled (`0600`), WAL-backed and uses
`BEGIN IMMEDIATE` with `synchronous=FULL`. One transaction commits:

1. the new current record or release tombstone;
2. the monotonic resource high-water and proof;
3. the append-only signed event.

Readers use query-only connections. Expiry is an observation, never a delete;
release creates a signed tombstone at the next epoch. Garbage collection and
arbitrary byte restore are disabled, so restart, rollback or an expired V1
file cannot lower or revive a position.

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
booleans and migration state.

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
