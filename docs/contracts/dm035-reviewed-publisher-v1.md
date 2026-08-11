# DM-035 reviewed publisher host contract

Status: normative for Cluster H6.

## Authority and route

Matrix owns source events, deterministic rendering, explicit consent, human
review, target/predecessor choice, DM-035 claim, provider receipt and signed
canonical `publication.receipted` event. Cluster owns the physical production
fence and fixed provider process. Wiki, compaii-state and HMK remain external
effect stores, never Matrix identity/history authority.

There is one outer route and no wildcard:

```text
adapter            cluster-dm035-publisher/v1
work kind          publication
resource namespace publication
```

The concrete resource is constructor-fixed per embodiment. One exact
four-method DM-031 curator capability coordinates the outer item; it gains no
review, identity, signing, fence-mutation or generic tool authority.

## Exact dependency line

At Matrix pin `f0181f7117859f3f9cc4afc7dfbdaf9b06e74754`, Cluster verifies
the complete DM-035 policy/profile/proposal/review/request/claim/acceptance and
provider request/plan/receipt schema line. It also verifies provider commit
`cf56e9de703f68f44b85fdf21f503d55a5557984`, adapter
`dm:adapter:v0:OnDIAMjSu2T_8EqLG_wxxygVXCPGXaTJsA41-IMcpSo`, API `1.0.0`,
policy hash `800929a4d56687ca224c5df767ab05c4c259acc75904530848683a92e2484b88`
and HMK `f10fd5c3089c0962920314c97e14bc024feffa7a`. Any drift disables the
boundary; there is no compatibility or receipt fallback.

## Payload-free current intent

`dm.cluster.dm035-execution-intent/v1` is derived only after Matrix validates
the complete signed DM-035 request and target claim. It contains no final bytes,
logical path, deployment path, URL, repository, command, template, database
handle, credential or provider configuration. It binds:

- request event ID/hash, request ID and exact inner claim ID/hash/generation;
- target kind plus a canonical target hash and fixed outer resource;
- publish/withdraw/rollback, exact approved final-byte SHA-256 and prior target
  SHA-256 when a predecessor exists;
- source-set and source-checkpoint hashes with explicit consent;
- independent reviewer decision/key/principal/hash/expiry;
- exact predecessor acceptance/provider receipt IDs and hashes;
- Matrix profile/policy hashes and current outer actor.

The outer preview hash is exactly the deterministic final-byte hash approved by
the independent reviewer. The outer execution authority remains automated
`daimon`: a prior human signature does not let the worker impersonate a human.
Changed bytes, target, source/checkpoint, consent, review, predecessor, claim,
profile, policy or actor changes the current intent and refuses effect/replay.

## Execution and recovery

The executor requires DM-031 resource-fence coordination and compares the claim
position with fresh production evidence before DM-035, after DM-035 and before
return. Holder/incarnation/epoch/proof/expiry drift is a refusal.

Cluster then calls only `PublicationCoordinator.execute(claim_id=...)`. The
Matrix library re-resolves sources and final bytes, verifies secret scan,
review, current predecessor and inner lease, runs the closed provider plan and
apply, reconciles current effect truth, and writes one signed acceptance. Its
owner-only journal plus the provider transaction journal already cover every
crash stage. Cluster intentionally adds no second mutable outer journal:

- before acceptance, exact retry resumes the same DM-035 plan/effect;
- after acceptance or response loss, Matrix discovers the one canonical event
  and freshly reconciles it;
- the content-derived outer effect UUID/timestamps/receipt reconstruct
  byte-identically from that acceptance.

This keeps canonical history in Matrix and avoids two competing commit records.

## Provider least authority

The provider and HMK checkouts must be clean exact commits, owner-owned and not
group/other writable. Wiki is a fixed owner-controlled root; projection,
runtime and HMK bases are separate owner-only roots. Overlap is rejected by the
pinned provider.

The provider executes outside the Matrix host in a minimal-env child process,
umask 077, with bounded stdin/stdout/stderr/time. It supports exactly
`manifest`, `plan`, `acquire`, `apply`, `reconcile`, and `release`. The operation
is an allowlist value; the document is canonical data; executable and host
roots are constructor-fixed. The provider process receives no Matrix ledger,
signing key, capability, recovery seed or ambient secret environment.

## Receipt and observer

The closed Cluster postcondition binds canonical target hash, operation,
sequence/outcome, before/after target hashes, source/checkpoint hashes, review
decision hash, signed acceptance event ID/hash, provider receipt ID/hash and a
hash of the complete provider effect set. It exposes no effect handles or
deployment layout.

On cached replay the route re-enters exact `PublicationCoordinator.execute`,
which can only return an existing canonical acceptance after provider
reconciliation. Cluster derives the postcondition again, reconstructs the
entire expected outer receipt, and returns current fence evidence. Changed
provider state, successor/tombstone head, target, receipt or observer outage
fails closed while the historical Matrix event/receipt remains immutable.

## Successor, tombstone and rollback

Successors, withdrawal tombstones and forward rollback are new independently
reviewed DM-035 requests naming the exact current predecessor. They advance
Matrix/provider sequence and never overwrite an unrelated target or erase
audit history. A historical outer replay after a successor is no longer current
effect truth and must not claim success.

Operational rollback disables the route/writer. After any accepted effect,
correction is a reviewed successor/tombstone/forward rollback through DM-035;
never force-push, delete canonical events/audit receipts, or restore an old
Wiki/state/HMK snapshot as authority.
