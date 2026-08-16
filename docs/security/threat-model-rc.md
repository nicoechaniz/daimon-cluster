# Release-candidate threat model

Status: normative software boundary for the V0 release candidate.
Last reviewed locally: 2026-08-16.

This model assumes mutually untrusted runtime content, snapshots, transport
messages and caller input. It does not assume an existing host or deployment.
Tests use temporary owner-only state or purpose-built disposable containers.

## Identity and multiplicity

A being root may authorize multiple legitimate `embodiment_id` values. Each
embodiment may advance through ordered incarnations. Shared launch admission is
keyed by `(being_ref, embodiment_id)` and also binds the exact credential,
activation, incarnation, holder and ephemeral session. Therefore:

- two distinct authorized embodiments of one being may run;
- two launches presenting the same embodiment authority may not both win; and
- a copied state directory, holder public metadata or stale session cannot
  renew or adopt the winner's lease.

This is a cooperative authority guarantee: every production-shaped start must
use the shared admission authority. Local file locks are only process hygiene
and are never presented as cross-host fencing.

## Trust boundaries

| Boundary | Authority and required evidence |
|---|---|
| Being/recovery/embodiment/incarnation | Matrix root-authorized signed history |
| Shared launch admission | Cluster authority-signed CAS receipt plus fresh holder proof |
| Concrete resource mutation | Enrolled holder authorization, trusted authority time and exact prepared successor |
| Runtime start | Installed Matrix activation, matching registry row, current shared admission and authenticated READY |
| Snapshot/recovery transfer | Closed filenames, exact sizes/hashes, descriptor-stable staging and signed recovery history |
| Host status/curator | Separate exact-method capabilities installed outside portable snapshots |
| Human mutation approval | Server-verified one-shot approval bound to actor, operation, target and current state |
| Tribe transport | Transport ACK/deduplication only; never Matrix semantic authority |

## Primary attacks and controls

### Duplicate launch and stale-holder takeover

The authority owns time and bounds lease/auth TTL. Holder enrollment is an
explicit registrar transaction; first acquire is not TOFU. Acquire/renew/
release use exact CAS positions and authority-signed receipts. Release recovery
requires a one-use challenge and fresh holder private-key proof. A monotonic
watchdog terminates the child before its conservative local deadline if renew
cannot complete.

Residual risk: bypassing the admission-aware start path would bypass this
cooperative guarantee. Production configuration must therefore expose no
generic Matrix start fallback; conformance tests enforce fail-closed wiring.

### Crash and response loss

Mutation preparation is serializable and binds operation, resource, holder,
predecessor, successor, TTL and authorization reference. Exact replay adopts
only the already committed successor. Journals persist intent and compensation
state across process death. Tests crash before/after CAS, registry mutation,
spawn, READY, snapshot staging and restore.

### Snapshot substitution and credential exfiltration

Source files are opened with no-follow descriptors, bounded, hashed while read
and checked for stable inode/device/size. V7 export verifies the active
root-authorized origin plus the signed exact twelve-profile binding and always
excludes root, operator and host client trees. Runtime filenames are selected
by exact bundle semantics rather than broad suffixes. Source/destination parent
chains reject symlinks; directory publication is descriptor-relative and
atomic no-replace.
Recovery accepts exactly `runtime.json` plus `ledger.sqlite`; it never transfers
custody, writable derived databases or journals. A second descriptor-stable
stage rechecks the manifest before target mutation.

### Capability widening

Matrix signs a binding over the exact ten operator and two host profiles. Host
status has five read methods; host curator has four curator methods. Cluster
installs those in distinct owner-only roots and rejects broader or mismatched
clients. Copying and publicly relabelling a descriptor/config/key from another
runtime cannot recreate the Matrix signature.

### Hostile caller or stolen service token

Routes enforce operation-specific scopes. Owner-scoped access denies missing or
mismatched ownership. Human attendance is not a caller-provided boolean: a
separate one-shot approval is bound to the exact request and state. Every
mutation is journaled and audited.

## Explicit non-guarantees

- Local/container tests do not prove independent physical custody or physical
  singleton behavior.
- The authority service is an availability dependency; outage fails closed and
  may stop a body.
- Root/recovery holder independence is a property of a future live ceremony,
  not of synthetic fixtures.
- No software result authorizes a host, SSH/access change, production cutover,
  external contact or real key rotation.

## Required RC evidence

- concurrent independent-state launch race: exactly one READY;
- stale/revoked/wrong holder and public-only recovery attempts rejected;
- clock skew, overlong TTL, replay and crash/restart matrix;
- zero adapter/spec effects after late revocation;
- V7 incomplete/relabelled/invalidly signed profile snapshot rejected before
  destination, with required custody/ledger bytes retained regardless of
  filename suffix;
- client/custody bytes absent from recovery transfer;
- clean full suite with resource leaks fatal; and
- network-disabled recovery/rebirth plus encrypted backup/offline restore.

The exact receipt is `docs/verification/rc-recovery-rebirth-2026-08-16.md`.
