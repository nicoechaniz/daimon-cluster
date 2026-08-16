# V0 RC recovery/rebirth qualification

Date: 2026-08-16. Software-only candidate; not deployed.

## Exact functional boundary

- Matrix main merge: `09414d6edd9586f539be8272c4979d0b36c86b87`,
  tree `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`.
- Cluster code boundary: `93230a890ffad78aa1d10af2b68a33a45ff9845c`,
  tree `598f502df42408d3f6e0dc788e765461fb54081b`.
- Tribe reviewed PR head:
  `418900a9d3732689d6a309336c467623637fe8d4`, tree
  `d5b50379b1d9abe781ef92d0a50390559eed17c1`; content-addressed source boundary
  `cd54865733c0b0200924dcd39213b7fcd7eb12ec`, tree
  `7052ca5672fb56a14b826382f468fb38e19c50f0`.

The final three-repository manifest records later documentation/pin-only heads
and archive hashes. Cluster installs Matrix from its full merged commit and
verifies that exact `direct_url.json` value.

## Guarantees exercised

### Shared admission and resource fencing

Two independent state directories racing one embodiment authority allow
exactly one process to reach READY. Admission binds being, embodiment,
credential, activation, incarnation, holder and an ephemeral session. Trusted
authority time, bounded TTL, explicit enrollment and exact CAS prevent future
clock takeover, TOFU enrollment and stale renewal. Launcher death, authority
outage and lost responses fail closed before the conservative local deadline.

Prepared resource mutations bind operation, resource, predecessor, successor,
TTL, holder and authorization reference. Release recovery uses a one-use
challenge and fresh private-holder proof; public-only metadata, substituted
sessions and altered requests cannot adopt the tombstone.

### Separated recovery and fresh embodiment

Matrix genesis/recovery holders each retain one key in one encrypted store and
emit partial signed artifacts. The aggregator has no holder keys. Threshold
shortfall, duplicate/hostile shares, expiry, revocation, divergent heads and
crash-at-publication retries are covered.

The target gets a new root-authorized embodiment credential, incarnation,
signing/capability material and writable stores. No predecessor custody or
writable database is copied. The recovery derivative contains exactly:

```text
ledger.sqlite
runtime.json
```

Cluster stages those bytes from stable no-follow descriptors, rechecks exact
size/hash and journals restore separately from installation. Wrong-password
retry, terminal replay, rollback, second-state disaster rebuild, old-event
continuity and fresh-event authorship pass.

### Capability and snapshot boundary

Matrix requires ten disjoint operator profiles plus separate host `status`
(five methods) and host `curator` (four methods). One embodiment signature
covers all twelve exact rows. Cluster installs host clients outside the runtime
snapshot.

V7 snapshot export always excludes root, operator and host client paths and
requires the complete canonical twelve-profile table. Empty, incomplete,
duplicated, relabelled, unsafe-path and changed-source cases fail before a
snapshot destination exists. Raw client keys are absent from the payload.

## Clean gates

```text
Matrix source-isolated suite: 640 passed, 22 declared skips
Matrix Python CI: 3.11, 3.12, 3.13, 3.14 passed
Matrix package/conformance/Hermes contract: passed
Cluster suite with resource/unraisable warnings fatal: 574 passed, 4 skipped
Cluster workflow lint/type/compile: passed
Disposable no-network recovery/rebirth: 1 passed
Disposable encrypted export/offline check/restore: 1 passed
```

The recovery container image is built from a full verified Git bundle of the
exact Matrix commit. Every role has a read-only root, no network, no Linux
capabilities and only explicit mounts. The fixture bootstrap and centralized
recovery helper are named `synthetic`; their staging is destroyed before the
separated source/offline-root/target roles run. This proves filesystem/process
isolation, not independent physical custody.

The backup/export test creates a real encrypted restic repository, permits only
read-only pull, rejects shell/TTY/forwarding/upload/path escape, preserves an
independent synthetic admin login through exporter revocation/deletion, checks
the repository and restores it in a second network-disabled container.

## Reproducibility and review

Matrix merge-tree artifacts are byte-identical across two offline builds:
wheel
`a8433cb007b46d45593895d0e459828a7281f09eb89cb85f558f8eabc9bc5e83`
and sdist
`f1fa00e3c5d18cb7ecce44ae656938ff35daeedb22e713cdc53b916208a6befe`.
Cluster installed the merge commit from Git and reproduced the same wheel hash.

Independent reviews passed Matrix capability/custody/runtime metadata and the
Cluster admission/fence code. The final Cluster pin/documentation successor
must receive its own exact-hash review and CI before merge.

## Explicit limits

- No host, SSH/access path, service, production state or real key was touched.
- No local test proves physical singleton or independent live custody.
- No participant was contacted and no cross-being canary ran.
- Physical rehearsal, real custody, Tribe operations, publication and cutover
  remain separate human gates described in `RESUME.md`.
