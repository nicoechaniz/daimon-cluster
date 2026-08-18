# V0 RC recovery/rebirth qualification

Date: 2026-08-18. Software-only candidate; not deployed.

## Exact functional boundary

- Matrix functional merge: `09414d6edd9586f539be8272c4979d0b36c86b87`,
  tree `d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`; merged closeout and exact
  installed pin: `7266de8551ae861f3773c587bf907cfcddde6ffd`, tree
  `d1ff7a6fc6b1351f67fd13171dcee51242fc9804`.
- Cluster functional merge: `820e3792a227b1848681a3421b113e8822c8d08a`,
  tree `4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8`; independent exact-hash
  review and main CI passed.
- Tribe merged main: `294e1194db6cd60d9349a2d43938475bbd1c8c20`,
  tree `bcba9989a38519df87ecbb6c87a33a2f9740b85d`; qualified material source
  `8ce2c9d4c6b3e4e94108600d4170f169ced26303`, tree
  `0431882544ebd72bfbfbb343677b2557ea4fdbce`. Reviewed head
  `e81c5da0b96d0ac29f7a3bdeacb1f0e7c860ec3c` has the same final tree and
  passed 148 tests with zero failures on Python 3.10–3.13.

The final three-repository manifest records later documentation/pin-only heads
and archive hashes. This successor installs Matrix from the full merged commit
named above and verifies that exact `direct_url.json` value.

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
writable database is copied. The distinct
`dm.cluster-matrix-recovery-snapshot/v1` derivative contains exactly the bundle
named by the snapshot and the canonical ledger named by that signed bundle. In
the disposable qualification fixture those names are:

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

V7 snapshot export always excludes root, operator and host client paths,
requires the complete canonical twelve-profile table and verifies its active
root-authorized Ed25519 binding. Empty, incomplete, duplicated, relabelled,
invalidly signed, unsafe-path and changed-source cases fail before a snapshot
destination exists. Required ledger/custody bytes remain present even when a
legal filename resembles a transient suffix. Linked source/destination paths
and concurrent destination claims fail without replacement. Raw client keys
are absent from the payload.

## Clean gates

```text
Matrix source-isolated suite: 640 passed, 22 declared skips
Matrix Python CI: 3.11, 3.12, 3.13, 3.14 passed
Matrix package/conformance/Hermes contract: passed
Cluster offline-qualifier/freezer suite with resource/unraisable warnings fatal: 622 passed, 4 skipped
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

Matrix closeout artifacts are byte-identical across two isolated builds:
wheel
`11ef77b2b4c743cfa25d6652e9cad3594e41223cb73f558d5ead8f47bd43609d`
and sdist
`b23d66004039dc9d454c1bf4382b87a381c538fe8194a3c262440425ffa6de69`.
The final offline qualification installs Matrix through an exact Git bundle so
`direct_url.json` retains VCS commit provenance; a plain wheel alone cannot
satisfy Cluster's exact-commit gate.

Independent reviews passed Matrix capability/custody/runtime metadata, the
Matrix documentation successor and the Cluster admission/fence code. This
prepared Cluster pin/documentation successor must still receive its own
exact-hash review and CI before merge.

## Explicit limits

- No host, SSH/access path, service, production state or real key was touched.
- No local test proves physical singleton or independent live custody.
- No participant was contacted and no cross-being canary ran.
- Physical rehearsal, real custody, Tribe operations, publication and cutover
  remain separate human gates described in `RESUME.md`.
