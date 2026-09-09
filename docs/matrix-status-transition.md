# Owner-local external Matrix status transition

**Source implementation, not deployment approval or installed-pair qualification.**
This helper is for an existing continuing runtime, not rebirth, enrollment,
application configuration, fleet maintenance or fence-authority provisioning.
It changes only an existing external status directory and its new private
transaction directory. It does not modify runtime custody, stores, registries,
external source checkpoints, services, pins or process state.

## Authority and operating prerequisites

- The owner must continuously stop **and externally fence every consumer and
  writer**, including clusterd, runtime launchers, auto-restarts, sidecar writers
  and custody/store writers, throughout runtime upgrade, sidecar transition and
  any reverse transition. `--externally-quiesced` is an explicit owner assertion;
  neither it nor the advisory locks enforces process fencing. Every success is
  `stopped-*`, never readiness or permission to start services.
- Use a separately reviewed, immutable Matrix/Cluster installation. This module
  uses actual Matrix canonical/crypto APIs and the existing upgrade helpers; it
  does not call, patch or suppress the host's `_matrix_api()` provenance guard.
  Parent-run installed-wheel/pin and composed-host qualification is separate.
  The current Cluster dependency pin is intentionally unchanged by this work.
- Obtain owner-reviewed exact request and receipt SHA-256 pins independently.
  Receipts are canonical owner-local records, **not signed authorization tokens**.
  The external pin binds the actual publication receipt, which binds the forward
  ready record, exact runtime inventory, checkpoint and source path. Runtime
  authority is independently checked through the real control chain,
  root-authorized credential/incarnation and Ed25519 capability-set binding.
  Deriving a pin from arbitrary local bytes is not review or owner approval.
- All paths must be absolute, without `..` or symlink components, owner-controlled
  and private. Runtime and upgrade transaction are siblings. The new sidecar
  transaction is a sibling of the existing `STATE/matrix-clients/HASH` directory;
  `HASH` must be the actual `matrix_client_root` hash for the expected embodiment.
  Runtime/upgrade and external sidecar/transaction trees must not overlap.
- Private files are owner-only, regular, single-link and bounded by the existing
  Matrix snapshot helper. SQLite WAL/SHM/journal files, special files and unsafe
  metadata refuse. Do not chmod, delete or repair existing stores to pass a check.
- The existing runtime daemon lock must already exist. Runtime parent/daemon and
  external parent locks serialize cooperating owner tools. Content CAS and the
  sidecar parent device/inode binding detect changes and parent substitution.
  This is not protection against a malicious root or same-UID writer ignoring
  the required external fence; it is not a kernel filesystem CAS primitive.

## Forward procedure

1. Complete the separately reviewed runtime upgrader publication while every
   consumer remains fenced. If interrupted after runtime exchange, resume that
   exact runtime transaction until its `published.json` exists. Do **not** use
   `ready.json` alone as evidence of runtime publication.
2. Prepare a canonical owner-only JSON request with exactly these fields:

   ```text
   runtime                    absolute actual runtime directory
   upgrade_transaction        absolute actual Matrix upgrade transaction
   transaction                new private external sidecar transaction
   target                     existing STATE/matrix-clients/HASH directory
   expected_target_sha256     Matrix inventory_digest of the original sidecar
   expected_upgrade_sha256    SHA-256 of actual upgrade published.json bytes
   expected_origin            exact body_ref/embodiment_id/incarnation_id/principal_id
   expected_being_ref         owner-reviewed continuing being reference
   ```

3. With the reviewed interpreter, stage the reviewed request:

   ```sh
   python -m clusterctl.matrix_status_transition stage \
     --request /absolute/reviewed-request.json \
     --request-sha256 REQUEST_SHA256 --externally-quiesced
   ```

   Staging verifies the actual published forward inventory, original runtime
   checkpoint, active root authority, exact V3 status config, exact five methods,
   origin/runtime ID/label, symmetric key binding and signed status row. It also
   validates the original V1 external pair against the legacy runtime checkpoint.
   It preserves `checkpoint/` and stages byte-exact `candidate/` containing only
   `client.json` and `capability.key`. Nothing is symlinked. `ready.json` records
   exact paths/digests and returns `stopped-staged`.

4. Review/pin that ready record, then publish:

   ```sh
   python -m clusterctl.matrix_status_transition publish \
     --transaction /absolute/external-transaction \
     --ready-sha256 SIDECAR_READY_SHA256 --externally-quiesced
   ```

   Publication revalidates runtime/publication binding and private metadata,
   candidate/checkpoint/target inventories and receipt CAS. The current status
   capability is checked at the last pre-exchange boundary, after inventory I/O.
   Linux `renameat2(RENAME_EXCHANGE)` swaps the entire directories and fsyncs both
   parents; there is no two-rename emulation. `candidate/` then contains the
   original sidecar and the separate `checkpoint/` remains unchanged.
   The receipt returns `stopped-published`.

## Interruption, retry and stopped states

- A complete staged request is exactly retryable before publication. Incomplete
  staging (partial directory/copy or missing ready record) is retained and
  refused, not silently repaired. Keep consumers fenced; separately review
  recovery of that retained evidence. The helper has no generic repair command.
- Before sidecar exchange, old external/new runtime is deliberately unavailable.
  After an exchange with lost return/fsync or receipt-write interruption, retry
  `publish` with the **same ready pin**. It recognizes only the exact exchanged
  inventory pair, resyncs parents and publishes/verifies the exact receipt.
  Incomplete private receipt temporaries are retained, never mistaken for success.
- Exact already-exchanged replay may acknowledge an expired **capability**; it
  does not exchange, rotate, reissue or extend authority. Root identity authority
  must still verify. This acknowledges stopped bytes, not a usable client.
- Changed runtime (including legitimate post-start effects), candidate, checkpoint,
  receipt or target refuses. Replaying a historical publication record never
  authorizes a runtime/client mismatch. Keep all evidence and consumers stopped.
- No power-loss hardware drill is claimed: synthetic tests exercise real directory
  exchange and injected exceptions at exchange/fsync/receipt boundaries.

## Reverse procedure

First complete the independently reviewed **monotonic runtime rollback**, while
consumers stay fenced. Never restore encrypted custody/high-water from the old
checkpoint, and never rewind the external source checkpoint. If runtime rollback
refuses post-effect state, the sidecar helper cannot make it safe: retain the
candidate state and use separately reviewed forward recovery.

Then run:

```sh
python -m clusterctl.matrix_status_transition rollback \
  --transaction /absolute/external-transaction \
  --ready-sha256 SIDECAR_READY_SHA256 \
  --rollback-publication-sha256 ACTUAL_RUNTIME_ROLLED_BACK_RECEIPT_SHA256 \
  --password-fd 3 --externally-quiesced
```

FD3 must be supplied by the approved owner-local custody mechanism. Passwords or
capability keys are never command-line values or printed. Forward sidecar
operations require no password. Rollback reads a bounded password descriptor,
uses it for validation and clears its mutable CLI buffer; Python immutable copies
are not claimed to be securely erasable.

Reverse validates the exact forward sidecar publication, exact Matrix reverse
ready/publication records, actual runtime inventory and advanced counter, unchanged
original checkpoint and exact pre-effect forward tree retained by runtime rollback.
It verifies the old sidecar's capability against the reverse bundle. It then runs
the fully digest-pinned legacy loader on a **private validation copy**, not the
actual runtime, to authenticate actual encrypted custody and legacy store contracts.
The copy must remain byte-identical. No constructor is invoked on live state.
A durable reverse intent binds the exact reverse receipt before external exchange.
The original sidecar is restored only after these checks, including current
capability admission immediately before exchange. The result is
`stopped-rolled-back`; the new pair remains in `candidate/`, the original
`checkpoint/` is untouched, and exact reverse retry does not exchange again.
Interrupted validation copies are retained and may require reviewed recovery.

## Explicit unsupported conditions / limits

- No automatic start/stop, process fencing, registry updates, application or
  foreign-being enrollment, root/fence authority creation, SSH or deployment.
- No portable snapshot restore, post-effect runtime downgrade, custody rewind,
  client-only rollback against a modern runtime, curator transition or fleet
  migration. Only existing V1 legacy status pairs and V3 successors are supported.
  The legacy V1 object has exactly `schema`, `capability`, `expected_server`.
  All V2 clients are refused, including valid empty-history and nonempty-history
  variants; V2 without `historical_servers` is invalid in the pinned legacy loader.
  Never relabel a real client or reconstruct its bytes to pass this boundary.
- Provisional/binding layouts and extended control/rekey histories remain refused.
  The only supported nonempty authority history is a bounded, cryptographically
  verified compact authority-epoch chain described below; this is not V2 client
  history support or permission to discard runtime history.
- No receipt/candidate reconstruction from arbitrary partial staging, new target
  creation, cross-filesystem exchange fallback or copying an existing transaction
  to another external parent inode. Large inventories inherit Matrix's per-file
  size and memory behavior; this is not a fleet-scaled transaction framework.
- Exact replay after credential/incarnation expiry may still refuse even though
  capability-only expiry is supported. Revalidation is not authority renewal.
- This helper imports private Matrix upgrade and public verification primitives;
  the reviewed Matrix successor is a required compatibility dependency. The
  correction leaves the existing successor pin
  `0a80cc5c38d3c7f5cad98d440153f0cf9706686b` unchanged; full maintenance
  composition qualification and release approval remain separate gates.

## Compact authority-epoch history

A native V1 status client can be valid even when its runtime has undergone an
ordinary signed authority-epoch succession. Runtime authority history and a
client's `historical_servers` field are different contracts. V1 retains its
exact three-field shape, and all V2 clients remain outside this transition lane.

The public verifier accepts an empty history or at most 256 compact entries.
Each entry has exactly `manifest` and `successor`; only the
`dm.we.authority-epoch/v1` successor schema is admitted. Historical authorities
are reconstructed using Matrix's `BeingManifest` and `RootAuthority` with the
shared active control/credential/incarnation context. Matrix's
`RootHistoryAuthority` verifies the complete ordered chain, signatures, hashes,
lineage and successor semantics. Unknown or additional fields, malformed chains,
replayed epochs, enrollment/recovery successors, extended control histories and
provisional/binding histories are refused. No duplicate cryptographic verifier
or runtime constructor is introduced.

This verification applies wherever the existing pair validator is invoked,
including forward staging/publication/replay and reverse validation. Current
origin, active credentials, expiry, secret-key correspondence, exact methods,
signed profile bindings, inventories, parent identity and CAS checks remain in
force. History and original V1 client bytes must be preserved across monotonic
reverse; do not rewrite production data to match an empty-history fixture.

This scope extension does not make every post-rollback runtime immediately
re-upgradable. Native runtime rollback can retain generated modern client
artifacts whose subsequent regeneration conflicts with Matrix's preservation
guard. A fresh transaction pathname alone does not resolve that condition.
Preserve the complete earlier transaction and artifacts, and separately qualify
a bounded recovery path; this sidecar change does not authorize deletion,
unverified cleanup, custody rewind or a blanket preservation exception.

The active Matrix dependency is the exact pin declared by the maintenance tree's
requirements and host provenance guard. The earlier V1-correction pin and review
counts below remain historical evidence, not this extension's qualification.
New exact-head review, genuine installed-pair tests and hosted CI are required.

## Corrected legacy contract and evidence boundary

The source of truth is Matrix `915c56c8899fd53d683bd7c7c81c3465b600bed9`:
`src/daimon_matrix/client.py` defines V1/V2 and `ClientConfig.load` requires
`historical_servers` for V2; `operator_bootstrap.py` emits V1 status clients.
The earlier helper and its synthetic fixture wrongly paired a V2 label with
only V1's three fields. That fixture was rejected by the real legacy client
loader. The runtime loader alone did not detect the invalid external client.

The old 52-test result, 35-probe review and four composed journeys remain
historical evidence, **not corrected V1 qualification or transferable approval**.
This successor needs independent review of its exact three-file freeze and
separate parent-owned integration/deployment gates. No old evidence is rewritten.

The corrected fixture copies the pinned bootstrap's native pair byte-for-byte
and runs the complete pinned `ClientConfig.load` in an isolated subprocess.
One sequential RED→GREEN cycle demonstrates native V1 acceptance; additional
regressions verify existing refusal guards, not new implementation cycles.
Reverse qualification establishes exact restore and replay before status effects,
then loads the restored external config and executes all five authenticated calls
through the actual pinned legacy `LocalClient`, private Unix socket and daemon
connection handler: `runtime.status`, `scope.me`, `scope.we`, `scope.we.diff`,
`scope.we.sync-plan`. No peer listener or deployed daemon is started. These reads
change the synthetic runtime ledger; subsequent reverse replay must refuse without
further mutation. They do not prove a post-effect downgrade is safe.

## Source-test reproduction

Unit development uses fresh unrelated synthetic identities and the real APIs.
Preseed `DM_LEGACY_SOURCE` with the exact `915c56c8899fd53d683bd7c7c81c3465b600bed9`
`src` tree; its entire inventory must match Matrix's built-in legacy source pin.
Tests never download fixtures. The legacy bootstrap/loader runs only in temporary
synthetic directories. No runtime constructor, enrollment or rebirth on live state
is authorized by these tests.

```sh
DM_LEGACY_SOURCE=/absolute/pinned-legacy/src \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/absolute/frozen-matrix/src:/absolute/cluster \
/absolute/unit-venv/bin/python -m pytest -q -W error \
  tests/test_matrix_status_transition.py
```

That source-path invocation is explicitly **unit development**, not installed-wheel
qualification. To reproduce the correction against an already installed, immutable
Matrix `0a80cc5c38d3c7f5cad98d440153f0cf9706686b` instead, first verify its
`daimon-matrix` `direct_url.json` commit and use only the Cluster path in
`PYTHONPATH` (never a moving Matrix checkout):

```sh
DM_LEGACY_SOURCE=/absolute/pinned-legacy/src \
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/absolute/cluster \
/absolute/installed-pair-venv/bin/python -m pytest -q -W error \
  -p no:cacheprovider tests/test_matrix_status_transition.py
```

Passing this focused suite against an installed dependency is not full installed
Cluster/Matrix host qualification. The parent owns composed receiver tests;
no `_matrix_api` or package metadata is spoofed here. Independent source review,
exact release provenance, human deployment approval and separately established
fence authority remain necessary gates.
