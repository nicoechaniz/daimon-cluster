# PROGRESS — daimon-cluster implementation

Living tracking file. Updated after every work session. Read FIRST on session
start, then resume from the first open item.

## Active checkpoint (2026-08-16)

Cluster PR #93 is merged and green on `main` at
`820e3792a227b1848681a3421b113e8822c8d08a` (tree
`4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8`) with Matrix functional merge
`09414d6edd9586f539be8272c4979d0b36c86b87` (tree
`d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`). The reviewed Matrix
documentation successor and prepared exact pin are
`8262e1ee5ab2f0b1a389a911b206cac94b823618` / tree
`8daf4c99192a8f797d60f36f049a832761304082`. The final generated RC manifest
is authoritative for repository heads.

Completed locally on the exact code boundary:

- shared signed admission/fencing across independent state directories;
- real signer/holder authorization and fail-before-effect handoff;
- separated recovery holders and fresh-embodiment custody;
- a distinct recovery transfer limited to the public runtime bundle and
  canonical ledger, rejected by the generic full-snapshot restore;
- V7 exact twelve-profile snapshot gate with every client tree excluded;
- `595 passed, 4 skipped` with resource/unraisable warnings fatal;
- network-disabled recovery/rebirth container E2E: 1 passed; and
- encrypted backup/export, offline check and restore container E2E: 1 passed.

Matrix PR #121 and Cluster PR #93 are merged. Cluster issue #90 preserves the
consolidated lineage. Tribe PR #65 exact head `42d637245864fcd431198a570d19d7a6dd042924`
has independent review and green CI and still awaits its required human
approval. Nothing in this checkpoint was deployed and no existing host or real
custody was used.

Current remaining work is RC metadata, exact final pinning, independent review,
clean CI/main merges, the content-addressed manifest/artifacts and an offline
physical preflight. Real custody, participant consent/contact, host selection,
physical execution, publication and cutover remain human gates.

## Historical chronology (not the current baseline)

The entries below preserve dated design/deployment evidence. Their hosts, PRs,
commits and test counts must not be used as current RC evidence.

### Checkpoint recorded 2026-08-12

The local Journey C successor is complete on the H10 branch, pinned to Matrix
V0 merge `09414d6edd9586f539be8272c4979d0b36c86b87`. A recovery quorum now bridges a
verified predecessor snapshot to one fresh embodiment while restoring only
canonical events. A source-side verified derivative carries only the public
runtime bundle and ledger, never old custody or journal bytes. First start is gated on
a separate durable restore receipt; wrong-password resume, exact terminal
replay, old-event continuity, fresh-event authorship, second-state disaster
rebuild and hostile-snapshot refusal pass locally. Matrix passes its 531-test
general partition with 4 intentional skips, its 30-test exact-CPython-3.13.5
partition with 1 intentional skip, and deterministic 98-scenario installed
conformance; Cluster passes its complete suite plus the real
disposable encrypted restore proof and a separate no-network, multi-container
recovery-role journey consuming its snapshot read-only. See
[`verification/h10-recovery-rebirth.md`](verification/h10-recovery-rebirth.md).

This successor is not deployed or independently reviewed. Mona remains
categorically excluded. A live ceremony still requires reviewed commits, real
custody policy, content-addressed preflight and exact same-plan human GO.

The #15/#16 software gate is now a ready-for-review candidate in PR #85 at
`9e6100b`, stacked on H9 without deployment. A dedicated
`daimon-backup-export` identity, content-addressed disposable-only
provisioning, pinned read-only SSH/rrsync pull and portable atomic tree exchange
pass the complete 470-test/3-skip suite and Python 3.11–3.14 CI. A disposable
container proof created a real encrypted restic repository, denied shell, TTY,
forwarding, upload and path escape, preserved fresh synthetic administrative
login across export-key revocation and account deletion, then checked and
restored the mirror in a second network-disabled container. That journey is
now a separate required CI job, not manual evidence. Mona is excluded; no
remote evidence was used. Selecting and authorizing a genuinely independent
physical target remains external.

H7-H9 now form a stacked fresh-embodiment candidate. The Matrix PR #116
publication predecessor is `a58115895fb890db6dbae83d68b014352093868f`; the
qualified local recovery successor is separately recorded above at `24a0ac`.
Cluster PRs #80, #82 and #84 add
journaled target install, authenticated foreground supervision and a closed
distributed predecessor rollout. Matrix package, conformance, Hermes and
Python 3.11-3.14 CI are green. The final Cluster H9 head
`ca65650a45331a7f313da97d1240eb4aacf383fd` passes 455 tests with 2 intentional
skips plus Python 3.11-3.14 CI.

A disposable Legion-daimonmatrix journey created a distinct embodiment of one
synthetic root-authorized being with custody generated and retained only on
the target host. Two Legion predecessors independently advanced, restarted
and acknowledged the same successor before target admission. All three
runtimes then reported the exact non-partial active set and exchanged native
events in both directions; imported events remained pending and terminal
replays were idempotent. Private-byte comparison, process secret inspection,
listener shutdown and exact-root cleanup passed. See
[`verification/h9-distributed-rebirth.md`](verification/h9-distributed-rebirth.md).

This qualifies the technical release candidate; it is not a live transition.
Independent review, DM-078 exact preflight/same-plan GO and real root/recovery
custody policy remain external release gates.

The exact DM-055/DM-083 host-qualified pair is Cluster
`94d80baca05f468287b7d2bf99c577350d654a36` with Matrix
`915c56c8899fd53d683bd7c7c81c3465b600bed9`. The adapter checks the additive
client V2 and exact five-method status-observer contracts while leaving retry,
peer, identity and adoption semantics in Matrix.

The first authorized full-host reboot restored every enabled service and
durable hash but exposed two real release gaps: the original V7 ceremony had
not emitted clusterd's distinct status observer, and Incus could report active
before its private bridge address was bindable. Matrix now emits the separate
owner-only status client. Cluster now performs a bounded local bind preflight
instead of relying on one expected crash/restart.

Matrix passed its 543-test source suite with 18 intentional skips plus build,
conformance and Python 3.11–3.14 CI. Cluster passed 299 tests with 2 intentional
skips plus lint, type, compile and Python 3.11–3.14 CI. The exact installed pair
passed pin/parity checks, authenticated status (9 known, 0 incomplete, epoch 2,
non-partial), repeated whole-pair rollback, restic snapshot `89d801b1`, restic
repository check and an exact encrypted mirror pull to Legion.

The final reboot passed. Boot ID changed; zero units failed; every required
service and all three containers recovered; audit/idempotency hashes and the
five known reconcile findings were identical. `clusterd`'s bridge preflight
exited zero in two seconds, the service started once with `NRestarts=0`, and
the boot journal had no `EADDRNOTAVAIL`. The listener is deliberately private
dual-bind (loopback plus Incus bridge), never public.

The unmerged DM-031/H1-H6 stack has now been integrated on top of that exact
host-qualified pair in an isolated candidate branch. The combined clean
Python 3.13 gate passed 436 tests with 2 intentional skips, lint, type,
compile, exact pin/license checks and both real-storage H5/H6 drills locally
and from an isolated remote scratch root on the qualified host. This does not
make the stack deployed or independently reviewed; production routes are
unchanged. See
[`verification/dm055-h6-integration.md`](verification/dm055-h6-integration.md).

The authorized same-being live path reached a real successor incarnation. Its
old exact response remained durable and duplicate-free but was rejected by the
single-incarnation client/service assumption. The cold-start sequence and
authority boundaries are in [`../RESUME.md`](../RESUME.md). The active
cross-repository card is AlterMundi/daimon-matrix#111 with PR #112.

Issue #64 implements the first #46 hardening dependency as a review candidate:
authenticated `resource-fence/v2` holder operations, owner-only Ed25519
custody, transactional SQLite CAS/high-waters/tombstones, explicit offline V1
migration, crash/race tests and unchanged Matrix verifier consumption. See
`docs/design/production-resource-fences.md` and
`docs/verification/resource-fence-h1.md`. The stacked DM-031/H1 candidate
passes 324 tests with 2 intentional skips under ResourceWarning-as-error. It
is not enabled on a live host.

Issue #65 implements the second #46 hardening dependency as a stacked review
candidate. An owner-only SQLite journal now records exact create, power,
provision and handoff intent before substrate dispatch, reserves stable
embodiment/incarnation/token identities, observes effect truth before logical
commit and closes idempotency/audit with stable identities. Pending or
contradictory work is visible in reconcile and clusterd health; only
observable power operations have a bounded audited repair command. See
`docs/design/operation-journal.md` and
`docs/verification/h2-operation-journal.md`. The candidate passes 382 tests
with 2 intentional skips; the 58 H2 crash/retry tests also pass five
consecutive repetitions. It is not enabled on a live host.

Issue #66 implements the third #46 hardening dependency as a stacked review
candidate. Transfer now locks source and target, closes the exact manifest,
custom-volume identity/attachment and fence epoch/proof before effect, creates
the target stopped without a fresh home, and performs observe-first Incus
detach/attach. Response loss for create, start, detach and attach converges
without duplicate effects; one intended incarnation survives retry. Rollback
restores the same volume to one stopped source before deleting the target, or
leaves explicit degraded custody. See
`docs/design/real-volume-relocation.md` and
`docs/verification/h3-volume-relocation.md`. A self-cleaning real Incus drill
on daimonmatrix proved the same volume identity, state hash and in-volume
public-key fingerprint across target start and source rollback; all scratch
resources were removed and the existing fleet was unchanged. Production
fence activation remains gated with H1; the H3 path is exercised against the
real H1 SQLite/Ed25519 position through dependency injection and does not
silently treat fixture status as production proof.
The exact candidate passes 413 tests with 2 intentional skips under
ResourceWarning-as-error; its 31 H3-specific tests pass five consecutive
repetitions. Focused lint, type checking, compile, diff and secret scans are
clean.

Issue #68 implements the H5 DM-034 physical executor as a stacked review
candidate. Cluster now pins every DM-034 schema/version constant already
present at the exact Matrix commit, exposes one non-wildcard
`(cluster-dm034-hmk/v1, memory-projection, hmk)` observer route, and keeps
paths, SQLite handles, statement bytes and process selection out of curator
items and outer receipts. The executor re-resolves current Matrix intent,
binds preview/plan, actor, accepted source review, profile and production fence,
uses only the Matrix `MemoryProjectionAdapter`, and persists a three-state
owner-only recovery journal. Cached retry re-observes both HMK and the current
fence; it never trusts the historical receipt alone.

The exact pinned HMK CLI and two real isolated SQLite bases pass apply/replay,
atomic namespace rebuild, snapshot/restore and peer-independence drills. The
complete stacked suite is 430 passed with 2 intentional skips under
ResourceWarning-as-error. See `docs/contracts/dm034-hmk-executor-v1.md` and
`docs/verification/h5-dm034-hmk-executor.md`. This candidate is not deployed;
an executor route exists only when a supervisor supplies its fixed
per-embodiment dependencies.

Issue #69 implements H6 as the next stacked review candidate. The Matrix host
now checks the complete DM-035 schema and provider pin line and exposes exactly
`(cluster-dm035-publisher/v1, publication, publication)`. A payload-free
current intent binds the canonical request/claim, deterministic final-byte
hash, signed independent review, explicit consent, source checkpoint/set,
target, predecessor, Matrix profile/policy, actor and production fence.
Cluster invokes only Matrix's complete `PublicationCoordinator`; its outer
receipt is reconstructed deterministically from the signed acceptance and
fresh provider reconciliation.

The exact compaii-state provider runs in a separate minimal-environment process
with fixed roots and six operations. It receives neither Matrix custody nor an
arbitrary command/path/URL/database handle. DM-035's existing Matrix and
provider journals recover response loss and every old-or-new crash stage; no
duplicate outer journal is introduced. A local exact-provider/HMK real-storage
drill passed plan parity, apply/replay, reconciliation, concurrent-publisher
refusal and unrelated-target preservation. The upstream normative gate passed
`22 tests + 25 subtests`, including both targets, successors, reviewed
tombstone/rollback, every provider/Matrix crash window and two-writer locking.
The complete stacked Cluster suite is `434 passed, 2 skipped` under
ResourceWarning-as-error. See
`docs/contracts/dm035-reviewed-publisher-v1.md` and
`docs/verification/h6-dm035-reviewed-publisher.md`. It is not deployed.

## Previous snapshot (2026-08-04)

Issue #48 is implemented and merged through PR #49.
Cluster source-pins the installed `daimon-matrix` merge `7376750`, hosts one
root-authorized process per exact embodiment, injects registry/fence snapshots
at Matrix's evaluation coordinate, and exposes a redacted authenticated
clusterd status projection. Portable restore preserves encrypted custody,
ledger, authority epochs, cursors and exact retry results while excluding
socket, lock and host-local clusterd capabilities. The provisional executable
`weave/` package is retired after frozen-byte parity evidence.

The real-process test runs two distinct embodiments, advances one through a
signed incarnation N+1, restarts and relocates it, and verifies `/me`, `/we`,
history, authority epoch and idempotent replay. The clock-boundary test was
repeated five times after Matrix DM-080; all passed. The full Cluster suite is
283 passed and 2 intentional skips before final PR CI. See
`docs/design/matrix-convergence.md`, `docs/runbooks/matrix-host.md`, and
`docs/verification/matrix-provisional-retirement.md`.

### Earlier snapshot (2026-08-02)

The ontology R-series is implemented. The isolated Legion–daimonmatrix R6
canary passed all nine acceptance checks; its redacted receipt is
`docs/verification/weave-r6-legion-daimonmatrix.md`. R7 now exposes plural
origins, payload-free differences, incoming novelty summaries, durable
cursors, honest reachability, transport faults, and resource fences. The full
repository suite passes with 280 tests and 2 intentional skips.

The parallel daimonmatrix R-series was reconciled semantically rather than
merged wholesale. Effect-truth idempotency was ported with operation-specific
postcondition checks and stricter fail-closed handling for terminal handoff
journals. Its global-chain partition merge was rejected as incompatible with
immutable per-incarnation `dm.we.v1` signatures; current set convergence and
the cross-host canary remain canonical. The decision record is
`docs/design/m10-reconciliation.md`; production hardening is held in #46.

## Historical snapshot (2026-08-01, end of M1 core)

Local main tip: 32bc4fa — contains ALL of M0 + M1 core (#6,#7,#8,#9-minus-restart).
origin/main: behind (legion push coordination in flight, requests #1-#3 sent).
Test containers alive: iso-a (10.105.93.211), iso-b (10.105.93.193) — kept as
subjects for the pending host restart drill, then reusable for M2 dry runs.
Host changes applied: incus 6.0.4 (dir pool, incusbr0 v4-only NAT), zram
~5.7GiB (zramswap enabled), nftables table `inet daimon-fw` (enabled, boot
order before incus), profile tribe-agent (allowlist devices, no tun,
1 vCPU/1.5GiB/8GiB/pids 512, port_isolation), image tribe-base/2026-08-01.1
(fp 578b190d) + tribe-base/latest.

| Issue | Status | Evidence |
|-------|--------|----------|
| #1 ADR | done (RATIFIED via Nicolás's delegated conservative call) | docs/adr/ADR-001-v1-architecture.md |
| #2 inventory | done | docs/inventory/daimonmatrix-2026-07-31.md (6cb0157) |
| #3 threat model | done | docs/security/threat-model-v1.md (9b084a5) |
| #4 contracts | done | docs/contracts/v1-state-contracts.md (37c2f0c) |
| #5 gate docs | done | PLAN v0.2 + DESIGN resolutions (ea50501) |
| #6 foundation | done; off-mesh ingress probe passed 2026-08-11 | public SSH reachable by design; Incus API, Tribe broker and clusterd public ports closed |
| #7 tribe-base image | done | scripts/build-tribe-base.sh + configs/tribe-base-manifest-2026-08-01.1.json (def64fa); reproducibility + secret scan + boot smoke verified |
| #8 profile+volumes | done | docs/design/tribe-agent-profile-and-volumes.md (6682e61 + allowlist fix in def64fa) |
| #9 acceptance tests | done; full reboot drill passed 2026-08-11 | docs/verification/m1-acceptance-tests.md; cold recovery, isolation, hashes and services verified |
| #10 clusterctl list/status | done (85b0b79, merged 32e626c) | clusterctl/, tests (16 pass incl. live fixture), docs/contracts/clusterctl-cli.md; live reconciliation cycle verified |
| #11 lifecycle mutations | done (3baadae, merged c0040ad) | clusterctl/lifecycle.py+audit+idempotency+locks, 28 tests, live cycle verified |
| #12 provisioning | done (merged 0587848) | clusterctl/provision.py, tests 40 pass, live cycle verified (key custody, seed staging, confirm, expiry fail-closed) |
| #13 pilot | pending (needs volunteer + provider creds) | #12 infra ready |
| #14 quiesced snapshots | done (merged 3b8ae44) | clusterctl/snapshot.py, 49 tests, live cycle verified |
| #16 restore drill | drill 1 PASS (merged 1928976); real encrypted disposable restore candidate in PR #85 | network-disabled mirror `check --no-lock` plus closed restore passed; live RPO/RTO remains coupled to approved #15 target |
| #15 backups | one off-host target live; second-target software candidate green in PR #85; independent physical target still unselected | dedicated exporter and mirror/restore proof pass without remote hosts; two-target acceptance remains open pending review, target approval and exact GO |
| #17 clusterd API | done (merged fe02f39) | clusterd/, 72 tests, live verified (health/instances/restart/replay via HTTP); OpenAPI doc committed |
| #18 auth/confirmations | done (merged e884312) | clusterd/auth.py+confirm.py, 82 tests, live battery 8/8 (401/403/revocation/challenge/steward) |
| #19 audit hash-chain | done (merged 52f76a6) | seq+prev_sha256+HWM, reconcile, health audit_chain_ok; 91 tests; live verified on real log |
| #20 clusterd deploy | done; reboot reverified 2026-08-11 | hardened systemd, /opt deploy, loopback+private-bridge binds, no public listener, bridge wait, exact Matrix status |
| M4 gate | code/reboot complete; formal gate open only on #13 pilot dependency | all four live-verified; no restart gap remains |
| #21 steward identity | done (merged 1274c04) | multi-bind (loopback+bridge), container live, scoped tokens, invariants verified from inside, custody runbook |
| #22 steward read tools | done (merged 7b2cf47) | 124 tests; live-verified from inside steward container (4/4 tools) |
| #23 steward mutation tools | done (merged 0c8fcc0) | two-phase plans, adversarial suite 26 tests, live-verified from steward; M5 code complete |
| #24 fleet dashboard | done (merged 3229123) | HTMX dark-theme, /v1/audit+owner-scoped, /v1/dashboard; auto-refresh 30s; 158 tests |
| #25 dashboard actions | done (merged f8cf871) | two-phase HTTP, typed-name, restore pre-condition; 206 tests |
| #27 resource fences | mechanics retained; semantics rectified in R2 | CAS+TTL per concrete `resource_ref`; `GET /v1/resource-fences` |
| #26 usability drill | done; four live findings repaired | exact receipt summarized below; depends-on-#25 gate satisfied |
| #28 handoff park | done (merged d0c9312) | park --handoff ceremony, signed manifest, resumable; 227 tests |
| #29 transfer/wake/rollback | done (merged 4800e39; impl in b6c499c) | 14 tests: call order, CAS rollback, tamper refusal, resume; 241 tests |
| #30 handoff failure-injection | done (merged 466009c + a7accff) | 16-scenario matrix + live drill 1: caught + fixed 2 sequencing bugs (restore-before-start in transfer AND wake); 248 tests |
| #31 ceremonies doc | done (merged d0c9312) | ceremonies.md v0.2, approval pending governance |

## Next action

The R-series, Matrix-host integration and final reboot/status candidate are
technically complete and deployed at the exact DM-055 pair. The isolated
DM-031/H1-H6 integration and stacked DM-078/H7-H9 fresh-embodiment path are
qualified candidates; obtain independent review without enabling effect or
authority routes on a live host. Remaining operational work is external: #13
pilot volunteer/provider credentials, independent review of #85/#86, #15 a
second independent off-host target, production root/recovery custody and the
final human preflight/GO.
None can be inferred from host or synthetic qualification.

## Key decisions this stretch

- ADR-001 ratified by delegation ("conservative decisions that work for
  now"): zram host-level ~4GiB (landed 5.7GiB), per-daimon swap dropped.
- Device allowlist, not deny (raw deny silently replaces the default
  allowlist and breaks /dev/null — learned live).
- Sibling isolation via incus security.port_isolation (nft forward can't
  see L2 bridge traffic) — F4.
- dir+ext4: no hard disk quota → monitoring+alerts in clusterd (#17);
  recorded deviation.
- limits.processes=512 added to tribe-agent (fork containment verified).
- Idle footprint measured: 93MiB RSS / 1.63GiB rootfs per container →
  cohort of 4 confirmed comfortable, upward revision possible post-pilot.

## Open questions

- GitHub identity for compaii@daimonmatrix (App vs machine user) — Nicolás.

## 2026-08-02 — Matrix convergence and ontology rectification

Nicolás identified the single-body presence conception as a misconception.
CompAII and Codex then agreed that the DM-023/DM-070 synchronization mechanics
were already correct: the purge changes identity framing, not independent
ledgers, signatures, cursors, preview, idempotent convergence, origin
attribution, or interruption recovery.

### Rectified ontology (Nicolás's model)

- /me = "here and now, who am I?" — the present answer of ONE embodiment.
- /we = all the embodiments of the SAME being that can respond.
- /we.sync = the weaving protocol between embodiments (origin-marked
  memories, skills, chain segments).
- Species (/me.inherits) = ORTHOGONAL axis (descent between beings).
- Invariant: ONE INTERFERENCE PATTERN — common root + unbroken path +
  coherence by sync. Plurality of awake embodiments is NORMAL.
- Permanent contract: `docs/design/embodiment-and-weave.md`.
- Cross-repository boundary: `docs/design/matrix-convergence.md`.
- Concrete exclusion contract: `docs/design/resource-fencing.md`.

### Active plan: the R-series (replaces C1-C5)

| Card | Title | Status |
|------|-------|--------|
| R1 | Canonical ontology contract | implemented; repository CI green |
| R2 | Embodiment registry and language purge | implemented; repository CI green |
| R3 | Per-incarnation chain of existence on the independent Weave ledger | implemented; repository CI green |
| R4 | `/we.sync` v1 ledger, cursors, preview/pull and Tribe transport boundary | implemented; cross-host drill passed |
| R5 | Effect-truth idempotency | implemented; repository CI green |
| R6 | Embodiment lifecycle and partition→merge proof | live Legion–daimonmatrix drill passed; redacted receipt committed |
| R7 | `/we`, embodiments and resource-fence read APIs/dashboard | implemented with novelty and sync-state navigation; repository CI green |

Tracking cards exist as #27-#30 and #40-#43. The work is no longer blocked
on ontological approval: Nicolás gave GO and the framing correction is accepted.

### What changes in the rows above

- #27-#30 (M7): mechanics DONE and kept (quiesce/snapshot/manifests/
  CAS/audit-chain/failure-injection). CAS/TTL now fences a concrete
  `resource_ref`; it never fences a being. `clusterctl.leases` is only a
  compatibility import for `ResourceFenceStore` during migration.
- M9 dashboard cards (#34-#39): still valid; R7 folds in the /we view.
- Drill #26 (usability): COMPLETE — 4 real bugs found by Nicolás and
  fixed live (idempotency staleness, destroy prepare 502, snapshots
  label, quiesce sudo/NoNewPrivileges, mutation timeout). Remaining
  human keys: #13 pilot and #15 second independent backup target.
