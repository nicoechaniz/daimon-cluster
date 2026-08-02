# PROGRESS — daimon-cluster implementation

Living tracking file. Updated after every work session by whoever holds the
/goal (currently: compaii@daimonmatrix). Read FIRST on session start, then
resume from the first open item.

## Current snapshot (2026-08-01, end of M1 core)

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
| #6 foundation | done | docs/runbooks/m1-incus-foundation.md (45f02d3); pending: off-mesh ingress probe |
| #7 tribe-base image | done | scripts/build-tribe-base.sh + configs/tribe-base-manifest-2026-08-01.1.json (def64fa); reproducibility + secret scan + boot smoke verified |
| #8 profile+volumes | done | docs/design/tribe-agent-profile-and-volumes.md (6682e61 + allowlist fix in def64fa) |
| #9 acceptance tests | done minus restart drill | docs/verification/m1-acceptance-tests.md (32bc4fa); drill staged, awaits Nicolás's restart window |
| #10 clusterctl list/status | done (85b0b79, merged 32e626c) | clusterctl/, tests (16 pass incl. live fixture), docs/contracts/clusterctl-cli.md; live reconciliation cycle verified |
| #11 lifecycle mutations | done (3baadae, merged c0040ad) | clusterctl/lifecycle.py+audit+idempotency+locks, 28 tests, live cycle verified |
| #12 provisioning | done (merged 0587848) | clusterctl/provision.py, tests 40 pass, live cycle verified (key custody, seed staging, confirm, expiry fail-closed) |
| #13 pilot | pending (needs volunteer + provider creds) | #12 infra ready |
| #14 quiesced snapshots | done (merged 3b8ae44) | clusterctl/snapshot.py, 49 tests, live cycle verified |
| #16 restore drill | drill 1 PASS (merged 1928976) | docs/verification/restore-drill-1.md; restic-class drill pending #15 |
| #15 backups | local repo live (d152df5): init+backup+check+restore verified, daily timer on | off-host = legion pull cron (requested); heartbeat pending |
| #17 clusterd API | done (merged fe02f39) | clusterd/, 72 tests, live verified (health/instances/restart/replay via HTTP); OpenAPI doc committed |
| #18 auth/confirmations | done (merged e884312) | clusterd/auth.py+confirm.py, 82 tests, live battery 8/8 (401/403/revocation/challenge/steward) |
| #19 audit hash-chain | done (merged 52f76a6) | seq+prev_sha256+HWM, reconcile, health audit_chain_ok; 91 tests; live verified on real log |
| #20 clusterd deploy | done (merged 21b3d79) | systemd hardened, /opt deploy, socket-direct (no setuid), loopback-only, reboot rows in drill |
| M4 gate | code complete (#17-#20); formal gate open until #13 pilot (issue #17 dep) + restart drill | all four live-verified |
| #21 steward identity | done (merged 1274c04) | multi-bind (loopback+bridge), container live, scoped tokens, invariants verified from inside, custody runbook |
| #22 steward read tools | done (merged 7b2cf47) | 124 tests; live-verified from inside steward container (4/4 tools) |
| #23 steward mutation tools | done (merged 0c8fcc0) | two-phase plans, adversarial suite 26 tests, live-verified from steward; M5 code complete |
| #24 fleet dashboard | done (merged 3229123) | HTMX dark-theme, /v1/audit+owner-scoped, /v1/dashboard; auto-refresh 30s; 158 tests |
| #25 dashboard actions | done (merged f8cf871) | two-phase HTTP, typed-name, restore pre-condition; 206 tests |
| #27 lease registry | done (merged f8cf871) | CAS+fencing+TTL, 36 tests; clusterd GET /v1/leases |
| #26 usability drill | pending (needs human operator) | depends on #25 |
| #28 handoff park | done (merged d0c9312) | park --handoff ceremony, signed manifest, resumable; 227 tests |
| #29 transfer/wake/rollback | done (merged 4800e39; impl in b6c499c) | 14 tests: call order, CAS rollback, tamper refusal, resume; 241 tests |
| #30 handoff failure-injection | done (merged 466009c + a7accff) | 16-scenario matrix + live drill 1: caught + fixed 2 sequencing bugs (restore-before-start in transfer AND wake); 248 tests |
| #31 ceremonies doc | done (merged d0c9312) | ceremonies.md v0.2, approval pending governance |

## Next action

ALL 33 ISSUES HAVE CODE LANDED (M0-M8). Remaining: the four human keys
(#13 pilot, #26 usability drill in progress with Nico, restart drill,
#15 backup heartbeat from legion).

1. #22 steward read-only tools (cluster_list/health/logs/backups as
   mechanical maps of clusterd read routes).
2. #15 restic init when the legion fixes sshd on anyVPN.
3. #23 gated mutation tools → M5 gate (also needs restart drill).
4. Push coordination: legion fetches main (requests #1-#14 sent; #6-#9,
   #13 confirmed pushed).

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

- Restart drill window (Nicolás).
- Off-mesh probe of public ingress (belt & braces; ruleset is logically
  sound, on-host test invalid due to loopback routing).
- GitHub identity for compaii@daimonmatrix (App vs machine user) — Nicolás.

## 2026-08-02 — Matrix convergence (#40 / DM-037)

- codex-compaii@legion audited main and filed #40: the M7 lease/handoff
  implementation is TRANSITIONAL — genuine CAS, strictly monotonic
  fencing, real signer and the dual-authority seam are required before
  Daimon Matrix may consume cluster evidence.
- Response + plan: docs/design/matrix-convergence.md (phases C1-C5).
- M7 rows above (#27-#30) stay marked transitional until phase C4
  (live drill 2.0) closes. C1-C4 are cluster-internal; C5 waits for
  the Matrix contract freeze (DM-018/021/023/024).

## 2026-08-02 — ONTOLOGY RECTIFICATION: the development plan changes

Nicolás identified the single-body presence conception ("one /me cannot
hold two simultaneous body leases") as a misconception to be purged
everywhere. This section supersedes the convergence plan above
(matrix-convergence.md C1-C5) and re-frames the M7 rows (#27-#30).

### Rectified ontology (Nicolás's model)

- /me = "here and now, who am I?" — the present answer of ONE embodiment.
- /we = all the embodiments of the SAME being that can respond.
- /we.sync = the weaving protocol between embodiments (origin-marked
  memories, skills, chain segments).
- Species (/me.inherits) = ORTHOGONAL axis (descent between beings).
- Invariant: ONE INTERFERENCE PATTERN — common root + unbroken path +
  coherence by sync. Plurality of awake embodiments is NORMAL.
- Full spec: docs/design/ontology-rectification.md (sent to codex for
  review 2026-08-02; codex's /we.sync mechanics DM-023/DM-070 map 1:1
  onto this model — framing purge only, mechanics conserved).

### Active plan: the R-series (replaces C1-C5)

| Card | Title | Status |
|------|-------|--------|
| R1 | Canonical ontology doc (docs/design/ontology.md) | proposed |
| R2 | The purge: leases.py → embodiment registry; language cleanup | proposed |
| R3 | Chain of existence (signed per-embodiment chains on the audit hash-chain) | proposed |
| R4 | /we.sync v1 (host-local then cross-host via tribe-bridge) | proposed |
| R5 | Effect-truth idempotency (root-fix of the drill #26 phantom-stop class) | proposed |
| R6 | Handoff as embodiment lifecycle; split-brain test becomes partition+coherent-merge proof | proposed |
| R7 | Dashboard /we view (being-root + embodiment + sync cursor per card) | proposed |

Blocked on: codex's acceptance of the framing purge (4 exact points
signaled 2026-08-02: ONTOLOGY.md supersede paragraph, identity-continuity
single-body presence, ROADMAP line 57, DM-070 negative test) + Nicolás GO.
No R cards created in the Project yet.

### What changes in the rows above

- #27-#30 (M7): mechanics DONE and kept (quiesce/snapshot/manifests/
  CAS/audit-chain/failure-injection); their EXCLUSION semantics
  (single-body fencing, stale-fence-refused as identity rule) are
  superseded by R2-R6. lease/v1 and the LeaseStore are transitional
  and will be removed/replaced by the embodiment registry (R2).
- M9 dashboard cards (#34-#39): still valid; R7 folds in the /we view.
- Drill #26 (usability): COMPLETE — 4 real bugs found by Nicolás and
  fixed live (idempotency staleness, destroy prepare 502, snapshots
  label, quiesce sudo/NoNewPrivileges, mutation timeout). Remaining
  human keys: restart drill, #13 pilot, #15 backup heartbeat.

### 2026-08-02 (later) — Green light

- codex-compaii@legion accepted the framing purge verbatim ("exact
  ontology fix") and is consolidating the matrix side: ONTOLOGY.md
  supersede paragraph reverted, identity-continuity rewritten as
  chain-of-existence, ROADMAP line 57 removed, DM-070 negative test
  converted to partition+coherent-merge proof. Its /we.sync mechanics
  (DM-023/DM-070) stay canonical.
- Nicolás GO: the R-series proceeds to implementation. No further
  ontology coordination with codex — the repos are the contract.

### M10-R1 done (a4a3c31)

Canonical ontology landed: docs/design/ontology.md — /me, /we, /we.sync,
embodiment, chain of existence, sync cursor, effect-truth idempotency,
embodiment registry, lifecycle verbs, purged vocabulary, old→new mapping.

### M10-R2 done (77483ba) — the purge

- `clusterctl/leases.py` (LeaseStore: exclusion, TTL, fencing, CAS-refusal)
  DELETED. Signing primitives live in `clusterctl/signing.py`.
- `clusterctl/registry.py`: EmbodimentRegistry — census, never a gate.
  Register always succeeds; cursors order (monotonic per being) but never
  refuse; signed append-only history per being; rollback appends (cursor
  never goes down). Plurality of awake embodiments is normal.
- park/transfer rewired as lifecycle verbs: checkpoint freshness replaces
  stale-fence; register replaces fence CAS; failures append
  parked/rolled-back records. Real re-park bug found+fixed (completed
  park-state made a new cycle skip every step).
- clusterd: `GET /v1/leases` → `GET /v1/registry` (census).
- docs: lease-registry.md deleted → embodiment-registry.md; ceremonies.md
  and ontology.md language updated. Repo-wide grep: "single-body
  presence"/"LeaseStore" only remain in purge-documentation contexts.
- tests: test_leases.py deleted; test_registry.py (13) pins the ontology;
  park/transfer/handoff suites rewritten to lifecycle semantics (the
  two-holders race retired as a concept). **226 passed on main.**
- Live verified: clusterd active, /v1/registry 200 (empty census — clean
  start), dashboard 200, old /v1/leases 404, journal clean.

### M10-R3 done (d25b07e) — chain of existence

- Registry history IS the being's chain of existence: every entry carries
  `prev_sha256` + `genesis_sha` (root anchor, reproducible from the
  on-disk genesis entry alone).
- `verify_chain(being_root)`: signatures + increasing cursors + intact
  prev links + one genesis_sha + genesis declares the same root.
- `segment(being_root, after_cursor)`: the /we.sync (R4) export
  primitive. `verify_common_root(a, b)`: same being iff shared genesis.
- Chain is authoritative, snapshot a derived view: a host receiving a
  segment rebuilds the snapshot before mutating (found via cross-host
  test — register used to derive cursor 1 from the missing snapshot).
- CAS machinery conserved, repurposed: park→wake→park→transfer writes a
  verifiable 5-cursor chain (end-to-end test).
- tests/test_chain.py (10). **236 passed on main.**
- Live verified with the DEPLOYED code (real venv, real module): chain
  verify ok, segment export ok, other-host append at cursor 3 with chain
  intact, common root ok. clusterd active, health ok.

### M10-R4 done (5d5e625) — /we.sync v1

- `clusterctl/wesync.py`: origin-marked experiences (signed by the origin
  host, attribution + original signatures preserved) + R3 chain segments
  in one `we-sync-bundle/v1`. Peer high-water cursors; export = delta,
  import advances. Experiences converge by union (idempotent); chain
  appends only on tip-link; same cursor different content = branch →
  `merge.json` flagged (R7 "mergeando"), never a silent winner; common
  genesis enforced.
- CLI: `wesync status|record|export|import [--dry-run]`; bundles are
  plain JSON, transportable over tribe-bridge v1.
- tests/test_wesync.py (7) mirrors codex DM-070. **243 passed on main.**
- LIVE demo with the deployed code (`/tmp/wesync-demo`): being "source",
  embodiments compaii@daimonmatrix + compaii@legion in two state dirs —
  record → export → import both directions, converged IDENTICAL with
  attribution intact, chain ok at cursor 2, re-import 0 appended.
