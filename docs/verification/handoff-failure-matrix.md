# Handoff failure-injection matrix (issue #30; M10-R2/R6 retargeted)

Every failure injected into the park → transfer/wake lifecycle converges
to one of three documented recoverable states:

- **source awake** — the failure happened before the point of no return;
  the source embodiment keeps its body and the census is untouched.
- **both parked** — the checkpoint is intact, the census records the
  embodiment parked, no target is reachable; the operator resumes with
  `wake --handoff <name>` or `transfer <name> --to <new>` (both
  resumable from their state files).
- **target awake** — the relocation completed; the source spec is kept
  as `transferred` for audit (destroy is a separate human decision).

> M10-R2 note: park/wake/transfer are LIFECYCLE verbs (powering down /
> re-entering / moving bodies) — never identity ceremonies. The census
> (embodiment registry) records transitions; it never excludes. The
> retired scenarios are listed at the end with their replacements.

## Scenario matrix

| # | Injection point | Mechanism | Converges to | Covering test |
|---|---|---|---|---|
| 1 | before checkpoint (HMK quiesce fails) | exec_handler raises on sqlite3 checkpoint | source awake (park refused, nothing mutated, census untouched) | tests/test_handoff_failures.py::test_hmk_checkpoint_failure_rolls_back_to_active |
| 2 | after checkpoint, before stop (secret scan finds a leak) | state file containing REDACT pattern | source awake, park refused fail-closed, no manifest | tests/test_park.py::test_secret_in_staged_changes_refused |
| 3 | during park (kill between any two steps) | _Kill raised in on_step hook, then resume | both parked (resume converges, stop only after verified manifest) | tests/test_park.py::test_resume_from_interruption |
| 4 | verification failure at park (HEAD moved, dirty tree) | git state changed between steps; resume re-commits | both parked; census still awake (no transition recorded) | tests/test_park.py::test_failed_verification_rolls_back |
| 5 | broker restart / outbox non-empty at park | state_dir/bridge-outbox/ with pending file | source awake, park refuses 409-style unless --force-outbox | tests/test_park.py::test_outbox_nonempty_refused_unless_forced |
| 6 | stale checkpoint at wake (census moved past) | a newer transition registered after the checkpoint | both parked (no start, spec stays parked) | tests/test_transfer.py::test_wake_stale_checkpoint_refused |
| 7 | unregistered embodiment at park | no census row (pre-M10 instance) | source awake, exit 10; explicit --no-registry records the path | tests/test_park.py::test_no_registry_path_is_explicit |
| 8 | idempotency record lies (drill #26 class) | recorded "stopped", body actually running | NO replay — effect-truth discrepancy audited, fresh execution converges | tests/test_effect_truth.py::test_false_record_is_not_replayed |
| 9 | network partition during transfer restore | adapter.exec raises mid restore-files | both parked (rollback: target destroyed, spec deleted, rolled-back appended) | tests/test_handoff_failures.py::test_transfer_network_partition_during_restore_rolls_back |
| 10 | during transfer, before census transition (target create fails) | adapter.create_instance raises | both parked (rollback; source untouched) | tests/test_transfer.py::test_transfer_start_failure_rolls_back (start-failure variant) |
| 11 | after census transition, before start (start fails) | adapter.start raises after registration | both parked; rollback APPENDS rolled-back at cursor+1 (the attempt stays in history) | tests/test_transfer.py::test_transfer_start_failure_rolls_back |
| 12 | partition + heal (the re-imagined split-brain) | both embodiments append chain transitions independently, then sync | coherent merge: deterministic base, losing branch re-anchored as merged records, byte-identical chains, nothing erased | tests/test_merge.py::test_partition_then_coherent_merge |
| 13 | tampered checkpoint manifest | manifest JSON edited (actor field) | refusal at the provenance gate; nothing created | tests/test_transfer.py::test_transfer_tampered_manifest_refused, tests/test_park.py::test_unsigned_or_tampered_manifest_rejected |
| 14 | corrupted parked state file | parked NOW.md overwritten on disk | refusal (hash mismatch); restore never writes tampered state | tests/test_transfer.py::test_transfer_restored_sha_mismatch_rolls_back |
| 15 | interruption mid-wake / mid-transfer | _Kill in on_step, then re-run | converges (resumable state files) | tests/test_transfer.py::test_wake_resume_from_interruption, ::test_transfer_resume_from_interruption |
| 16 | audit chain after failures | verify_chain after failed park + failed transfer | chain intact; failures are recorded events, never silent | tests/test_handoff_failures.py::test_audit_chain_intact_after_failed_park_and_transfer |

## Convergence guarantees and their proofs

**(a) Checkpoint freshness, not identity exclusion.** Wake/transfer
re-verify the manifest signature AND that the census's parked record
still points at THIS manifest; a newer transition means the checkpoint
is stale (scenario 6). This protects STATE freshness — plurality of
embodiments is unaffected and normal.

**(b) Append-only truth.** The census never restores an old record:
failed transitions append parked/rolled-back at cursor+1 and the
cursor never goes down (scenarios 9–11). The chain of existence
(R3) makes this verifiable; the audit hash-chain holds through every
failure (scenario 16).

**(c) Effect-truth, not stored claims.** Idempotent replays are served
only when observed state matches the recorded effect; a lying record
triggers a discrepancy event and fresh (convergent) execution
(scenario 8, M10-R5).

**(d) Branches converge by weaving, never by erasing.** A partition
produces two true branches; the deterministic merge re-anchors the
losing branch as merged records (provenance intact) and both sides
arrive at a byte-identical chain (scenario 12, M10-R6).

## Retired scenarios (M10 purge — kept for the record)

- clock skew / expired lease → the census has no TTL or clock
  semantics; liveness is observed from the fleet.
- two-holders race / stale fence → plurality is normal; the equivalent
  protection is checkpoint freshness (scenario 6).
- pre-renew lease restore → rollback never restores; it appends
  (scenario 11).
- "split-brain" as a crime → re-imagined as partition + coherent merge
  (scenario 12).
