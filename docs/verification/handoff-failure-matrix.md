# Handoff failure-injection matrix (issue #30)

Every failure injected into the park → transfer/wake handoff converges to
one of three documented recoverable states:

- **source awake** — the failure happened before the point of no return;
  the source daimon keeps (or resumes) its lease and body.
- **both parked** — the checkpoint is intact, the source holds (or can
  re-acquire) its fence, no target is reachable; the operator resumes
  with `wake --handoff <name>` or `transfer <name> --to <new>` (both
  resumable from their state files).
- **target awake** — the relocation completed; the source spec is kept
  as `transferred` for audit (destroy is a separate human decision).

## Scenario matrix

| # | Injection point | Mechanism | Converges to | Covering test |
|---|---|---|---|---|
| 1 | before checkpoint (HMK quiesce fails) | exec_handler raises on sqlite3 checkpoint | source awake (park refused, nothing mutated) | tests/test_handoff_failures.py::test_hmk_checkpoint_failure_rolls_back_to_active |
| 2 | after checkpoint, before stop (secret scan finds a leak) | state file containing REDACT pattern | source awake, park refused fail-closed, no manifest | tests/test_park.py::test_secret_in_staged_changes_refused |
| 3 | during park (kill between any two steps) | _Kill raised in on_step hook, then resume | both parked (resume converges, stop only after verified manifest) | tests/test_park.py::test_resume_from_interruption |
| 4 | verification failure at park (HEAD moved, dirty tree) | git state changed between steps; resume re-commits | both parked | tests/test_park.py::test_failed_verification_rolls_back |
| 5 | broker restart / outbox non-empty at park | state_dir/bridge-outbox/ with pending file | source awake, park refuses 409-style unless --force-outbox | tests/test_park.py::test_outbox_nonempty_refused_unless_forced |
| 6 | before CAS (fence renew during wake) | another holder renewed first → stale epoch | both parked (no start, spec stays parked) | tests/test_transfer.py::test_wake_stale_fence_refused |
| 7 | stale holder traffic (re-acquire after expiry) | holder B re-acquires (epoch resets to 0); holder A wakes with old manifest | both parked, B is the only valid holder — acquisition-bound fencing | tests/test_handoff_failures.py::test_stale_holder_wake_with_old_manifest_refused, ::test_stale_holder_transfer_with_old_manifest_refused |
| 8 | clock skew | lease created_ms far in the past, ttl_s=1 | expired lease does not block re-acquire; old-holder renew refused | tests/test_handoff_failures.py::test_clock_skew_expired_lease_status_and_reacquire |
| 9 | network partition during transfer restore | adapter.exec raises mid restore-files | both parked (rollback: target destroyed, spec deleted, source parked) | tests/test_handoff_failures.py::test_transfer_network_partition_during_restore_rolls_back |
| 10 | during transfer, before CAS (target create fails) | adapter.create_instance raises | both parked (rollback; source untouched) | tests/test_transfer.py::test_transfer_cas_failure_rolls_back (fence-path variant) |
| 11 | after CAS, before start (start fails) | adapter.start raises after fence acquired | both parked; pre-renew lease restored EXACTLY (epoch back to pre-transfer value) | tests/test_handoff_failures.py::test_transfer_start_failure_restores_pre_renew_lease |
| 12 | CAS failure mid-transfer (lease vanished) | lease file deleted after park | both parked (rollback; source lease intact/absent as before, resume hint recorded) | tests/test_transfer.py::test_transfer_cas_failure_rolls_back |
| 13 | tampered checkpoint manifest | manifest JSON edited (actor field) | refusal at the provenance gate; nothing created | tests/test_transfer.py::test_transfer_tampered_manifest_refused, tests/test_park.py::test_unsigned_or_tampered_manifest_rejected |
| 14 | corrupted parked state file | parked NOW.md overwritten on disk | refusal (hash mismatch); restore never writes tampered state | tests/test_transfer.py::test_transfer_restored_sha_mismatch_rolls_back |
| 15 | interruption mid-wake / mid-transfer | _Kill in on_step, then re-run | converges (resumable state files) | tests/test_transfer.py::test_wake_resume_from_interruption, ::test_transfer_resume_from_interruption |
| 16 | audit chain after failures | verify_chain after failed park + failed transfer | chain intact; failures are recorded events, never silent | tests/test_handoff_failures.py::test_audit_chain_intact_after_failed_park_and_transfer |

## Convergence guarantees and their proofs

**(a) No two valid holders.** CAS fencing: renew computes epoch+1 and
refuses when the lease is gone/expired (LeaseStore.renew); acquire
refuses while a live lease exists (LeaseStore.acquire). Proven by
tests/test_leases.py (TestAcquire, TestCASFencing, TestMultiDaimon)
plus scenarios 6–8 above. Issue #30 added acquisition-bound fencing:
because epochs reset to 0 on re-acquire, the checkpoint manifest binds
to `resource_fence_acquired_ms` (preserved across renews); a stale holder's
manifest never matches a newer acquisition (scenario 7).

**(b) No accepted work from a stale fence.** Every wake/transfer first
re-verifies the manifest signature AND the fence binding (epoch +
acquisition) before any mutation; the start step only runs after the
new fence is held (scenarios 6, 7, 11, 13, 14; call-order asserted in
tests/test_transfer.py::test_transfer_happy_path_order).

**(c) Every failure converges.** Park: stop runs ONLY after a verified
manifest; resume from any step re-verifies (scenarios 1–5, 15).
Transfer: any TransferError after target create triggers the idempotent
rollback (destroy target, delete spec, restore pre-renew lease exactly,
source stays parked) with a recorded resume hint (scenarios 9–12).
Wake: on failure the lease stays parked, the container stays stopped,
the spec rolls back to parked, and the signed wake record carries the
error (scenario 6, tests/test_transfer.py::test_wake_start_failure_rolls_back).

## Live-drill evidence

The live drill (real container, real HMK + state files, park --handoff →
transfer → verify → wake) is recorded in
`docs/verification/handoff-drill-1.md` (to be attached with the drill
artifacts when executed).
