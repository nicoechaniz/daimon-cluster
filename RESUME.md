# DM-083 resume checkpoint

Status: the DM-055/DM-083 runtime pair is host-qualified. Exact Cluster code
`94d80ba` pins exact Matrix code `915c56c`; local suites, Python 3.11–3.14 CI,
installed contract checks, rollback, encrypted backup/mirror and the final cold
host reboot all passed. Both PRs remain unmerged pending independent review.

Last reconciled: 2026-08-11.

## Exact state

- Matrix PR #112 freezes the deployed reboot/status candidate at
  `915c56c8899fd53d683bd7c7c81c3465b600bed9`.
- Cluster PR #77 runtime code
  `94d80baca05f468287b7d2bf99c577350d654a36` repins that exact dependency,
  verifies the five-method status-observer boundary and waits boundedly for the
  private Incus bridge before `clusterd` binds.
- Matrix passed 543 tests with 18 intentional skips plus build, conformance,
  provenance and Python 3.11–3.14 CI. Cluster passed 299 tests with 2
  intentional skips plus lint, type, compile and Python 3.11–3.14 CI.
- The exact pair runs on Legion and daimonmatrix. Authenticated host status is
  configured with integrity `ok`, nine known events, zero incomplete, epoch 2
  and non-partial `/we` and sync-plan views.
- Fresh restic snapshot `89d801b1` passed repository verification and Legion
  pulled the encrypted repository. The prior 4a Cluster release is preserved
  as an explicit rollback; deployment adaptation failures exercised and passed
  that whole-pair restore path multiple times.
- The final reboot changed boot ID and recovered every enabled service plus
  `iso-a`, `iso-b` and `steward`. Audit/idempotency hashes and the exact five
  reconcile findings persisted. The private-bridge preflight exited zero,
  `clusterd` started once, and the boot had no `EADDRNOTAVAIL` or restart.
- Matrix PR #112 / issue #111 owns the accepted dogfood evidence and remaining
  independent review gate.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and PR #112.
2. Preserve Matrix runtime code `915c56c` and Cluster runtime code `94d80ba` as
   the exact deployed pair. Documentation-only successors do not move the pin.
3. Obtain independent review for Matrix PR #112 and Cluster PR #77. Do not
   self-merge or treat CI as that review.
4. Continue only the remaining explicit external gates: consented cross-being
   native delivery, fresh-host root authorization/private custody, governance
   approvals and final human cutover. Do not infer them from this host proof.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
