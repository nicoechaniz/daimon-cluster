# DM-083 resume checkpoint

Status: the DM-055/DM-083 runtime pair is host-qualified. Exact Cluster code
`94d80ba` pins exact Matrix code `915c56c`; local suites, Python 3.11–3.14 CI,
installed contract checks, rollback, encrypted backup/mirror and the final cold
host reboot all passed. The forward candidate adds the reviewed-stack gates for
a fresh embodiment plus a purpose-built-only second-mirror implementation. No
forward candidate is deployed; all remain unmerged pending independent review.
The local-only H10 successor now completes recovery-quorum rebirth and
canonical-event restore; it does not change the deployed pair.

Last reconciled: 2026-08-12.

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
- A separate authorized helper without ZeroTier resolved the host publicly and
  proved only public SSH reachable; Incus API, Tribe broker and clusterd public
  ports were closed. This completes the old M1 off-mesh ingress gap.
- Matrix PR #112 / issue #111 owns the accepted dogfood evidence and remaining
  independent review gate.
- The isolated integration merge `9591d44` combines H6 head `26fcfaf` with
  DM-055 PR head `b719cbb` (runtime code `94d80ba`) while pinning Matrix
  `915c56c`. Its clean Python 3.13 gate passed 436 tests with 2 skips, lint,
  type, compile, pin/license checks and real-storage H5/H6 drills. It is not
  deployed or independently reviewed.
- Matrix PR #116 publication predecessor
  `a58115895fb890db6dbae83d68b014352093868f` and Cluster PRs #80, #82 and #84
  through H9 head
  `ca65650a45331a7f313da97d1240eb4aacf383fd` form the
  root-authorized fresh-embodiment candidate. The current stack converges three
  local processes, keeps target custody separate, requires the closed
  predecessor acknowledgement set and passes Python 3.11–3.14 CI. It creates a
  new embodiment; it never copies an existing embodiment's custody or writable
  database.
- Matrix V0 candidate `96e9b112053b02e91d2f0f9add4b507c32058889` and this H10
  branch complete the
  local recovery-quorum Journey C. Every predecessor is revoked, exactly one
  fresh body is active, a source-verified custody-free bundle-plus-ledger
  transfer carries only canonical snapshot events across the boundary and a
  distinct restore journal gates first start. Full suites, deterministic
  installed conformance, crash retry, hostile snapshot refusal, a second
  disaster rebuild and a no-network multi-container role-separation journey
  with read-only snapshot transfer are green. Nothing was deployed or
  contacted remotely.
- Cluster PR #85 at `9e6100b` adds the second-mirror software boundary on top
  of H9. Its dedicated export identity, content-addressed disposable
  provisioning, atomic repository exchange and real encrypted offline restore
  pass `470 tests, 3 skips` plus all four CI versions. The adversarial Docker
  proof denies shell, TTY, forwarding, upload and path escape; revoking the key
  or deleting the export account preserves fresh synthetic administrative
  logins and an unchanged admin-key hash.
- PR #85 is not a deployment and does not select a second physical target.
  Mona is categorically excluded; prior Mona activity is incident evidence
  only. PR #86 carries the minimal administrative-access invariant and incident
  record directly against `main`; its CI is green and independent review is
  pending.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and PRs #112/#116.
2. Preserve Matrix runtime code `915c56c` and Cluster runtime code `94d80ba` as
   the exact deployed pair. Documentation-only successors do not move the pin.
3. Publish the H10 successors for independent review, then obtain review for
   Matrix PRs #112/#116, the Cluster stack through #84, H10, safety PR #86,
   mirror PR #85 and Tribe PR #61. Respect stack order; do
   not self-merge or treat CI as independent review.
4. Keep all mirror/export/restore rehearsals on local fixtures or purpose-built
   disposable infrastructure. Never contact Mona for discovery or proof.
5. Continue only the remaining explicit external gates: selecting an approved
   independent second target, root/recovery custody policy, exact same-plan GO,
   governance approvals and final human cutover. Do not infer them from
   synthetic qualification or SSH inventory.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
