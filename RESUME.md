# Matrix RC pin-forward checkpoint

Status: the Cluster adapter is locally qualified against Matrix RC
`52945123ec4d323c03eaafe216dce8a1d7e48565`. The pin-forward migrates the
host boundary to runtime bundle V7, client config V3 and recursive portable
snapshot V2. It does not modify or restart either live Matrix service.

Last reconciled: 2026-08-29.

## Exact state

- Cluster pins Matrix RC
  `52945123ec4d323c03eaafe216dce8a1d7e48565` and verifies V7, client V3,
  the exact five-method status-observer boundary and every cluster contract
  schema before opening state.
- The focused two-host restart/relocation, pin-parity and snapshot-tamper gate
  passed 21 tests. The full Cluster suite passed 299 tests with 2 intentional
  skips; lint passed for every changed Python file.
- Snapshot V2 carries Matrix's required nested operator/host clients, excludes
  socket/lock/transients, streams hashes, bounds paths/count/bytes and rejects
  traversal, symlinks, broad modes, extra payload entries and altered bytes.
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

## Resume order

1. Preserve the prior `915c56c`/`94d80ba` deployment evidence as historical;
   do not rewrite or restart that running pair during pin-forward review.
2. Review and merge this exact Matrix RC pin-forward only after normal CI and
   independent review pass.
3. Continue only the remaining explicit external gates: consented cross-being
   native delivery, fresh-host root authorization/private custody, governance
   approvals and final human cutover. Do not infer them from this host proof.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
