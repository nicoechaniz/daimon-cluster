# DM-083 resume checkpoint

Status: autonomous DM-055/DM-083 integration is active. The authorized live
same-being session reached a real Matrix authority-epoch succession; the next
exact repin closes the rolling-deadline conflict found while preparing a
post-commit peer-response-loss drill.

Last reconciled: 2026-08-11.

## Exact state

- The prior executable Cluster baseline produced by PR #51 is `5cc2583`; it
  pinned the historical Matrix preparation commit `8145b4c` through V5.
- Cluster main `5d3892e` contains issue #61 / PR #62 and pins the exercised
  successor-retry candidate `f0181f7`.
- Matrix PR #112 now freezes the peer-retry candidate at
  `c7c6e236ff59596dd596e69fcd46efbe0446ea69`.
- Cluster branch `dm055-peer-retry-clock` repins that exact dependency and
  continues to treat runtime and retry semantics as opaque Matrix authority.
- Matrix's complete local suite, deterministic generation, reproducible build
  and installed-wheel DM-055 smoke gate pass. Cluster's exact downstream and
  CI gates remain before deployment.
- Matrix PR #112 / issue #111 owns the live dogfood. The `f0181f7` predecessor
  remains deployed until this repaired pair passes those gates.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and PR #112.
2. Keep Matrix candidate `c7c6e236ff59596dd596e69fcd46efbe0446ea69`
   immutable while the downstream gate runs.
3. Complete the `dm055-peer-retry-clock` repin: V7 remains only a hosting
   envelope, and both client config constants are checked without interpreting
   retry history.
4. Record the resulting Cluster commit in Matrix issue #111 / PR #112. If the
   Matrix candidate changes afterward, repin and repeat; source similarity is
   not enough.
5. Deploy the exact pair under the recorded authorization and rollback plan;
   require byte-identical old-response replay, no duplicate event and
   successor-lane convergence.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
