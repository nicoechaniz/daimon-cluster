# DM-083 resume checkpoint

Status: autonomous DM-083 integration is active. The authorized live
same-being session reached a real Matrix authority-epoch succession; issue #61
repins the exact repair for the retry defect found there.

Last reconciled: 2026-08-10.

## Exact state

- The prior executable Cluster baseline produced by PR #51 is `5cc2583`; it
  pinned the historical Matrix preparation commit `8145b4c` through V5.
- Matrix draft PR #112 now freezes the successor-retry candidate at
  `f0181f7117859f3f9cc4afc7dfbdaf9b06e74754`.
- Cluster issue #61 repins that exact dependency and verifies client config V2
  while treating runtime and retry semantics as opaque Matrix authority.
- A clean Python 3.13 environment installed Matrix directly from that Git pin,
  verified `direct_url.json` and MIT package metadata, then passed Cluster's
  lint, type, compile and complete test gates: 297 passed, 2 intentional skips.
- Matrix draft PR #112 / issue #111 owns the live dogfood. The predecessor
  candidate is deployed; this repaired candidate remains undeployed until its
  exact downstream and CI gates pass.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and draft PR #112.
2. Keep Matrix candidate `f0181f7117859f3f9cc4afc7dfbdaf9b06e74754`
   immutable while the downstream gate runs.
3. Complete Cluster issue #61: V7 remains only a hosting envelope, and both
   client config constants are checked without interpreting retry history.
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
