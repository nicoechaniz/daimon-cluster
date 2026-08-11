# DM-083 resume checkpoint

Status: autonomous DM-055/DM-083 integration is active. The authorized live
same-being session reached a real Matrix authority-epoch succession and the
first full-host reboot restored every enabled service. The next exact repin
closes both the rolling-deadline retry conflict and the missing least-authority
host-status capability exposed by those live gates.

Last reconciled: 2026-08-11.

## Exact state

- The prior executable Cluster baseline produced by PR #51 is `5cc2583`; it
  pinned the historical Matrix preparation commit `8145b4c` through V5.
- Cluster main `5d3892e` contains issue #61 / PR #62 and pins the exercised
  successor-retry candidate `f0181f7`.
- Matrix PR #112 now freezes the reboot/status candidate at
  `915c56c8899fd53d683bd7c7c81c3465b600bed9`.
- Cluster branch `dm055-peer-retry-clock` repins that exact dependency and
  continues to treat runtime and retry semantics as opaque Matrix authority.
- Matrix's complete local suite and generated evidence pass. A clean Cluster
  environment verified the exact Git install and MIT metadata, then passed 298
  tests with 2 intentional skips plus lint, type and compile gates. CI and the
  installed reboot/status round trip remain before this pair can replace the
  currently deployed `c7c6e23` candidate.
- Matrix PR #112 / issue #111 owns the live dogfood.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and PR #112.
2. Keep Matrix candidate `915c56c8899fd53d683bd7c7c81c3465b600bed9`
   immutable while the downstream gate runs.
3. Complete CI for the `dm055-peer-retry-clock` repin. V7 remains only a
   hosting envelope, and the client config/status-observer contracts are
   checked without interpreting retry history or Matrix custody.
4. Record the resulting Cluster commit in Matrix issue #111 / PR #112. If the
   Matrix candidate changes afterward, repin and repeat; source similarity is
   not enough.
5. Deploy the exact pair under the recorded authorization and rollback plan;
   provision the distinct host-local status client, require authenticated
   `/v1/weave/status`, then repeat the reboot persistence gate.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
