# DM-083 resume checkpoint

Status: repository integration resumed for the frozen DM-083 candidate. Live
effects remain owned by the separately authorized Matrix DM-083 runbook.

Last reconciled: 2026-08-10.

## Exact state

- The prior executable Cluster baseline produced by PR #51 is `5cc2583`; it
  pinned the historical Matrix preparation commit `8145b4c` through V5.
- Matrix draft PR #112 now freezes the DM-083 V7 candidate at
  `bcf6b9f6ef5a46fdd35dfc8036a7a4d458103c7b`.
- Cluster issue #57 repins that exact dependency and advances host-envelope
  checks through V7 without interpreting peer topology, sync or adoption.
- A clean Python 3.13 environment installed Matrix directly from that Git pin,
  verified `direct_url.json` and MIT package metadata, then passed Cluster's
  lint, type, compile and complete test gates: 292 passed, 2 intentional skips.
- Matrix draft PR #112 / issue #111 owns the bounded two-host dogfood and its
  explicit human gate. No DM-083 host preflight or effect has run.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and draft PR #112.
2. Keep Matrix candidate `bcf6b9f6ef5a46fdd35dfc8036a7a4d458103c7b`
   immutable while the downstream gate runs.
3. Preserve the completed Cluster issue #57 gate: V7 is accepted only as a
   hosting envelope and every public schema constant is checked.
4. Record the resulting Cluster commit in Matrix issue #111 / PR #112. If the
   Matrix candidate changes afterward, repin and repeat; source similarity is
   not enough.
5. Continue into the Matrix-owned DM-083 preflight only under its recorded
   operator authorization, backups, stop conditions and rollback plan.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
