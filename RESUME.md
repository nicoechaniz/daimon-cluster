# DM-083 resume checkpoint

Status: intentionally paused at repository preparation. This file authorizes no
host access, deployment, service restart, message, route, key, storage, fence
or lifecycle effect.

Last reconciled: 2026-08-06.

## Exact state

- Cluster `main` is `5cc2583`, produced by PR #51.
- That release pins Matrix `8145b4c` in `requirements-weave.txt`, accepts
  runtime bundles V1 through V5, and passed its synthetic installed-process
  gate.
- Matrix DM-082 then merged at `dad012d` and added relationship/grant runtime
  bundle V6 plus the complete local relationship-to-encrypted-message journey.
- Therefore the current Cluster pin is valid historical preparation but is not
  the candidate for live DM-083. Issue #52 owns the required repin.
- Matrix draft PR #112 / issue #111 owns the bounded two-host dogfood and its
  explicit human gate. No DM-083 host preflight or effect has run.

## Resume order

1. Read Matrix `RESUME.md`, issue #111 and draft PR #112.
2. Wait until one immutable post-DM-082 Matrix candidate is named.
3. Implement Cluster issue #52: update the exact full Git pin, accept V6 only
   as a hosting envelope, verify every public schema constant, and run the
   source plus installed-process compatibility suite.
4. Record the resulting Cluster commit in Matrix issue #111 / PR #112. If the
   Matrix candidate changes afterward, repin and repeat; source similarity is
   not enough.
5. Stop after repository verification. Read-only host preflight and every live
   effect still require the exact operator authorization specified by DM-083.

Cluster owns bodies, storage, lifecycle, deployment evidence and concrete
resource fences. Matrix alone owns being/relationship/grant authority,
canonical ledgers, `/me`, `/we`, adoption and communication semantics. Tribe
Bridge ACKs remain separate transport evidence.

The only identified chat-facing Tribe repository is
`nicoechaniz/tribe-bridge`; no separate `tribe-chat` repository was found in
the recorded project set.
