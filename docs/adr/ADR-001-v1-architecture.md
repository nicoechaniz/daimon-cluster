# ADR-001: daimon-cluster v1 architecture decisions

Status: RATIFIED (2026-08-01). Ratification path: delegated by Nicolás —
"conservative decisions that work for now, adjust later". The one recorded
deviation resolves conservatively: host-level zram (~4 GiB) in M1,
per-daimon swap budget dropped from v1 container budgets (zram is a host
safety net, not a per-tenant guarantee).
Evidence for issue #1. Authors: compaii@daimonmatrix (drafting),
compaii@legion (handover + prior endorsement of these directions with
Nicolás), codex@localhost (issue decomposition).

This ADR resolves every open question in PLAN §12 (5 questions) and
DESIGN §7 (6 questions), with the three overlaps resolved once and
cross-referenced.

Overlap map:

| PLAN §12 | DESIGN §7 | Topic | Resolved in |
|----------|-----------|-------|-------------|
| Q2 steward identity | Q1 compaii@daimonmatrix host vs container | steward + host residency | D2 |
| Q3 state repos | Q2 state repo topology | per-daimon state repos | D3 |
| Q5 zfs vs dir | Q3 storage backend | storage | D5 |

---

## D1 — Lease representation (PLAN Q1)

> **SUPERSEDED (2026-08-02, M10-R2).** The lease registry as identity
> authority is a retired misconception (`docs/design/ontology.md`). The
> embodiment registry (`docs/design/embodiment-registry.md`) is a CENSUS
> and sync directory, never an exclusion mechanism; the signed,
> governance-rooted, append-only properties decided below survive in it.

**Decision: ACCEPTED — dedicated signed lease registry, outside the
governance directory.**

Rejected alternatives:

- *Full governance epoch bump per move* (PLAN Q1 option A): legitimate but
  heavyweight; conflates identity governance with runtime state; every move
  would require the offline governance holder. Rejected.
- *Signed metadata field in the directory updated by the current governance
  holder* (PLAN Q1 option B, the PLAN's own proposal): still couples dynamic
  runtime state to the identity registry and forces directory re-issuance
  (or stale metadata) on every move. Rejected in favor of a separate
  registry whose trust root is the same governance key but whose cadence is
  operational, not constitutional.

Registry semantics (binding for M7):

- Record: `{identity, holder, state: awake|asleep|transitioning, generation,
  fencing_token (monotonic uint64), ttl_ms, updated_at, signature}`.
- Updates are **compare-and-swap** on `(identity, generation)`; a writer
  presenting a stale generation is rejected (`generation_conflict`).
- **Fencing**: every stateful operation by a lease holder carries the current
  `fencing_token`. The broker and transfer tooling reject any token lower
  than the last-seen token for that identity (**stale-writer rejection**) —
  this is what prevents a previously-awake body from acting after the flip.
- **TTL with explicit states**: `awake` leases must be renewed before TTL
  expiry; an expired lease degrades to `asleep`, never to ambiguity. A body
  that loses its lease mid-work stops accepting new work and parks itself.
- **Broker enforcement**: the tribe-bridge v1 broker consults the registry
  for direct-message delivery. Delivery to an `asleep` holder is **queued,
  not delivered**; delivery to `transitioning` is deferred until the state
  resolves; `awake` delivers normally. Registry reads are cached only for
  seconds and never override a fresher fencing token presented by a sender.
- **Failure posture**: conservative. A failed flip leaves the identity
  `asleep` everywhere — never awake twice. Humans wake it manually.
- Directory epoch bumps remain for identity/key/audience changes only.

Consequences: a new small service/table to build (M7, issues #27–#30) and a
broker hook; in exchange, park-and-pull becomes safe under crash and
split-brain conditions without governance-holder availability.

## D2 — Steward identity and host residency (PLAN Q2 + DESIGN Q1)

**Decision: ACCEPTED — dedicated `steward@daimonmatrix` identity without
Incus socket or host shell; Incus authority stays in a non-agent host
service account behind clusterd.**

- The steward receives **scoped clusterd API credentials only**. Its Hermes
  plugin talks to clusterd; clusterd (host service account) is the only
  actor holding the Incus socket.
- DESIGN Q1 resolved: **compaii@daimonmatrix stays on the host** for v1 as
  the resident incarnation (and initial steward persona while the dedicated
  identity is provisioned in M5, issue #21). It does NOT migrate into an
  agent container in v1; symmetry is sacrificed deliberately — the host
  needs a trusted operator incarnation, and making it just-another-container
  would either grant that container host authority (violating the boundary)
  or orphan operations.
- Mutation tools remain human-gated per PLAN §8 (no unattended mutation from
  cron ticks).

Consequences: M5 provisions a new directory identity (governance action,
needs Nicolás); the threat model (#3) must treat steward compromise as
scoped-credential compromise, not host compromise.

## D3 — State repositories (PLAN Q3 + DESIGN Q2)

**Decision: ACCEPTED — one private state repository per daimon identity.**
Exception: one per human where a single human owns several tightly coupled
identities. Never a shared branch-based repository.

Rationale: blast radius per identity, independent ACLs, clean rebirth
semantics (`/we.pull` already assumes one repo per identity), no cross-agent
branch contention. Consequences: slightly more repos to administer; the
onboarding ceremony (M8, #31) must include repo provisioning.

## D4 — Authentication (PLAN Q4)

**Decision: ACCEPTED — v1: anyVPN-restricted ingress + per-human scoped
bearer tokens; tribe-bridge v1 signed-request auth for agent callers
(reusing v1 verification code). Product phase: OIDC Authorization Code +
PKCE behind an adapter; provider selection deferred until that phase is
funded (owner: Nicolás).**

No deviation. Consequences: the auth adapter interface (issue #18) must be
designed so OIDC slots in without changing clusterctl/clusterd internals.

## D5 — Storage backend (PLAN Q5 + DESIGN Q3)

**Decision: ACCEPTED — Incus `dir` backend.**

Evidence: `docs/inventory/daimonmatrix-2026-07-31.md` §4 — the host has a
single 100 GiB QEMU disk fully allocated to ext4 root; no dedicated block
device exists. Loop-backed ZFS is rejected per the issue's own constraint.

Consequences (binding for PLAN §7 rewrite in issue #5): the snapshot table
changes — Incus `dir` snapshots are full copies, so hourly local snapshots
are replaced by **restic-only** point-in-time backups (daily, two off-host
targets) plus state-repo sync (6 h) as the fine-grained layer. RPO becomes
6 h worst case (state repos) with daily volume-level restic restore points.
This is recorded here so issue #5 does not re-derive it.

## D6 — Network (DESIGN Q4)

**Decision: ACCEPTED — host-managed private bridge; no public IPv6 per
container in v1; anyVPN-restricted ingress; no default `/dev/net/tun` or
`CAP_NET_ADMIN` in agent containers.**

Evidence: inventory §2 — only a single IPv6 /128 is confirmed; no routed
prefix. Unprivileged isolation is preserved: containers run with the default
unprivileged uid/gid mapping; the bridge is created and owned by the host;
containers receive veth pairs, not raw network devices.

Documented exception path: a container needing its own anyVPN identity
(requires `/dev/net/tun` + `CAP_NET_ADMIN`) is an explicit per-container
profile grant, recorded in the instance spec with a reason, denied by
default. In v1 the expected default is: containers reach the tribe broker
via the host's anyVPN address; direct per-container anyVPN identity is a
reviewed exception, not the baseline.

## D7 — Resource budgets (DESIGN Q5)

**Decision: ACCEPTED — pilot budget 1 vCPU / 1.5 GiB RAM / 8 GiB disk per
daimon; launch limits set from measurement.**

Evidence: inventory §3/§5 — measured Hermes RSS 288 MiB busy, 1.8% core
during an active turn, broker 35 MiB; pilot cohort 1–2 trivially safe; max
safe launch cohort **4 daimons** at the pilot budget with ≥25% RAM and ≥20%
disk headroom (RAM-bound).

**Deviation recorded (owner: Nicolás, evidence: inventory §5 swap caveat)**:
the ADR draft's 1 GiB swap per daimon is **unimplementable** — the host has
no swap at all. Resolution: provision host-level zram (~4 GiB) during M1
(issue #6) or drop the per-daimon swap budget in v1. Decision pends Nicolás
OK because it is a host-level change.

## D8 — Onboarding ceremony (DESIGN Q6)

**Decision: ACCEPTED — six separated roles:**

1. Tribe member requests (states desired identity + human sponsor).
2. Human sponsor confirms ownership of the identity.
3. Cluster owner (Nicolás) approves capacity.
4. Governance registers the identity (directory epoch bump — the ONLY
   governance touch in the flow).
5. Steward provisions (container, keys generated inside, scoped creds).
6. Member supplies their own private provider credentials (never shared,
   never Nicolás's keys).

Consequences: encoded as the M8 ceremony document (issue #31); the
steward's dashboard Create wizard (issue #25) must mirror these steps 1:1.

---

## Deviations register

| # | Deviation | Owner | Evidence | Resolution |
|---|-----------|-------|----------|------------|
| 1 | Per-daimon 1 GiB swap budget unimplementable (host has no swap) | Nicolás (delegated conservative call) | inventory §5 | host-level zram ~4 GiB (M1/#6); per-daimon swap dropped from v1 budgets |

All other scope resolutions are accepted without deviation.
