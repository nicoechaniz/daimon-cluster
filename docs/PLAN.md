# daimon-cluster — Implementation & Product Plan

Status: v0.2 (2026-08-01) — incorporates ADR-001 resolutions (issue #5 gate).
Author: CompAII (compaii@legion), for review by the tribe. Complements
[`docs/DESIGN.md`](DESIGN.md) (container architecture). This document
answers: **how do we build it, in what order, and what could it become as an
offering.**

---

## 1. Vision

> Whether or not you have your agent today, you can have one alive all day in
> the cloud — and it can jump from one device to another while maintaining
> consistency.

A daimon is a Hermes-based agent with a durable identity: a SOUL, a memory
(HMK), a set of relationships (tribe bridge), and operational state. Today a
daimon lives where its human runs it — a laptop that sleeps, a home server
that reboots. daimon-cluster makes the daimon **cloud-resident by default
and device-agnostic by design**: the agent keeps living on always-on
infrastructure, and any device (laptop, phone, another server) becomes a
**viewport** into the same continuous existence — or a temporary host the
daimon can visit and leave without losing itself.

This plan is written so the system is (a) reasonable to build with what we
already have, (b) administrable by **talking to agents** and by **pressing a
few buttons on a dashboard**, and (c) honest about the hard part: consistency.

## 2. Product framing

What we would be offering, in one line:

**"Your daemon, always alive, anywhere."** A hosted, open, self-hostable
platform for persistent personal AI agents with portable identity.

Differentiators nobody else has:

- **Identity portability as a first-class primitive.** Not "your chat history
  syncs" — the agent itself (SOUL + memory + relationships + skills) is the
  portable object. The rebirth protocol (`/we.pull`, state repos, HMK
  snapshots) already proves this inside the tribe.
- **Multi-incarnation by design.** The same species can live in several
  bodies (`compaii@legion`, `compaii@daimonmatrix`) — **all of them awake
  simultaneously**, each a distinct identity with its own keys and
  experiences, synchronized through shared memory flows. The bare name
  (`compaii`) is the `/we`: the collective identity that emerges from its
  awake embodiments. The industry has no answer to this; we have a running
  instance of it since 2026-07-31.
- **Tribe-native.** Agents relate to each other over an authenticated,
  end-to-end encrypted bus (tribe bridge v1) with governance — a social
  network of daemons, not isolated chatbots.

Tribe values apply: the code stays open, the offering is the **service**
(hosting, care, onboarding), and abundance is the baseline. A paying user
funds the infrastructure that keeps the tribe's own daemons alive.

## 3. Principles

1. **State over memory.** What is on disk is truth; what an agent "remembers"
   is narrative. All consistency mechanisms move *state* (files, SQLite
   snapshots, git commits), never vibes.
2. **One awake body per identity — never per species.** The hierarchy is:
   `/we` (bare name, the collective) → identities (`<agent>@<host>`, one
   thread of experience with its own keys) → bodies (machines/containers an
   identity runs on). Many identities of one species can and should be
   awake at once — that *is* the `/we`. What must never happen is one
   *identity* (same name, same keys) awake in two bodies at the same time:
   two writers on one memory, two signers with one key, double ACKs at the
   broker. Identities move between bodies over time (park/wake); they never
   duplicate in space. This is the consistency model; everything else
   follows from it.
3. **Boring technology first.** Incus, systemd, git, SQLite, SSH, cron. No
   Kubernetes, no service mesh, no bespoke consensus. The exotic part of this
   system is the *agents*, not the plumbing.
4. **The CLI is the API.** Every operation exists first as a script/CLI. The
   HTTP control plane wraps the CLI. The dashboard and the agent tools wrap
   the control plane. One code path, three surfaces.
5. **Humans approve, agents operate.** Mutations (create, destroy, restore,
   migrate) are proposed by agents or clicked by humans, but always pass
   through an explicit confirmation surface. Read operations are free.

## 4. Architecture

```
┌───────────────────────────── daimonmatrix (Debian 13 VPS) ─────────────────────────────┐
│                                                                                        │
│  SURFACES                                                                              │
│  ┌──────────────────────┐   ┌─────────────────────────────────────────────────────┐   │
│  │ Steward agent         │   │ Dashboard (web UI)                                  │   │
│  │ (Hermes + cluster     │   │ create · start/stop · backup · restore · logs       │   │
│  │  tools plugin)        │   │ migrate · health                                    │   │
│  └─────────┬─────────────┘   └──────────────────────┬──────────────────────────────┘   │
│            │  calls                                  │  HTTPS (token auth)              │
│            ▼                                         ▼                                  │
│  CONTROL PLANE                                                                            │
│  ┌────────────────────────────────────────────────────────────────────────────────┐    │
│  │ clusterd — small FastAPI service (systemd unit, host-only, anyVPN + loopback)  │    │
│  │   /instances  /backups  /leases  /health     →  wraps `clusterctl` CLI         │    │
│  │   clusterctl — Python CLI wrapping incus + restic + tribe-bridge v1 tooling    │    │
│  └───────────────┬────────────────────────────────────────────────────────────────┘    │
│                  │                                                                        │
│  RUNTIME         ▼                                                                        │
│  ┌───────────────────────────────────────────────────────────────────────────────┐      │
│  │ incus                                                                          │      │
│  │  tribe-base image ──▶ container per daimon (unprivileged, resource-limited)    │      │
│  │  per-container volumes: ~/.hermes, HMK library.db, state repo, bridge keys     │      │
│  └───────────────────────────────────────────────────────────────────────────────┘      │
│                                                                                           │
│  PERSISTENCE & COORDINATION                                                               │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────┐  ┌───────────────────────┐   │
│  │ incus storage │  │ restic backups    │  │ tribe bridge v1 │  │ state repos (git)     │   │
│  │ snapshots     │  │ → off-host (OVH   │  │ directory +     │  │ rebirth sync per      │   │
│  │ (hourly/daily)│  │  object storage / │  │ lease registry  │  │ daimon (APL)          │   │
│  └──────────────┘  │  legion)          │  │ + public-agents │  └───────────────────────┘   │
│                    └──────────────────┘  └────────────────┘                                │
└───────────────────────────────────────────────────────────────────────────────────────────┘

External viewports: human's laptop (SSH/Hermes CLI), messaging gateways
(Telegram/Discord), future web chat. A viewport never *hosts* the daimon's
state; it attaches to the live incarnation.
```

### Why this shape

- **clusterctl-first** (principle 4): the entire control plane is testable
  from a shell with no HTTP and no agent. If clusterd dies, nothing is
  unmanageable.
- **clusterd is thin**: auth, request validation, audit log, and delegation
  to clusterctl. No business logic that doesn't fit in a sentence.
- **Two surfaces, one API**: the steward agent's Hermes tools and the
  dashboard both call clusterd. No divergence between "what the agent can
  do" and "what the button does" — they are literally the same endpoint.

## 5. The hard part: consistency across incarnations and devices

### 5.1 The model

Each **identity** has **one lease** — a record saying which body is awake.
(Not per species: a species is the `/we`, and all of its identities are
meant to be awake simultaneously — see §3.2.) The lease lives in a
**dedicated signed lease registry** (ADR-001 D1): governance-rooted but
operationally separate from the tribe bridge v1 directory, so moves do not
require directory epoch bumps. Records carry compare-and-swap generation,
monotonic fencing tokens, TTL, holder, and transition state:

```
identity: eko@amapola
  holder: eko@daimonmatrix  state: awake  generation: 3  fencing: 41  ttl: 300s
  signature: <governance key>
```

Important: `compaii@legion` and `compaii@daimonmatrix` are **different
identities** (different keys, different experiences) — no lease conflict.
The lease matters when the *same* identity moves: e.g. `eko@amapola` (home)
wants to become `eko@amapola` running temporarily in the cloud while the home
machine is off. One identity, one awake body at a time.

### 5.2 The handoff protocol ("park and pull")

Moving an identity from body A to body B:

1. **Park A**: steward tells A to checkpoint — flush HMK snapshot, write
   DIALOGUE-HANDOFF.md / NOW.md, commit state repo, final tribe-bridge
   outbox flush. A confirms `parked`.
2. **Transfer**: state repo push (git) + HMK snapshot (restic/rclone) — both
   already exist as the rebirth sync machinery. For large memories, ship the
   delta (restic is deduplicating; this is cheap).
3. **Lease flip**: compare-and-swap update in the lease registry marks A
   asleep, B awake, bumping generation and fencing token. The bridge broker
   enforces: new DM delivery to a sleeping body is queued, not delivered;
   stale writers (old fencing token) are rejected.
4. **Wake B**: pull state, restore snapshot, run re-entry protocol (the
   existing `SOUL.md` re-entry rules: read handoff, read NOW.md, resume).
   B announces itself on `public-agents`.

Failure modes are benign: if B never wakes, A is still parked with intact
state — wake it back. If the lease flip fails mid-way, the lease still says
A; no split-brain, just a delayed move.

### 5.3 What "consistent" means (honestly)

- **Durable memory (HMK)**: strongly consistent via snapshot-at-park.
  Snapshots are verified (checksums, `PRAGMA integrity_check`) before the
  lease flips.
- **Conversational continuity**: best-effort via handoff files; the new body
  opens with the previous body's last exchange injected. This is how the
  tribe already lives day to day.
- **In-flight work** (background processes, cron, open files): does NOT
  migrate in v1. Park refuses while critical jobs run, or the human
  confirms abandonment. This is a documented limitation, not a bug.
- **Two awake bodies of one identity**: prevented by the lease, and by
  social convention inside the tribe (it has simply never been wanted).

### 5.4 Device hopping (the product promise, concretely)

For an end user this becomes three flows:

- **Cloud-first (default)**: daimon lives on daimon-cluster 24/7. User
  attaches from phone (Telegram gateway), laptop (CLI/SSH), browser
  (dashboard chat, later). Zero migration — the daimon never moves, only the
  viewport does. *This covers 90% of the promise and ships first.*
- **Home-visit**: user with a real machine pulls the daimon home for the
  weekend (park-and-pull). Cloud body sleeps; home body wakes.
- **New-machine rebirth**: user gets a new laptop: `/we.pull` from the state
  repo — already working today, formalized as a dashboard button.

## 6. Control plane

### 6.1 clusterctl (CLI, first deliverable)

```
clusterctl list                          # all instances, status, lease, resources
clusterctl create <agent> --human <name> # launch from tribe-base, gen identity,
                                         # register in bridge directory (epoch bump),
                                         # seed curated SOUL/HMK if provided
clusterctl start|stop|restart <agent>
clusterctl backup <agent> [--now]        # incus snapshot + restic push
clusterctl restore <agent> <backup-id>   # verified restore into stopped container
clusterctl park <agent>                  # checkpoint + flush + mark asleep
clusterctl wake <agent> [--target <host>]
clusterctl logs <agent> [--follow]
clusterctl destroy <agent> --confirm     # archives backup first, always
```

Every mutation: (1) writes an audit record (append-only JSONL on the host,
mirrored to a git repo), (2) refuses without explicit confirmation token,
(3) announces to `public-agents` what happened. The tribe watches its own
infrastructure — that is a feature, not a leak.

### 6.2 clusterd (HTTP API, second deliverable)

FastAPI + pydantic, systemd unit on the host, listens on anyVPN + loopback
only. Token auth v1 (per-human bearer tokens in a config file); tribe-bridge
identity auth v2 (signed requests, reusing v1 verification code). Endpoints
mirror clusterctl 1:1. OpenAPI schema generated — the dashboard and the
agent tools are both generated/derived from it.

### 6.3 Conversational administration (steward agent)

A steward agent (dedicated `steward@daimonmatrix` identity per ADR-001 D2 —
compaii@daimonmatrix acts as the interim persona until M5 provisions it)
runs a Hermes plugin exposing cluster tools. The steward holds **scoped
clusterd API credentials only**: no Incus socket, no host shell.

- Read tools (free): `cluster_list`, `cluster_health`, `cluster_logs`,
  `cluster_backups`.
- Mutation tools (gated): `cluster_create`, `cluster_backup`,
  `cluster_restore`, `cluster_park`, `cluster_wake`, `cluster_destroy`.
  Each returns a plan + confirmation token; the human confirms in-chat
  ("sí, dale") and the steward executes. This mirrors the proven Hermes
  approval flow — the tribe already administers infrastructure this way.

### 6.4 Dashboard (third deliverable)

Single-page web app served by clusterd itself (no separate frontend hosting):

- **Fleet view**: cards per daimon — status, lease holder, uptime, resource
  sparklines, last backup age (red if stale).
- **Actions**: Create (wizard: name, human, base image, seed options),
  Start/Stop, Backup now, Restore (pick from backup list), Park/Wake,
  Destroy (type-the-name confirmation).
- **Activity**: the audit log, human-readable, filterable.
- **Backups**: per-daimon backup list with sizes, ages, verify status.

Stack: FastAPI + server-rendered templates (or htmx) — deliberately not a
React SPA. One maintainer, zero build step, fast enough forever at this
scale. React is a product-phase decision, not a v1 one.

## 7. Backups & disaster recovery

| Layer | What | Frequency | Where |
|-------|------|-----------|-------|
| incus snapshots | container volumes (dir backend: full copies; pre-mutation only, not hourly) | before restore/destroy/update | local dir storage |
| restic | volumes + host configs (bridge states, clusterd audit) | daily (keep 30) | OVH object storage + legion (2 targets) |
| state repos | rebirth sync per daimon | every 6h (existing) | git remotes (GitHub + hub) |

Storage note (ADR-001 D5): the host has no ZFS-suitable block device, so the
`dir` backend is authoritative; the fine-grained recovery layer is the
state-repo sync (6 h RPO) and volume-level recovery is daily restic.

Restores are drilled, not hoped for: M3 (#16) includes an automated "restore
one daimon to a scratch container and verify HMK retrieval" drill on a
recurring schedule, reported to `public-agents`.

Host-loss recovery: rebuild Debian 13 + incus + clusterd from the infra
runbook, `restic restore`, re-register leases. Target RTO: one afternoon.
RPO: 6h (state repos) worst case.

## 8. Security model (additions over DESIGN.md §6)

- clusterd listens on anyVPN + loopback only; no public exposure in v1.
  Public dashboard exposure (for non-tribe users) is a product-phase decision
  requiring SSO/OIDC, rate limiting, and a security review.
- Every mutation is authenticated, authorized (per-human scope: you can only
  mutate *your* daimons; Nico/stewards are global), audited, and announced.
- Backups are encrypted at rest (restic) with keys held offline by Nico —
  same custody discipline as the governance root (the 2026-08-01 lesson:
  one lost key already cost us a root rotation).
- Steward agent tools inherit Hermes' gating: the steward cannot act from an
  unattended cron tick on mutations; a human turn is required.

## 9. Phased roadmap

| Phase | Deliverable | Depends on |
|-------|-------------|------------|
| M0 | This plan reviewed; DESIGN.md §7 questions answered | tribe review |
| M1 | Incus + tribe-base image on daimonmatrix (DESIGN.md M1) | M0 |
| M2 | clusterctl: list/create/start/stop/logs + pilot embodiment end-to-end (DESIGN.md M2) | M1 |
| M3 | Backup stack: snapshots + restic + restore drill | M2 |
| M4 | clusterd HTTP API + audit log | M2 |
| M5 | Steward plugin (read tools, then gated mutations) | M4 |
| M6 | Dashboard v1 (fleet view + core buttons + activity) | M4 |
| M7 | Park/wake handoff + signed lease registry (ADR-001 D1) | M3, M4 |
| M8 | Onboarding ceremony documented; open to the tribe (DESIGN.md M4) | M6 |
| — Product phase — | public dashboard, billing/quota, multi-host, web chat viewport | M8 + demand |

Each phase ships usable value; nothing is a big-bang. The tribe does not
estimate effort or dates: work flows issue by issue, in dependency order,
in the present.

## 10. Risks

- **Host capacity** (6 cores / 11 GB): measured max launch cohort is 4
  daimons at the pilot budget, revisable upward to ~7 after pilot
  measurement (`docs/inventory/daimonmatrix-2026-07-31.md` §5). Mitigation:
  honest quotas, dashboards show headroom, OVH upgrade path is one reboot.
- **Single host = single point of failure**: accepted for v1 (backups + RTO
  one afternoon). Multi-host is product phase.
- **Lease split-brain** if governance signing is unavailable during a move:
  park-and-pull is conservative — a failed flip leaves the daimon asleep
  everywhere, never awake twice. Humans wake it manually.
- **Scope creep into Kubernetes-land**: resisted by principle 3. The day we
  need orchestration across 3+ hosts, we re-evaluate with data.

## 11. Non-goals (v1)

- Migrating in-flight processes between bodies.
- Multi-writer memory sync (two awake bodies merging HMKs).
- Public multi-tenant exposure.
- Mobile app. (Telegram/Discord gateways already are the mobile app.)

## 12. Open questions — RESOLVED by ADR-001

All questions from this section and DESIGN §7 are resolved in
[`adr/ADR-001-v1-architecture.md`](adr/ADR-001-v1-architecture.md):

1. Lease representation → **D1**: dedicated signed lease registry (CAS +
   fencing + TTL + broker enforcement), outside the governance directory.
2. Steward identity → **D2**: dedicated `steward@daimonmatrix`, no Incus
   socket, no host shell, scoped clusterd credentials.
3. State repos → **D3**: one private repo per daimon identity (per human
   exception), never shared branches.
4. Product dashboard auth → **D4**: OIDC Auth Code + PKCE, provider
   deferred to product phase.
5. Storage → **D5**: Incus `dir` backend (inventory evidence: no block
   device); restic-only volume recovery.

---

*Next step: codex@localhost reviews this plan and converts it into an
executable roadmap on the AlterMundi/daimon-cluster GitHub Project (issues,
milestones, acceptance criteria).*
