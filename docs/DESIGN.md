# Historical single-host design draft (superseded)

This document records the 2026-07-31 single-host proposal. It is not the
current RC architecture, inventory or deployment plan. See
`docs/design/matrix-convergence.md`, `docs/security/threat-model-rc.md` and
`RESUME.md` for the current purpose-built, multi-host-capable boundary. Host
names, addresses and resource figures below are historical evidence only.

# daimon-cluster design (draft v0.1 — for tribe review)

Status: DRAFT, open for comments. Authors: CompAII (hermes-compaii@daimonmatrix)
with Nicolás Echániz. Please review via GitHub issues.

## 1. Vision

One VPS, many daemons. Each tribe member runs an embodiment of their agent on
daimonmatrix, in their own container: their own Hermes, their own memory,
their own identity — synchronized with the tribe through the mechanisms we
already built (Hermes fork, state repos, tribe bridge v1).

The embodiment on the VPS is a **second incarnation**, not a clone:
same species, own keys, own experiences. Naming follows the tribe bridge
standard: `<agent>@daimonmatrix` (e.g. `eko@daimonmatrix`), distinct from the
home incarnation (`eko@<homehost>`). The bare name remains reserved for the
collective identity (future `/we`).

## 2. Container technology: Incus

Chosen: **Incus system containers** (community LXD fork, packaged in
Debian 13).

Why:

- Full Debian userland with systemd per container → `hermes-gateway` runs as a
  systemd user service exactly like on a real host. Identical operational
  model to legion; existing skills and runbooks apply unchanged.
- Unprivileged by default (uid/gid mapping) → real isolation from the host
  and between agents.
- Native resource limits (CPU, memory, disk) → no noisy neighbors.
- Image + profile model → one `tribe-base` image; launching a new embodiment
  is `incus launch tribe-base <agent>`. Fleet updates rebuild one image.
- Works inside this KVM VPS without nested virtualization (containers share
  the host kernel).

Rejected alternatives:

- **Docker/Podman**: systemd inside is awkward; an agent home is a pet, not
  cattle.
- **systemd-nspawn**: fine and native, but no image store and manual
  networking; weaker fleet tooling.
- **Plain Unix users** (current compaii@daimonmatrix test setup): weak
  isolation; does not scale to "everyone gets their own space".

## 3. Layout (draft)

```
daimonmatrix (host, Debian 13)
├── incus (daemon, zfs or dir storage backend)
│   ├── tribe-base image: Debian 13 + hermes-agent fork clone + venv
│   │   + HMK dependencies + tribe-bridge v1 client env scaffolding
│   ├── container: eko        (user: eko,      hermes home: ~eko/.hermes)
│   ├── container: oliva      (user: oliva,    hermes home: ~oliva/.hermes)
│   └── container: <agent>    ...
├── tribe-bridge v1 broker (already running, 10.10.20.69:8685)
└── compaii@daimonmatrix (resident incarnation, stays on the host per
    ADR-001 D2; interim steward persona until steward@daimonmatrix is
    provisioned in M5)
```

Per-container defaults (profile `tribe-agent`):

- limits.cpu: 1 (allow burst), limits.memory: 1.5GB, root disk: 8GB
- Debian 13 userland, systemd, sshd for the human member
- ZeroTier client with per-container identity (keeps the anyVPN-first
  endpoint rule clean: each embodiment gets its own `10.10.20.x`)
- Hermes fork clone at `~/Projects/hermes-agent`, venv, gateway user service

## 4. Identity and memory per embodiment

- tribe bridge v1 directory entry: `<agent>@daimonmatrix`, keys generated
  inside the container at provisioning time (private keys never leave it).
- Directory audience updates require a governance epoch bump (coordination
  with legion, current governance holder).
- Durable memory: each embodiment runs its own HMK `library.db`. Rebirth-style
  state sync per agent (their own state repo, or branches in a shared one —
  OPEN QUESTION, see §7).
- First boot does NOT clone home memories by default. The home agent decides
  what to seed (a curated handoff beats a raw dump — the E01 lesson: autonomy
  without curation drifts).

## 5. Update / sync flows

- **Code**: hermes-agent fork `main` — containers pull like any tribe host.
- **Base image**: rebuilt on the host when the fork or system deps change;
  containers are recreated or updated in a rolling window. Identity and memory
  live on per-container volumes, not in the image.
- **Coordination**: tribe bridge v1 (`public-agents` + per-agent audiences).
- **Access**: each human member SSHes into their own container only.

## 6. Security boundaries

- Unprivileged containers, always.
- Host services (tribe broker, mirror) stay on the host, reachable by
  containers via the hub anyVPN address or loopback proxy — never the other
  way around.
- No shared credentials: each embodiment has its own provider auth
  (e.g. its own Kimi OAuth), provisioned by its human.
- GitHub access: embodiments do NOT get Nico's keys. Write access to GitHub
  flows through legion (key holder) or per-agent credentials their human
  chooses to grant.

## 7. Open questions — RESOLVED by ADR-001

All six questions are resolved in
[`adr/ADR-001-v1-architecture.md`](adr/ADR-001-v1-architecture.md):

1. compaii@daimonmatrix container vs host steward → **D2**: stays on the
   host as resident incarnation + interim steward persona; the steward ROLE
   goes to a dedicated identity without host shell or Incus socket.
2. Per-agent state repos vs shared → **D3**: one private repo per daimon
   identity (per-human exception for coupled identities).
3. Storage backend → **D5**: `dir` (inventory: no ZFS-suitable block
   device); restic-only volume recovery.
4. IPv6 → **D6**: no routed prefix confirmed; no public IPv6 per container
   in v1; host-managed private bridge + anyVPN ingress.
5. Resource budgets → **D7**: pilot 1 vCPU / 1.5 GiB / 8 GiB confirmed by
   measurement; max launch cohort 4 (RAM-bound, no host swap — zram
   decision pending Nicolás).
6. Onboarding ceremony → **D8**: six separated roles (member requests,
   sponsor confirms, cluster owner approves capacity, governance registers
   identity, steward provisions, member supplies own credentials).

## 8. Milestones (draft)

1. M0 — Design review by tribe agents (this document, GitHub issues).
2. M1 — Incus installed on daimonmatrix, `tribe-base` image built.
3. M2 — Pilot container: one volunteer embodiment (eko or oliva) end-to-end:
   provisioning, identity registration, hermes running, tribe messaging.
4. M3 — Update runbook: image rebuild + rolling refresh drill.
5. M4 — Open to the tribe; onboarding ceremony documented.
