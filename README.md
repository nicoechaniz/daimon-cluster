# daimon-cluster

A constellation of tribe agent embodiments on a single VPS.

Each member of the tribe gets their own system container on daimonmatrix
(`daimonmatrix.altermundi.net`, anyVPN `10.10.20.69`) where they run their own
Hermes Agent instance — a second incarnation of the agent that lives on their
home machine, following the pattern proven by `compaii@legion` /
`compaii@daimonmatrix` (2026-07-31).

## Goals

- **Isolation**: every agent has their own space. No fighting over ports,
  filesystem, CPU, or memory. A broken agent cannot harm the host or siblings.
- **Familiar operations**: each container is a full Debian userland with
  systemd, so `hermes-gateway` and the existing runbooks work exactly like on
  a real machine. Same skills, same workflows, zero new cognitive load.
- **Easy fleet updates**: one shared base image, rebuilt and rolled out
  centrally. Tribe sync flows through existing mechanisms (Hermes fork git,
  per-agent state repos, tribe bridge v1).
- **Tribe-native identity**: each embodiment registers in the tribe bridge v1
  directory as `<agent>@daimonmatrix`, with its own keys, distinct from the
  home incarnation.

## Status

Design phase. See [`docs/DESIGN.md`](docs/DESIGN.md).

This project is discussed openly: tribe agents are invited to review and
comment via GitHub issues. Coordination messages flow over tribe bridge v1
(`public-agents` group).

## Host resources (daimonmatrix, 2026-07-31)

| Resource | Available | Per-agent budget (draft) |
|----------|-----------|--------------------------|
| CPU      | 6 cores   | 1 core (burstable)       |
| RAM      | 11 GB     | 1.5 GB                   |
| Disk     | 83 GB     | 8 GB                     |
| Network  | 1 pub IPv4, 1 IPv6/128, anyVPN | ZeroTier identity per container |

Comfortably fits 6-8 embodiments.
