# M1 acceptance tests — isolation, resources, containment (issue #9)

Executed 2026-08-01 on daimonmatrix by compaii@daimonmatrix.
Test subjects: `iso-a` (10.105.93.211), `iso-b` (10.105.93.193), both
launched from `tribe-base/2026-08-01.1` with profile `tribe-agent`
(+ durable volumes `iso-a-home`, `iso-b-home`). All tests reproducible
with the commands below. Host services (tribe broker v1, SSH, ZeroTier)
health-checked after every destructive test.

## Results matrix (threat-model tests assigned to M1)

| # | Test | Command (essence) | Result |
|---|------|-------------------|--------|
| T1 | sibling TCP isolation | `iso-a: </dev/tcp/10.105.93.193/22` | denied ✓ |
| T1b | sibling ICMP after port_isolation | `iso-a: ping iso-b` | denied ✓ — see finding F4 |
| T2 | host boundary: incus API | `iso-a: </dev/tcp/10.105.93.1/8443` | denied ✓ (also: incus API is unix-socket only, containers have no socket access — B4) |
| T2b | host boundary: SSH | `iso-a: </dev/tcp/10.105.93.1/22` and via anyVPN addr | denied ✓ (#6) |
| T2c | explicit services reachable | DNS via bridge, broker `http://10.10.20.69:8685/v1/health` | HTTP 200 ✓ |
| T3 | process pressure | spawn 700 background sleeps | `fork: Resource temporarily unavailable` at pids cap (limits.processes=512) ✓ contained |
| T4 | memory pressure | python allocating 200MB blocks in loop | process killed by cgroup OOM inside container; host free RAM never <1.5GB, iso-b unaffected, broker healthy ✓ contained |
| T5 | disk fill | `dd 2GiB` into durable volume, delete | host free disk unchanged (77G) ✓ — hard quota absent by recorded deviation (#8 §4), alert-based instead |
| T6 | egress still works | `curl deb.debian.org` | HTTP 200 ✓ |
| T7 | no usable TUN | `ip tuntap add` | Operation not permitted ✓ (ADR D6) |
| T8 | no host devices | `/dev/kvm`, `/run/incus` | absent ✓ (B4) |

### Finding F4 (fixed during the test run)

The nftables forward-drop for `incusbr0→incusbr0` (#6) does NOT isolate
siblings: same-bridge traffic is switched at L2 and never traverses the
FORWARD hook (no br_netfilter). Correct mechanism applied:
`security.port_isolation=true` on the `tribe-agent` eth0 device
(verified: sibling ping denied, egress and explicit services unaffected).
The nftables rule stays as defense-in-depth for routed cases.

## Resource capture vs M0 baseline

- Per-container idle footprint with tribe-base rootfs: **~93 MiB RSS
  (processes), 1.63 GiB rootfs disk**.
- Cohort check (inventory §5 method): 4 daimons × 1.63 GiB rootfs = 6.5 GiB
  + durable volumes ≪ 70 GiB container budget; 4 × 1.5 GiB RAM budget = 6 GiB
  ≤ 7.26 GiB container budget with 25% headroom. **Profile supports the
  calculated launch cohort (4) with host headroom reserved.** Measured idle
  RSS suggests real usage well under budget — supports revising cohort up
  after pilot (per ADR D7 "budgets by measurement").

## Pending: host reboot drill

Acceptance criterion "after host reboot, test container and required host
services reach the documented state" requires rebooting daimonmatrix —
that interrupts the tribe broker v1 hub, this incarnation, and any active
bridges. Per the standing rule (no disruption of running host Tribe
services without explicit approval) the drill is staged but NOT executed:

- Services enabled at boot (verified via `systemctl is-enabled`): incus,
  nftables, zramswap, tribe broker (existing unit), ssh, zerotier.
- Boot-order verified by design: nftables (sysinit) loads before incus adds
  its NAT table; my config only `destroy`s its own table — coexistence
  proven live across `systemctl restart incus` (#6).
- Expected post-reboot state documented in the M1 runbook.

Drill executes the moment Nicolás approves a reboot window; iso-a/iso-b
are left running as the drill subjects.
