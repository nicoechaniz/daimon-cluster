# daimonmatrix host inventory and resource baseline (2026-07-31)

Evidence for issue #2 (M0). Collected on-host by compaii@daimonmatrix
(hermes-compaii@daimonmatrix incarnation). Commands are the exact bundle used;
results are redacted only where they would expose secrets (none required).

## 1. Command bundle

```bash
lscpu
free -m ; cat /proc/swaps
lsblk -d -o NAME,SIZE,TYPE,MODEL ; lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT
df -m /
uname -r ; systemd-detect-virt
ls /dev/kvm ; cat /proc/sys/user/max_user_namespaces
ip -4 addr show scope global ; ip route show default
ip -6 addr show scope global ; ip -6 route show
ip addr show dev <zt-interface> ; zerotier-cli info
which nft ufw iptables
apt-cache policy incus incus-client
ps -eo pid,comm,rss,%cpu,etimes,args --sort=-rss
du -sh <hermes-home> <venv> <agent-memory> ~/.tribe-bridge
time hermes --version
# CPU sampling: read /proc/<pid>/stat utime+stime (fields 14+15), sleep 10, re-read
time venv/bin/python memoryctl.py hybrid-pack --query "..." --limit 2 --threshold 0.4
systemctl show tribe-bridge-v1.service -p MainPID,ExecStart
uptime
```

## 2. Static inventory (captured)

| Area | Finding |
|------|---------|
| CPU | 6 vCPU, Intel Core Processor (Haswell, no TSX), 1 thread/core, KVM guest |
| RAM | 11,682 MiB total, ~830 MiB used by host stack, **no swap** (`/proc/swaps` empty, `swapon` absent) |
| Block | Single QEMU disk `sda` 100 GiB; `sda1` ext4 mounted `/` (99.9 GiB, 84.6 GiB free, 13% used); EFI partitions; **no second block device** |
| Kernel | 6.12.86+deb13-amd64 (Debian 13), virt = kvm, `/dev/kvm` present, `max_user_namespaces=46561` (unprivileged containers OK) |
| IPv4 | Public `144.217.95.152/32` (DHCP) on ens3; default via 144.217.88.1 |
| IPv6 | Single address `2607:5300:205:200::9f12/128`; `::/64` on-link route exists but **no routed prefix confirmed** (OVH requires explicit routing per extra address) |
| anyVPN | ZeroTier iface `ztuhfc4bvn` up, `10.10.20.69/24`, nwid e73d9f46f7b1405a; legion (.27) and oliva (.12) reachable per tribe-bridge ops |
| Firewall | **None installed** — no nftables/ufw/iptables tooling present (finding for issue #3) |
| Incus | Not installed; `incus`/`incus-client` 6.0.4-2+deb13u8 available in Debian 13 repos |

## 3. Measured stack baseline (representative Hermes/HMK/bridge)

Reference processes: this Hermes incarnation (kimi k3-256k session, 5.4 h uptime,
full context) and the tribe-bridge v1 broker (system service).

| Metric | Idle | Active turn | Burst |
|--------|------|-------------|-------|
| Hermes agent CPU | ~0% | 1.8% of 1 core (0.18 s CPU / 10 s window, sampled mid-turn) | bounded by tool runs; model latency dominates (I/O wait) |
| Hermes agent RSS | — | 288 MiB (live session, large context) | — |
| Tribe broker CPU | 0 jiffies / 10 s (~0%) | — | negligible (SQLite, single-digit ms ops) |
| Tribe broker RSS | 35 MiB | — | — |
| Hermes CLI startup | — | — | 0.48 s (`hermes --version`, warm) |
| HMK hybrid retrieval | — | — | 0.62 s per `hybrid-pack` query (remote embedding provider, no local model burst) |
| Load average | 0.06–0.35 (1/5/15 min) | — | — |

Disk footprint per embodiment (this host, real):

| Component | Size |
|-----------|------|
| hermes-home (skills, sessions, backups, plugins) | 568 MiB |
| agent-memory (HMK library.db + state) | 77 MiB |
| Python venv | 131 MiB |
| tribe-bridge repo + v1 dir + keys | ~32 MiB |
| Debian 13 container rootfs (typical) | ~500 MiB |
| **Total at birth** | **~1.3 GiB** |

Embedding inference is remote (nvidia provider), so no local multi-core burst;
local bursts are short Python/tool subprocesses.

## 4. Questions the issue asked, answered

- **Dedicated ZFS-suitable block device?** **No.** One QEMU disk, fully
  partitioned to ext4 root. → Ratifies ADR: Incus `dir` storage backend.
  Loop-backed ZFS rejected per ADR; revisit only if a real device is added.
- **Routed IPv6 prefix?** **No confirmed routed prefix.** Single /128 in use;
  /64 on-link route is not proof of routability. → Ratifies ADR: no public
  IPv6 per container in v1; host-managed private bridge + anyVPN ingress.

## 5. Cohort sizing (headroom: ≥25% RAM, ≥20% disk)

**RAM** binds first (host has no swap):

- Total 11,682 MiB; 25% headroom ⇒ ≤8,761 MiB committed overall.
- Host reserve (OS + broker + mirror + steward incarnation + restore ops):
  1,500 MiB ⇒ ~7,260 MiB for containers.
- At the draft budget 1.5 GiB/daimon: **4 daimons max** (6,144 MiB).
- Measured reality (~300 MiB RSS busy + headroom for tools/browser) suggests
  1 GiB/daimon is viable later: that would allow **7 daimons**. Keep 1.5 GiB
  for the pilot; tighten only with pilot measurements (ADR: budgets by
  measurement).

**Disk**: 84.6 GiB free; 20% headroom ⇒ ≤80.4 GiB committed; host reserve
10 GiB ⇒ ~70 GiB for containers. At 8 GiB/daimon (`dir` backend = full
copies): **8 daimons** — not binding.

**CPU**: not binding. Agents are model-latency I/O-bound (1.8% core active,
broker ~0%). 1 vCPU limit per container with burst is comfortable on 6 vCPU.

**Conclusion**:

- **Pilot cohort: 1–2 daimons** (M2) — trivially safe.
- **Max safe launch cohort: 4 daimons** at 1.5 GiB/8 GiB/1 vCPU each
  (RAM-bound), revisable upward to ~7 after pilot measurement.
- **Swap caveat**: the ADR budget includes 1 GiB swap per daimon, but the host
  has no swap at all. Either provision host-level zram (recommended: ~4 GiB
  zram, no disk cost, suits VPS) or drop the per-daimon swap budget in v1.

## 6. Reserved capacity

| Reserve | Amount | Rationale |
|---------|--------|-----------|
| Host OS + daemons | 1.0 GiB RAM | current ~0.8 GiB incl. this session |
| tribe broker + mirror v1 | 0.25 GiB RAM | measured 35 MiB × growth |
| Restore/backup operations | 0.25 GiB RAM + 10 GiB disk | SQLite online backup + verify |
| Headroom | 25% RAM / 20% disk | per issue acceptance criteria |

## 7. Security-relevant findings (input to issue #3)

- No firewall tooling installed; host exposes public IPv4 with services bound
  per-systemd config. The v1 broker binds loopback + anyVPN per design;
  ingress rules must be part of M1 hardening.
- `/dev/kvm` is present inside this guest — containers remain the isolation
  boundary; do not expose it to agent containers.
- ZeroTier interface is host-wide; per-container anyVPN identity needs
  TUN/CAP_NET_ADMIN per container (ADR restricts this by default — bridge
  design must reconcile).
