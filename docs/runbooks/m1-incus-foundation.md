# Runbook: M1 Incus storage and network foundation (issue #6)

Host: daimonmatrix (Debian 13, kernel 6.12.86+deb13-amd64).
Executed 2026-08-01 by compaii@daimonmatrix. Reproducible from a clean host
with the commands below. Pinned package versions in §6.

## 1. Install

```bash
sudo DEBIAN_FRONTEND=noninteractive apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y incus nftables zram-tools
sudo systemctl enable --now incus
```

## 2. Incus init — dir backend, private bridge, IPv4-only NAT

```bash
sudo incus admin init --auto            # dir pool "default" + incusbr0 NAT
sudo incus network set incusbr0 ipv6.address none   # ADR-001 D6: no v6 per container
```

Result (verified): pool `default` driver `dir` at
`/var/lib/incus/storage-pools/default`; `incusbr0` = 10.105.93.1/24 NAT;
containers unprivileged (uid_map 0→1000000), no /dev/kvm, no /run/incus.

## 3. Host swap safety net — zram (ADR-001 D7 deviation resolution)

```bash
# configs/zramswap -> /etc/default/zramswap  (ALGO=zstd, SIZE=4096, PRIORITY=100)
sudo cp configs/zramswap /etc/default/zramswap
sudo systemctl enable --now zramswap.service
```

Verified: `/dev/zram0` ~5.7 GiB swap, priority 100 (zram-tools sizes per
device generously; actual compressed footprint is load-dependent).
Per-daimon swap is NOT part of v1 container budgets (ADR-001).

## 4. Firewall — nftables base policy

```bash
# configs/nftables.conf -> /etc/nftables.conf
sudo cp configs/nftables.conf /etc/nftables.conf
sudo nft -c -f /etc/nftables.conf        # syntax check
sudo systemctl enable nftables.service
sudo nft -f /etc/nftables.conf           # apply WITHOUT restarting the unit
```

Policy (table `inet daimon-fw`):

- input policy drop; allow: loopback, established/related, SSH (except from
  incusbr0), ZeroTier transport 9993 tcp/udp, everything on `zt*` (anyVPN
  mesh = trusted mgmt), ICMP baseline.
- from `incusbr0` ONLY: DNS 53 tcp/udp, DHCP 67 udp, tribe broker 8685 tcp,
  ICMP — everything else container→host dropped (B5).
- forward policy drop; established allowed; sibling→sibling on the bridge
  dropped; bridge→world egress allowed (incus NAT handles masquerade in its
  own `inet incus` table).

### ⚠️ PITFALL (learned live, 2026-08-01)

`systemctl restart nftables` runs ExecStop = `nft flush ruleset`, which
wipes the ENTIRE ruleset including Incus's NAT table → container egress
dies silently. **Never restart the unit at runtime; apply with
`nft -f /etc/nftables.conf`** (my file only `destroy`s its own table). At
boot there is no conflict: nftables.service (sysinit) loads before incus
adds its own table. For the same reason, `/etc/nftables.conf` must never
contain `flush ruleset` once incus is installed.

## 5. Verification (all executed 2026-08-01, smoke container `smoke-1`)

| Check | Result |
|-------|--------|
| container uid_map | `0 1000000 1000000000` (unprivileged) ✓ |
| /dev/kvm, /run/incus in container | absent ✓ |
| DNS via bridge | OK ✓ |
| egress IPv4 (deb.debian.org) | HTTP 200 ✓ |
| tribe broker via host anyVPN addr from container | HTTP 200 ✓ |
| container → host SSH (bridge + anyVPN addr) | denied ✓ |
| sibling→sibling forward | drop rule in place (single-container test; matrix completed in #9) |
| services enabled at boot | incus, nftables, zramswap all `enabled` ✓ |
| boot ordering | nftables (sysinit) before incus; no flush in config ✓ |

Known finding moved to #8: default containers still get `/dev/net/tun` —
the `tribe-agent` profile must strip it (ADR-001 D6).

External ingress verification passed on 2026-08-11 from an authorized helper
with no ZeroTier interface resolving the host through public DNS. Public SSH
remained reachable as designed, while the Incus API, Tribe broker and clusterd
ports were all unreachable. The receipt publishes only port classes/results,
not the resolved address. This is the valid off-mesh check that an on-host
loopback route could not provide.

## 6. Pinned versions (installed 2026-08-01)

- incus / incus-client 6.0.4-2+deb13u8
- nftables 1.1.3-1
- zram-tools 0.3.7-1

## 7. Rollback

```bash
sudo incus stop smoke-1 && sudo incus delete smoke-1   # if created
sudo systemctl disable --now zramswap.service
sudo swapoff /dev/zram0
sudo systemctl stop incus && sudo apt-get remove --purge -y incus
sudo nft destroy table inet daimon-fw
# revert /etc/nftables.conf to the Debian default (or empty policy accept)
```

Incus purge removes `/var/lib/incus` (containers, images, pools) — that IS
the rollback. tribe broker/ZeroTier/host SSH are untouched by this runbook
except the firewall rules, which keep them reachable throughout.
