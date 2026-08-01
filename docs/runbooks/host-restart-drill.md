# Runbook: host restart drill (closes issue #9's last criterion)

Purpose: prove that after a full host restart, daimonmatrix returns to its
documented state: tribe broker v1, SSH, ZeroTier, incus + containers,
firewall, zram — with zero manual intervention beyond the restart itself.

**The restart command is hardline-blocked for agents.** A human (Nicolás)
executes it from a terminal outside the agent. Everything else is staged.

## 0. Pre-flight (agent, before the window)

- [ ] tribe notice: post to `public-agents` that the hub will drop ~2 min.
- [ ] Test containers running: `incus list iso-` shows iso-a/iso-b RUNNING.
- [ ] Boot enablement snapshot:
  `systemctl is-enabled incus nftables zramswap ssh zerotier-one` → all
  `enabled`; broker unit: `systemctl is-enabled tribe-bridge-v1-broker`
  (or the unit name in use — verify with `systemctl list-units | grep -i tribe`).
- [ ] Note uptime and current incus list output for comparison.

## 1. Restart (human, from a terminal outside the agent)

```bash
sudo systemctl reboot
```

Expected hub downtime: ~1–3 minutes (VPS-class).

## 2. Post-restart verification (agent, once SSH is back)

Run in order; every line should match the OK column:

| Check | Command | OK |
|-------|---------|----|
| SSH back | you are reading this | ✓ |
| ZeroTier | `zerotier-cli status` → ONLINE; `ip a show dev zt+` has 10.10.20.69 | ✓ |
| firewall | `nft list tables` → `inet daimon-fw` AND `inet incus` both present | ✓ |
| zram | `cat /proc/swaps` → /dev/zram0 ~5.7G | ✓ |
| incus | `incus list` → iso-a/iso-b RUNNING with 10.105.93.x IPs | ✓ |
| container egress | `incus exec iso-a -- curl -4 -s -o /dev/null -w "%{http_code}" http://deb.debian.org` → 200 | ✓ |
| container isolation | `incus exec iso-a -- ping -c1 -W2 10.105.93.193` → fails | ✓ |
| broker | `curl -s http://127.0.0.1:8685/v1/health` → JSON with build_commit | ✓ |
| broker via anyVPN | `curl -s http://10.10.20.69:8685/v1/health` → same | ✓ |
| tribe link | send + receive a v1 DM with compaii@legion | ✓ |
| clusterd | `systemctl is-active clusterd` → active; `curl -s http://127.0.0.1:8785/v1/health` → `"status":"ok"`, `audit_chain_ok:true` | ✓ |
| clusterd loopback-only | `ss -tlnp \| grep 8785` → 127.0.0.1 only, nothing on public IPs | ✓ |
| clusterd auth + state | authenticated `GET /v1/instances` (token at /var/lib/daimon-cluster/.nico-token) → iso-a/iso-b JSON; `clusterctl reconcile --json` findings == pre-reboot set (idempotency/audit survived) | ✓ |

## 3. Close

- Append results to `docs/verification/m1-acceptance-tests.md` (replace the
  "Pending: host restart drill" section with the dated results table).
- Report to `public-agents`; tick the issue #9 acceptance box via the
  push/comment flow.
- If any check fails: capture `journalctl -b` excerpts, mark the drill
  FAILED, file a follow-up issue, and notify the tribe before attempting
  fixes beyond re-running `nft -f /etc/nftables.conf` or restarting a
  service that failed to start.
