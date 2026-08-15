# Runbook: host restart drill (closes issue #9's last criterion)

Purpose: prove that after a full host restart, daimonmatrix returns to its
documented state: tribe broker v1, SSH, ZeroTier, incus + containers,
firewall, zram — with zero manual intervention beyond the restart itself.

The 2026-08-11 drill was executed under Nicolás's explicit authorization for
autonomous reversible SSH testing on the then-unused infrastructure. That
authorization is the receipt for this drill only; future disruptive reboots
still require current scope and authority.

## 0. Pre-flight (agent, before the window)

- [x] Existing Tribe direct-message receipt established the maintenance lane;
  do not disclose private message contents in public evidence.
- [x] Test containers running: `incus list` showed iso-a/iso-b/steward RUNNING.
- [ ] Boot enablement snapshot:
  `systemctl is-enabled incus nftables zramswap ssh zerotier-one` → all
  `enabled`; actual broker unit: `tribe-bridge-v1.service`.
- [x] Capture boot ID, service/container state, audit/idempotency hashes and
  exact reconcile findings before the reboot.

## 1. Restart (authorized operator)

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
| zram | `cat /proc/swaps` → /dev/zram0 ~4 GiB | ✓ |
| incus | `incus list` → iso-a/iso-b/steward RUNNING | ✓ |
| container egress | `incus exec iso-a -- curl -4 -s -o /dev/null -w "%{http_code}" http://deb.debian.org` → 200 | ✓ |
| container isolation | `incus exec iso-a -- ping -c1 -W2 10.105.93.193` → fails | ✓ |
| broker | `curl -s http://127.0.0.1:8685/v1/health` → JSON with build_commit | ✓ |
| broker via anyVPN | `curl -s http://10.10.20.69:8685/v1/health` → same | ✓ |
| tribe link | send + receive a v1 DM with compaii@legion | ✓ |
| clusterd | `systemctl is-active clusterd` → active; `curl -s http://127.0.0.1:8785/v1/health` → `"status":"ok"`, `audit_chain_ok:true` | ✓ |
| clusterd private-only | `ss -tlnp \| grep 8785` → loopback + private Incus bridge, nothing on public IPs | ✓ |
| clusterd auth + state | authenticated `GET /v1/instances` (token at /var/lib/daimon-cluster/.nico-token) → iso-a/iso-b JSON; `clusterctl reconcile --json` findings == pre-reboot set (idempotency/audit survived) | ✓ |
| bridge startup gate | `ExecStartPre` exits 0; one clusterd start, no `EADDRNOTAVAIL`, `NRestarts=0` | ✓ |
| Matrix status | authenticated `/v1/weave/status` → exact pin, configured, integrity ok, counts/epoch stable and no partial view | ✓ |

## 3. Close

- Append results to `docs/verification/m1-acceptance-tests.md` and tick issue
  #9's reboot acceptance box through the normal evidence flow.
- If any check fails: capture `journalctl -b` excerpts, mark the drill
  FAILED, file a follow-up issue, and notify the tribe before attempting
  fixes beyond re-running `nft -f /etc/nftables.conf` or restarting a
  service that failed to start.

## Executed receipt

The final 2026-08-11 reboot passed every row above. Boot ID changed to a fresh
value; audit/idempotency hashes were unchanged; the exact five pre-existing
reconcile findings remained; `clusterd`'s private-bridge preflight took two
seconds and the service started once. The first reboot's two findings—missing
Matrix status sidecar and one initial bridge bind failure—are retained in the
acceptance record because they directly produced the final 915/94 repairs.
