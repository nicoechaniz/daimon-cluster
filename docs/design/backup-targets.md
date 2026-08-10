# Backup targets strategy (issue #15 design input)

UPDATE 2026-08-01 — model inverted (Nico's call): the legion's sshd
stays closed by design. The encrypted restic repo lives LOCAL on
daimonmatrix; the legion PULLS its off-host copy over its existing ssh
access to this host. No new listeners, no outbound ssh from
daimonmatrix, password never leaves the host.

## Live architecture (2026-08-01)

- Local repo: `/var/lib/daimon-cluster/restic-repo` (restic 0.18.0,
  encrypted; password at backup-keys/restic-password, 0600 root).
- Daily: systemd timer `restic-backup.timer` (04:17 + jitter) runs the
  deployed `/opt/daimon-cluster/scripts/restic-backup.sh`. It stops active
  Matrix hosts and then clusterd, captures the complete state boundary,
  deployed release, Matrix service/custody and every declared daimon's durable
  volume, then resumes only services that were active. The repository and its
  circular unlock material are excluded; retention is 7d/4w and every run ends
  with `restic check`.
  Fail-closed --check-only/--verify modes gate destroy/update paths.
- Off-host copy: legion cron rsync -a --delete of the repo dir (using its
  already-authorized remote sudo because the Cluster state parent is 0700)
  (append-mostly → cheap) + heartbeat via bridge. Legion holds
  ciphertext only. Fleet-phase targets (OVH S3 / Hetzner paid, second
  tribe host) stay parked for Nicolás.
- Verified 2026-08-01: init, backups, check clean, restore
  byte-identical.

Status: design v0.1 (2026-08-01). restic 0.18.0 installed on daimonmatrix.
Inputs: PLAN §7 (RPO 6h, daily restic, two independent targets), threat
model B8, #14 quiesce design (snapshots and restic share one manifest).

## 1. Requirement

Two INDEPENDENT off-host targets. Independence means: different failure
domains — not two dirs on the same disk, ideally not one provider.

## 2. Candidate targets

| # | Target | Type | Cost | Independence | Decision |
|---|--------|------|------|--------------|----------|
| A | legion (Nicolás's home machine) via SFTP over anyVPN | sftp:compaii@10.10.20.27:/backup/daimon-cluster | free | different host, different site, different power/net | recommended as target 1 |
| B | OVH Object Storage (S3) in another region | s3:... | PAID | different provider-side fault domain | needs Nicolás (paid op — hard rule) |
| C | Hetzner Storage Box | sftp | PAID | different provider entirely | needs Nicolás (paid op) |
| D | Second tribe host (amapola/oliva when updated) via SFTP over anyVPN | sftp | free | tribe-owned redundancy | needs those hosts updated + consent |

Conservative v1: A + D when available; A + local-archive as degraded mode
(documented, not compliant) until a second target exists. Paid options
(B/C) stay parked until Nicolás approves spend.

## 3. What gets backed up (per #8 §5)

- Durable volumes ONLY (`/var/lib/incus/storage-pools/default/custom/<agent>-home`)
  → identity, HMK, state repos, bridge keys. Rootfs excluded (rebuildable).
- Host configs: /etc/nftables.conf, /etc/default/zramswap, daimon-cluster
  repo configs/, state_dir (/var/lib/daimon-cluster).
- Repo passwords: generated at init, stored root-only on host AND in the
  tribe governance escrow (off-host copy of the password = the difference
  between backup and decoration). Escrow mechanism: sealed to governance
  HPKE key via tribe bridge v1, per B8 mitigations.

## 4. Schedule & verification

- Daily restic run per target after the quiesced capture (#14): one cron
  (or systemd timer) `clusterctl backup-all` that quiesces, snapshots,
  restic-backups to both targets, forgets per retention (7 daily / 4
  weekly / 6 monthly), and emits backup-manifest/v1 per daimon.
- `restic check` weekly on each target; `restic restore` drill monthly to
  scratch (folds into #16's automated drill, reported to public-agents).
- Failure of ONE target = warning event, backup still counts; failure of
  BOTH = the daimon's backup state flips to `unprotected` and the next
  destroy/update operation REFUSES until one target verifies (fail-closed,
  per B8).
