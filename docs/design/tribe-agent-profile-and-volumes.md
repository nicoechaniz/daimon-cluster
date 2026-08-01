# tribe-agent profile and durable volume layout (issue #8)

Status: IMPLEMENTED on daimonmatrix (2026-08-01). Profile source:
`configs/tribe-agent-profile.yaml` (applied via `incus profile edit`).

## 1. Profile `tribe-agent`

| Setting | Value | Source |
|---------|-------|--------|
| limits.cpu | 1 | ADR-001 D7 pilot budget |
| limits.memory | 1536MiB | ADR-001 D7; measured headroom (inventory §5) |
| limits.memory.swap | false | ADR-001 D7: per-daimon swap dropped; zram is host-level |
| security.nesting | false | least privilege; Hermes needs no nesting |
| raw.lxc cgroup device allowlist | std LXC set minus tun (`c 1:3,1:5,1:7,1:8,1:9,5:0,5:1,5:2,136:*`) | ADR-001 D6: no usable TUN by default. NOTE: a raw deny entry silently REPLACES the default device allowlist and breaks /dev/null — an explicit allowlist excluding tun is the correct form (learned live). |
| root disk | pool default, size 8GiB | ADR-001 D7 (see §4 caveat) |
| eth0 | incusbr0 | M1 foundation (#6) |

Verified live (test containers `test-vol`/`test-vol2`/`img-verify2`, since deleted):

- tun: `ip tuntap add` → `Operation not permitted` (allowlist excludes
  `c 10:200`; default container WAS able — finding confirmed and fixed at
  profile level). First attempt with a raw `devices.deny` entry broke
  `/dev/null` (raw entries replace the default allowlist) — corrected to
  the explicit allowlist and re-verified.
- memory: `/proc/meminfo` inside shows 1,572,864 kB = 1.5 GiB.
- unprivileged: uid_map 0→1000000 (inherited from M1 foundation).
- Exceptions (per ADR D6): a daimon needing usable TUN (own anyVPN
  identity) gets an explicit per-instance config addition
  (`raw.lxc` allow + reason recorded in instance spec), never via profile.

## 2. Durable volume layout

Replaceable vs durable separation:

```
rootfs (container root, from tribe-base image)   ← REPLACEABLE on refresh
└── /home/<agent>/            ← custom volume <agent>-durable (DURABLE)
    ├── .hermes/              HERMES_HOME: SOUL, config, skills, plugins
    │   └── agent-memory/     HMK library.db + state + backups
    ├── .tribe-bridge/        v1 keys + client env + inbox/outbox db
    └── Projects/<agent>-state/  rebirth state repo (git)
```

Rationale: one durable volume per daimon keeps backup, quota-monitoring,
and destroy/archive semantics uniform, while letting the rootfs be rebuilt
from a new image without touching identity.

Ownership: on the `dir` backend with unprivileged containers, volume
contents are host-uid-shifted; inside the container the mount is owned by
root — per-agent file ownership lives INSIDE the volume under the agent's
container uid. Provisioning (#11/#12) must `chown` the tree for the agent's
container user at seed time.

Mount options: defaults (noatime inherited). No host paths are ever bind-mounted.

## 3. Destroy semantics (binding for clusterctl #11)

1. `clusterctl destroy <agent>` ALWAYS archives first: park-equivalent
   snapshot (HMK integrity-verified) + restic push of the durable volume.
2. Confirmation token names a DISTINCT operation (`destroy`) — a `stop` or
   `park` confirmation never authorizes destroy (contracts #4).
3. Only after archive verification does the container get deleted; the
   durable volume is deleted last, and only on explicit
   `--delete-volumes` (default: retain as cold archive).

## 4. Disk quota caveat (recorded deviation from draft expectations)

The `dir` backend on ext4 does NOT enforce the 8GiB root size or volume
size limits (verified: container `df /` shows the full host filesystem).
Options considered: remounting host root with `prjquota` (invasive,
rejected for v1), dedicated block device (does not exist, ADR-001 D5).

**Conservative resolution**: hard quotas are replaced in v1 by
**monitoring + alert thresholds** — clusterd (#17) collects per-daimon
`du` of rootfs+durable volume and raises audit events at 80% of the 8GiB
budget and at host-level 20% free-disk headroom. Documented here and in
the threat model residual-risk register. Revisit if a second block device
is ever added.

## 5. Backup inclusion

- Durable volume: restic daily, two targets (M3 #15) — identity-critical.
- Rootfs: NOT backed up (rebuildable from image + seed).
- Pre-mutation incus snapshots of the durable volume before
  restore/destroy/update (dir: full copies, acceptable at 1–8 GiB).
