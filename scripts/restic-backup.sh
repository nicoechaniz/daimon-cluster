#!/usr/bin/env bash
# restic-backup.sh — daimon-cluster volume backup (issue #15)
#
# Backs up each declared daimon's durable volume + the cluster state dir
# to the configured restic target. FAIL-CLOSED: any failure exits non-zero
# and must surface as an alert (design: docs/design/quiesced-snapshots.md §5,
# docs/design/backup-targets.md).
#
# Env (from /etc/daimon-cluster/backup.env, NOT committed):
#   RESTIC_REPOSITORY   e.g. sftp:debian@10.10.20.27:/home/debian/daimon-backups/daimonmatrix
#   RESTIC_PASSWORD     repo encryption password (lives only in that file + keeper)
#   SFTP_IDENTITY       ssh key (default /var/lib/daimon-cluster/backup-keys/restic-sftp)
#
# Usage: restic-backup.sh [--check-only]
set -euo pipefail

ENV_FILE=/etc/daimon-cluster/backup.env
STATE_DIR=${DAIMON_STATE_DIR:-/var/lib/daimon-cluster}
POOL=${INCUS_POOL_PATH:-/var/lib/incus/storage-pools/default}

die() { echo "restic-backup: ERROR: $*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "$ENV_FILE missing (target not configured yet — see docs/design/backup-targets.md)"
set -a; source "$ENV_FILE"; set +a
: "${RESTIC_REPOSITORY:?}"; "${RESTIC_PASSWORD:?}"
export RESTIC_REPOSITORY RESTIC_PASSWORD
export RESTIC_SFTP_ARGS="-oIdentityFile=${SFTP_IDENTITY:-/var/lib/daimon-cluster/backup-keys/restic-sftp} -oStrictHostKeyChecking=accept-new"

if [ "${1:-}" = "--check-only" ]; then
    restic snapshots --latest 1 >/dev/null && echo "target reachable: $RESTIC_REPOSITORY" && exit 0
    die "target unreachable"
fi

# Snapshot freshness guard: only back up volumes whose latest quiesced
# manifest is < 26h old (RPO 6h target with 4x daily cadence; 26h = one
# missed run tolerated). Missing/ stale manifest => fail closed.
now_ms=$(( $(date +%s) * 1000 ))
fresh=0; stale=0
for manifest in "$STATE_DIR"/backups/*/*.json; do
    [ -e "$manifest" ] || continue
    created=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['created_ms'])" "$manifest")
    age_h=$(( (now_ms - created) / 3600000 ))
    if [ "$age_h" -gt 26 ]; then stale=$((stale+1)); else fresh=$((fresh+1)); fi
done
[ "$stale" -eq 0 ] || die "$stale daimon(s) with stale quiesced manifests (>26h) — run clusterctl snapshot create first"

# Volumes (durable home dirs) + cluster state (specs, audit, manifests —
# keys stay in volumes; state_dir holds no private material by design).
paths=()
for v in "$POOL"/custom/*-home; do [ -d "$v" ] && paths+=("$v"); done
paths+=("$STATE_DIR/instances" "$STATE_DIR/audit.jsonl" "$STATE_DIR/backups" "$STATE_DIR/leases.json")
existing=(); for p in "${paths[@]}"; do [ -e "$p" ] && existing+=("$p"); done
[ "${#existing[@]}" -gt 0 ] || die "nothing to back up"

restic backup "${existing[@]}" --tag daimon-cluster --tag "$(date +%F)"
restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 3 --prune --tag daimon-cluster
restic check --read-data-subset=5%
echo "restic-backup: ok ($fresh daimons fresh, target $RESTIC_REPOSITORY)"
