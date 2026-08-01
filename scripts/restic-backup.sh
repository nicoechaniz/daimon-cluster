#!/usr/bin/env bash
# restic-backup.sh — daimon-cluster backup (issue #15, local-repo + pull model)
#
# Backs up every declared daimon's durable volume + the cluster state dir
# to a LOCAL restic repo (encrypted, append-mostly). The off-host copy is
# PULLED by the legion over its existing SSH access to this host — no
# outbound SSH from daimonmatrix, no new listeners, no new exposure.
# The legion holds ciphertext only; the password never leaves this host.
#
# FAIL-CLOSED: destroy/update paths require at least one verified target;
# "verified" = local restic check passes + the legion's pull heartbeat is
# fresh (their cron reports via bridge).
#
# Env:
#   RESTIC_REPOSITORY   default /var/lib/daimon-cluster/restic-repo
#   RESTIC_PASSWORD     repo password (lives in /var/lib/daimon-cluster/backup-keys/restic-password)
# Usage: restic-backup.sh [--check-only|--verify]
set -euo pipefail

REPO="${RESTIC_REPOSITORY:-/var/lib/daimon-cluster/restic-repo}"
: "${RESTIC_PASSWORD:?set RESTIC_PASSWORD (see backup-keys/restic-password)}"
export RESTIC_REPOSITORY="$REPO" RESTIC_PASSWORD

STATE_DIR=/var/lib/daimon-cluster
POOL=/var/lib/incus/storage-pools/default/custom

if [[ "${1:-}" == "--check-only" ]]; then
    restic snapshots --latest 1 >/dev/null && echo "repo ok: $REPO" && exit 0
fi
if [[ "${1:-}" == "--verify" ]]; then
    restic check && exit 0
fi

# Path set: state (specs/audit/idempotency) + every declared daimon's volume.
PATHS=("$STATE_DIR/instances" "$STATE_DIR/audit.jsonl" "$STATE_DIR/idempotency.json")
for spec in "$STATE_DIR"/instances/*.yaml; do
    name=$(basename "$spec" .yaml)
    vol="$POOL/default_${name}-home"
    [[ -d "$vol" ]] && PATHS+=("$vol")
done

restic backup "${PATHS[@]}" --tag daimon-cluster --tag scheduled
restic forget --keep-daily 7 --keep-weekly 4 --prune
restic check
echo "backup complete: ${#PATHS[@]} paths -> $REPO"
