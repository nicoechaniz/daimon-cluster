#!/usr/bin/env bash
# restic-backup.sh — daimon-cluster backup (issue #15, local-repo + pull model)
#
# Backs up every declared daimon's durable volume + the complete quiesced
# Cluster service boundary
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
#   RESTIC_PASSWORD or RESTIC_PASSWORD_FILE
#   SYSTEMCTL_BIN / RESTIC_BIN and path overrides are test hooks.
# Usage: restic-backup.sh [--check-only|--verify]
set -euo pipefail

STATE_DIR="${DAIMON_CLUSTER_STATE_DIR:-/var/lib/daimon-cluster}"
DEPLOY_DIR="${DAIMON_CLUSTER_DEPLOY_DIR:-/opt/daimon-cluster}"
MATRIX_ETC_DIR="${DAIMON_MATRIX_ETC_DIR:-/etc/daimon-matrix}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
POOL="${INCUS_POOL_DIR:-/var/lib/incus/storage-pools/default/custom}"
REPO="${RESTIC_REPOSITORY:-$STATE_DIR/restic-repo}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-systemctl}"
RESTIC_BIN="${RESTIC_BIN:-restic}"
if [[ -z "${RESTIC_PASSWORD:-}" && -z "${RESTIC_PASSWORD_FILE:-}" ]]; then
    echo "set RESTIC_PASSWORD or RESTIC_PASSWORD_FILE" >&2
    exit 2
fi
export RESTIC_REPOSITORY="$REPO"
if [[ -n "${RESTIC_PASSWORD:-}" ]]; then
    export RESTIC_PASSWORD
fi
if [[ -n "${RESTIC_PASSWORD_FILE:-}" ]]; then
    export RESTIC_PASSWORD_FILE
fi

if [[ "${1:-}" == "--check-only" ]]; then
    "$RESTIC_BIN" snapshots --latest 1 >/dev/null \
        && echo "repo ok: $REPO" && exit 0
fi
if [[ "${1:-}" == "--verify" ]]; then
    "$RESTIC_BIN" check && exit 0
fi

active_matrix_units=()
while IFS= read -r unit; do
    [[ -n "$unit" ]] && active_matrix_units+=("$unit")
done < <(
    "$SYSTEMCTL_BIN" list-units \
        --type=service --state=active --no-legend --plain \
        'daimon-matrix-*.service' 2>/dev/null | awk '{print $1}'
)
clusterd_was_active=false
if "$SYSTEMCTL_BIN" is-active --quiet clusterd.service; then
    clusterd_was_active=true
fi

resume_services() {
    local failed=0 unit
    if [[ "$clusterd_was_active" == true ]]; then
        "$SYSTEMCTL_BIN" start clusterd.service || failed=1
    fi
    for unit in "${active_matrix_units[@]}"; do
        "$SYSTEMCTL_BIN" start "$unit" || failed=1
    done
    return "$failed"
}

cleanup() {
    local status=$?
    trap - EXIT
    set +e
    resume_services
    local resume_status=$?
    [[ "$status" -eq 0 ]] && status=$resume_status
    exit "$status"
}
trap cleanup EXIT

for unit in "${active_matrix_units[@]}"; do
    "$SYSTEMCTL_BIN" stop "$unit"
done
if [[ "$clusterd_was_active" == true ]]; then
    "$SYSTEMCTL_BIN" stop clusterd.service
fi

# The whole state boundary is consistent now that clusterd and every hosted
# Matrix runtime are stopped.  Exclude only the repository itself and its
# circular unlock material.  Matrix sockets disappear on stop; restic ignores
# any other sockets.
PATHS=("$STATE_DIR")
[[ -d "$DEPLOY_DIR" ]] && PATHS+=("$DEPLOY_DIR")
[[ -d "$MATRIX_ETC_DIR" ]] && PATHS+=("$MATRIX_ETC_DIR")
shopt -s nullglob
for unit_file in \
    "$SYSTEMD_UNIT_DIR"/clusterd.service \
    "$SYSTEMD_UNIT_DIR"/daimon-matrix-*.service \
    "$SYSTEMD_UNIT_DIR"/restic-backup.service \
    "$SYSTEMD_UNIT_DIR"/restic-backup.timer; do
    PATHS+=("$unit_file")
done
for spec in "$STATE_DIR"/instances/*.yaml; do
    name=$(basename "$spec" .yaml)
    vol="$POOL/default_${name}-home"
    [[ -d "$vol" ]] && PATHS+=("$vol")
done

"$RESTIC_BIN" backup "${PATHS[@]}" \
    --exclude "$REPO" \
    --exclude "$STATE_DIR/backup-keys" \
    --tag daimon-cluster --tag scheduled
"$RESTIC_BIN" forget --keep-daily 7 --keep-weekly 4 --prune
"$RESTIC_BIN" check
echo "backup complete: ${#PATHS[@]} paths -> $REPO"

trap - EXIT
resume_services
