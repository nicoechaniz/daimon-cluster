#!/usr/bin/env bash
# Pull one encrypted restic repository through a read-only rrsync boundary.
# The destination never receives the repository password or source host sudo.
set -euo pipefail
umask 077

SOURCE="${MIRROR_SOURCE:-}"
DEST="${MIRROR_DEST:-}"
RECEIPT="${MIRROR_RECEIPT:-}"
CREDENTIAL_DIR="${MIRROR_CREDENTIALS_DIR:-${CREDENTIALS_DIRECTORY:-}}"
RSYNC_BIN="${RSYNC_BIN:-rsync}"
SSH_BIN="${SSH_BIN:-ssh}"

fail() {
    printf '%s\n' "$1" >&2
    exit "${2:-2}"
}

[[ "$SOURCE" =~ ^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+$ ]] \
    || fail "mirror_source_invalid"
for path in "$DEST" "$RECEIPT"; do
    [[ "$path" =~ ^/[A-Za-z0-9._/-]+$ ]] \
        || fail "mirror_path_invalid"
    [[ "$path" != "/" && "$path" != *"//"* && "$path" != *"/../"* ]] \
        || fail "mirror_path_invalid"
done
[[ -n "$CREDENTIAL_DIR" && -d "$CREDENTIAL_DIR" ]] \
    || fail "mirror_credentials_unavailable"

KEY="$CREDENTIAL_DIR/source-key"
KNOWN_HOSTS="$CREDENTIAL_DIR/source-known-hosts"
for credential in "$KEY" "$KNOWN_HOSTS"; do
    [[ -f "$credential" && ! -L "$credential" ]] \
        || fail "mirror_credential_unsafe"
done
key_mode=$(stat -c '%a' "$KEY")
(( (8#$key_mode & 077) == 0 )) || fail "mirror_key_permissions_unsafe"

[[ -d "$DEST" && ! -L "$DEST" ]] || fail "mirror_destination_unsafe"
dest_mode=$(stat -c '%a' "$DEST")
(( (8#$dest_mode & 077) == 0 )) \
    || fail "mirror_destination_permissions_unsafe"
receipt_parent=$(dirname "$RECEIPT")
[[ -d "$receipt_parent" && ! -L "$receipt_parent" ]] \
    || fail "mirror_receipt_parent_unsafe"

LOCK_FILE="${MIRROR_LOCK_FILE:-${DEST}.lock}"
ERROR_FILE="${MIRROR_ERROR_FILE:-${RECEIPT}.last-error}"
exec 9>"$LOCK_FILE"
flock -n 9 || fail "mirror_pull_already_running" 75

STAGING=$(mktemp -d "${DEST}.staging.XXXXXX")
MANIFEST=""
cleanup() {
    [[ -z "$MANIFEST" ]] || rm -f "$MANIFEST"
    [[ -z "$STAGING" ]] || rm -rf "$STAGING"
}
trap cleanup EXIT

error_receipt() {
    status=$?
    trap - ERR
    error_tmp=$(mktemp "${ERROR_FILE}.tmp.XXXXXX")
    printf '{"schema":"dm.cluster-mirror-error/v1","status":"failed","exit_code":%d}\n' \
        "$status" >"$error_tmp"
    mv -f "$error_tmp" "$ERROR_FILE"
    exit "$status"
}
trap error_receipt ERR

export RSYNC_RSH="$SSH_BIN -F /dev/null -i $KEY -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o ConnectTimeout=15"
"$RSYNC_BIN" \
    --archive \
    --delete-delay \
    --delay-updates \
    --partial-dir=.rsync-partial \
    --link-dest="$DEST" \
    --chmod=Du=rwx,Dgo=,Fu=rw,Fgo= \
    "$SOURCE:/" "$STAGING/"

for required in config data index keys locks snapshots; do
    [[ -e "$STAGING/$required" ]] || fail "mirror_repository_incomplete" 3
done
[[ -f "$STAGING/config" && ! -L "$STAGING/config" ]] \
    || fail "mirror_repository_incomplete" 3
if find "$STAGING" -type l -print -quit | grep -q .; then
    fail "mirror_repository_symlink_rejected" 3
fi

snapshot_path=$(
    find "$STAGING/snapshots" -mindepth 2 -maxdepth 2 -type f \
        -printf '%T@ %p\n' | LC_ALL=C sort -nr | sed -n '1p' | cut -d' ' -f2-
)
[[ -n "$snapshot_path" ]] || fail "mirror_snapshot_missing" 3
snapshot_rel=${snapshot_path#"$STAGING/snapshots/"}
snapshot_id=${snapshot_rel//\//}
[[ "$snapshot_id" =~ ^[0-9a-f]{64}$ ]] || fail "mirror_snapshot_id_invalid" 3

MANIFEST=$(mktemp "${DEST}.manifest.XXXXXX")
file_count=0
byte_count=0
while IFS= read -r -d '' relative; do
    file="$STAGING/$relative"
    hash=$(sha256sum "$file" | cut -d' ' -f1)
    size=$(stat -c '%s' "$file")
    printf '%s  %s\n' "$hash" "$relative" >>"$MANIFEST"
    file_count=$((file_count + 1))
    byte_count=$((byte_count + size))
done < <(cd "$STAGING" && find . -type f -printf '%P\0' | LC_ALL=C sort -z)

tree_sha256=$(sha256sum "$MANIFEST" | cut -d' ' -f1)
config_sha256=$(sha256sum "$STAGING/config" | cut -d' ' -f1)
completed_at=$(date --utc '+%Y-%m-%dT%H:%M:%SZ')
receipt_tmp=$(mktemp "${RECEIPT}.tmp.XXXXXX")
printf '{"schema":"dm.cluster-mirror-receipt/v1","source":"%s","latest_snapshot_id":"%s","repository_config_sha256":"%s","tree_sha256":"%s","file_count":%d,"byte_count":%d,"completed_at":"%s","status":"ok"}\n' \
    "$SOURCE" "$snapshot_id" "$config_sha256" "$tree_sha256" \
    "$file_count" "$byte_count" "$completed_at" >"$receipt_tmp"

# Both paths are siblings on one filesystem. GNU mv maps --exchange to an
# atomic renameat2 exchange: readers see either the complete old tree or the
# complete verified new tree, never an incomplete repository.
mv --exchange --no-copy --no-target-directory "$STAGING" "$DEST"
rm -rf "$STAGING"
STAGING=""
mv -f "$receipt_tmp" "$RECEIPT"
rm -f "$ERROR_FILE"

trap - EXIT ERR
rm -f "$MANIFEST"
MANIFEST=""
printf 'mirror complete: snapshot=%s files=%d bytes=%d tree=%s\n' \
    "$snapshot_id" "$file_count" "$byte_count" "$tree_sha256"
