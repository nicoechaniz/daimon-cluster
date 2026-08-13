#!/usr/bin/env bash
# Forced command for the dedicated backup-export SSH identity.
set -euo pipefail
umask 077

EXPORT_ROOT="${DAIMON_RESTIC_EXPORT_ROOT:-/var/lib/daimon-cluster/restic-repo}"
RRSYNC_BIN="${RRSYNC_BIN:-/usr/bin/rrsync}"

fail() {
    printf '%s\n' "$1" >&2
    exit "${2:-126}"
}

[[ "$EXPORT_ROOT" =~ ^/[A-Za-z0-9._/-]+$ ]] \
    || fail "backup_export_root_invalid"
[[ "$EXPORT_ROOT" != "/" && "$EXPORT_ROOT" != *"//"* \
    && "$EXPORT_ROOT" != *"/../"* && "$EXPORT_ROOT" != */ ]] \
    || fail "backup_export_root_invalid"
[[ -d "$EXPORT_ROOT" && ! -L "$EXPORT_ROOT" ]] \
    || fail "backup_export_root_unsafe"
[[ -x "$RRSYNC_BIN" && ! -L "$RRSYNC_BIN" ]] \
    || fail "backup_export_rrsync_unsafe"
[[ -n "${SSH_ORIGINAL_COMMAND:-}" ]] \
    || fail "backup_export_command_missing"

# rrsync reads SSH_ORIGINAL_COMMAND itself and admits only rsync server sender
# requests rooted below EXPORT_ROOT. -ro additionally rejects receiver mode.
exec "$RRSYNC_BIN" -ro "$EXPORT_ROOT"
