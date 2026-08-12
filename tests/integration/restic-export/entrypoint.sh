#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ "${DAIMON_DISPOSABLE_TEST_ONLY:-}" == "yes" ]]
[[ "${EXPORT_BUNDLE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]]

useradd --create-home --shell /bin/sh admin-test
usermod --password NP admin-test

install -d -o root -g root -m 0755 /etc/daimon-test
install -o admin-test -g admin-test -m 0600 \
    /fixture/admin.pub /etc/daimon-test/admin-test-keys

install -d -o root -g root -m 0755 /run/sshd
ssh-keygen -A
install -o root -g root -m 0600 /opt/fixture/sshd_config /etc/ssh/sshd_config
install -o root -g root -m 0600 \
    /opt/fixture/disposable-marker /run/daimon-disposable-host
python3 /opt/fixture/restic-export-apply-disposable.py \
    --bundle /fixture/bundle \
    --expect-sha256 "$EXPORT_BUNDLE_SHA256"

install -d -o root -g daimon-backup-export -m 0750 \
    /var/lib/daimon-cluster/restic-repo/data \
    /var/lib/daimon-cluster/restic-repo/index \
    /var/lib/daimon-cluster/restic-repo/keys \
    /var/lib/daimon-cluster/restic-repo/locks \
    /var/lib/daimon-cluster/restic-repo/snapshots/ab
install -o root -g daimon-backup-export -m 0640 \
    /fixture/repository/config /var/lib/daimon-cluster/restic-repo/config
install -o root -g daimon-backup-export -m 0640 \
    /fixture/repository/payload /var/lib/daimon-cluster/restic-repo/data/payload
install -o root -g daimon-backup-export -m 0640 \
    /fixture/repository/snapshot \
    /var/lib/daimon-cluster/restic-repo/snapshots/ab/cdef

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
