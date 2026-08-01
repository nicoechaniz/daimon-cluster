#!/usr/bin/env bash
# build-tribe-base.sh — reproducible tribe-base image build (issue #7)
# Usage: sudo ./scripts/build-tribe-base.sh <version>   e.g. 2026-08-01.1
# Produces: incus image alias tribe-base/<version> + tribe-base/latest,
# manifest + checksums in configs/tribe-base-manifest-<version>.json.
set -euo pipefail

VERSION="${1:?usage: build-tribe-base.sh <version>}"
PINS="$(dirname "$0")/../configs/tribe-base-pins.env"
# shellcheck disable=SC1090
source "$PINS"

BUILD="tribe-base-build-$(echo "$VERSION" | tr '.' '-')"
ALIAS="tribe-base/${VERSION}"

echo "== pins =="
echo "hermes=$HERMES_COMMIT hmk=$HMK_COMMIT tribe=$TRIBE_COMMIT base=$DEBIAN_BASE"

echo "== cleanup previous build container (if any) =="
incus delete "$BUILD" -f 2>/dev/null || true

echo "== launch build container =="
incus launch "$DEBIAN_BASE" "$BUILD"
sleep 5

echo "== provision =="
incus exec "$BUILD" -- bash -se <<PROVISION
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip git curl ca-certificates openssh-client sudo jq
useradd -m -s /bin/bash agent || true

mkdir -p /opt/tribe
cd /opt/tribe
git clone -q $HERMES_REPO hermes-agent
git -C hermes-agent checkout -q $HERMES_COMMIT
git clone -q $HMK_REPO hermes-memory-kit
git -C hermes-memory-kit checkout -q $HMK_COMMIT
git clone -q $TRIBE_REPO tribe-bridge
git -C tribe-bridge checkout -q $TRIBE_COMMIT

python3 -m venv /opt/tribe/venv-hermes
/opt/tribe/venv-hermes/bin/pip install -q --upgrade pip
/opt/tribe/venv-hermes/bin/pip install -q -e /opt/tribe/hermes-agent

python3 -m venv /opt/tribe/venv-tribe
/opt/tribe/venv-tribe/bin/pip install -q --upgrade pip
/opt/tribe/venv-tribe/bin/pip install -q "cryptography>=49"

chown -R agent:agent /home/agent
apt-get clean
rm -rf /var/lib/apt/lists/* /root/.cache /tmp/*
PROVISION

echo "== boot smoke tests =="
incus exec "$BUILD" -- bash -c '
  systemctl is-system-running 2>/dev/null || true
  HERMES_HOME=/tmp/hermes-smoke /opt/tribe/venv-hermes/bin/hermes --version
  rm -rf /tmp/hermes-smoke
  PYTHONPATH=/opt/tribe/tribe-bridge/src /opt/tribe/venv-tribe/bin/python -c "from cryptography.hazmat.primitives.hpke import Suite; print(\"tribe v1 crypto OK\")
"
  git -C /opt/tribe/hermes-agent log --oneline -1
'

echo "== secret scan =="
# Only flag actual credential FILES, never source code that mentions the
# pattern as a literal (redact.py, corpus_policy.py, tests all do).
LEAKS=$(incus exec "$BUILD" -- bash -c '
  find /root /home /opt/tribe -xdev \( -name "id_rsa*" -o -name "id_ed25519*" -o -name "*.pem" -o -name "*.key" -o -name "auth.json" -o -name ".env" -o -name "*.keys.json" -o -name "credentials*" \) 2>/dev/null | grep -vE "venv|node_modules|/tests?/|\.py$|\.pyc$" | head -20
  find /root/.ssh /home/*/.ssh -type f 2>/dev/null | head -10
  ls /root/.hermes /home/*/.hermes /root/.tribe-bridge /home/*/.tribe-bridge 2>/dev/null | head -10
' || true)
if [ -n "$LEAKS" ]; then
  echo "SECRET SCAN FAILED:"; echo "$LEAKS"; exit 1
fi
echo "secret scan: clean"

echo "== collect manifest =="
incus exec "$BUILD" -- bash -c 'dpkg -l | awk "{print \$2, \$3}" | sort' > "/tmp/tribe-base-dpkg-${VERSION}.txt"
incus exec "$BUILD" -- bash -c '/opt/tribe/venv-hermes/bin/pip freeze | sort' > "/tmp/tribe-base-pip-${VERSION}.txt"

echo "== publish =="
incus publish "$BUILD" --alias "$ALIAS" --reuse --force
FP=$(incus image info "$ALIAS" | awk '/^Fingerprint/ {print $2}')
incus image alias delete tribe-base/latest 2>/dev/null || true
incus image alias create tribe-base/latest "$FP"
cat > "$(dirname "$0")/../configs/tribe-base-manifest-${VERSION}.json" <<EOF
{
  "schema": "tribe-base-manifest/v1",
  "version": "${VERSION}",
  "fingerprint": "${FP}",
  "pins": {
    "debian_base": "${DEBIAN_BASE}",
    "hermes_commit": "${HERMES_COMMIT}",
    "hmk_commit": "${HMK_COMMIT}",
    "tribe_commit": "${TRIBE_COMMIT}"
  },
  "dpkg_manifest": "configs/tribe-base-dpkg-${VERSION}.txt",
  "pip_manifest": "configs/tribe-base-pip-${VERSION}.txt",
  "built_by": "compaii@daimonmatrix",
  "built_ms": $(date +%s%3N)
}
EOF
cp "/tmp/tribe-base-dpkg-${VERSION}.txt" "$(dirname "$0")/../configs/"
cp "/tmp/tribe-base-pip-${VERSION}.txt" "$(dirname "$0")/../configs/"

echo "== build container stopped (retained until verified) =="
incus stop "$BUILD" --timeout 30
echo "DONE: ${ALIAS} (fingerprint ${FP})"
