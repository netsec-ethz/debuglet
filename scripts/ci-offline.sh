#!/usr/bin/env bash
# Host-side witness: Docker is never exposed to the installed candidate.
set -euo pipefail
cd "$(dirname "$0")/.."
. deploy/ci/images.env
docker image inspect "$DEBUGLET_CI_RUNTIME_IMAGE" >/dev/null
trap 'rm -rf -- .cache/ci/offline-install' EXIT
bash scripts/ci-github.sh offline
version=$(cat .cache/ci/offline-version.txt)
python3 tools/check-offline.py --image "$DEBUGLET_CI_RUNTIME_IMAGE" \
    --installed-root ".cache/ci/offline-install/lib/debuglet/$version" \
    --archive ".cache/ci/packages/debuglet-$version-linux-amd64.tar.gz" \
    --source-sha "$(git rev-parse HEAD)" --evidence .cache/ci/offline-evidence
