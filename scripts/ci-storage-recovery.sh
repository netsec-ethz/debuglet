#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

: "${DEBUGLET_LOCAL_INSTALL_ROOT:?Set the verified full package directory}"
: "${DEBUGLET_LOCAL_SOURCE_SHA:?Set the matching package source revision}"
: "${DEBUGLET_STORAGE_DRILL_ROOT:?Provide an owned private tmpfs of at most 16 MiB}"
mkdir -p .cache/ci
"${GO:-go}" test -mod=readonly -json -tags=roles_integration -count=1 -failfast -timeout=5m \
  ./internal/acceptance/roles -run '^TestInstalledStorageRecovery$' | tee .cache/ci/storage-recovery-tests.json
python3 tools/check-evidence.py --test ./internal/acceptance/roles:TestInstalledStorageRecovery \
  --test ./internal/acceptance/roles:TestInstalledStorageRecovery/first \
  --test ./internal/acceptance/roles:TestInstalledStorageRecovery/second \
  --test ./internal/acceptance/roles:TestInstalledStorageRecovery/third \
  --evidence .cache/ci/storage-recovery-tests.json
