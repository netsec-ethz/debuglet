#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# ci-local supplies the same verified installation used by its original flow.
: "${DEBUGLET_LOCAL_INSTALL_ROOT:?Run make ci-local to install the candidate first}"
: "${DEBUGLET_LOCAL_SOURCE_ROOT:?Missing matching source root}"
: "${DEBUGLET_LOCAL_SOURCE_SHA:?Missing candidate revision}"
mkdir -p .cache/ci
evidence="$(realpath .cache/ci)/role-evidence"
mkdir -p -m 0700 "$evidence"
export DEBUGLET_ROLE_EVIDENCE_DIR="$evidence"
"${GO:-go}" test -mod=readonly -json -tags=roles_integration -count=1 -timeout=5m \
  ./internal/acceptance/roles -run '^TestInstalled(Roles|BackupRestore|Recovery)$' | tee .cache/ci/role-tests.json
python3 tools/check-evidence.py --test ./internal/acceptance/roles:TestInstalledRoles \
  --test ./internal/acceptance/roles:TestInstalledBackupRestore \
  --test ./internal/acceptance/roles:TestInstalledRecovery \
  --test ./internal/acceptance/roles:TestInstalledRecovery/graceful \
  --test ./internal/acceptance/roles:TestInstalledRecovery/terminated \
  --evidence .cache/ci/role-tests.json
