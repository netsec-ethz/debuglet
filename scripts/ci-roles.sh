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
"${GO:-go}" test -mod=readonly -json -tags=roles_integration -count=1 -timeout=3m \
  ./internal/acceptance/roles -run '^TestInstalledRoles$' | tee .cache/ci/role-tests.json
"${GO:-go}" run -mod=readonly ./internal/packaging check-role-evidence \
  -evidence .cache/ci/role-tests.json
