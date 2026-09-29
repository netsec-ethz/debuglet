#!/usr/bin/env bash
# Measure the installed TEST profile inside the launcher's no-network container.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEBUGLET_SOAK_ISOLATED:?Run through scripts/ci-github.sh soak}"
export GOPROXY=off GOSUMDB=off
mkdir -p .cache/ci/soak
evidence=$(mktemp -d "$PWD/.cache/ci/soak/run.XXXXXXXX")
work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-soak.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
{
    git rev-parse HEAD
    printf 'Container limits: network=none cpus=4 memory=4g pids=512\n'
    printf 'make ci-build ci-package\n'
    printf 'go test -tags=roles_integration -count=1 -timeout=5m ./internal/acceptance/roles -run ^TestInstalledScheduleSoak$\n'
} > "$evidence/commands.txt"
make ci-build ci-package > "$evidence/package.log" 2>&1
. scripts/ci-install-candidate.sh
install_candidate "$work/install" "$evidence/install.log" .cache/ci/packages > "$evidence/verify.json"
export DEBUGLET_LOCAL_INSTALL_ROOT="$installed_root"
export DEBUGLET_LOCAL_SOURCE_SHA=$(git rev-parse HEAD)
export DEBUGLET_SOAK_EVIDENCE_DIR="$evidence"
"${GO:-go}" test -mod=readonly -json -tags=roles_integration -count=1 -timeout=5m \
    ./internal/acceptance/roles -run '^TestInstalledScheduleSoak$' | tee "$evidence/tests.json"
python3 tools/check-evidence.py --evidence "$evidence/tests.json" \
    --test ./internal/acceptance/roles:TestInstalledScheduleSoak
