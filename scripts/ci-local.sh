#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

. scripts/ci-install-candidate.sh
mkdir -p .cache/ci
evidence="$(realpath .cache/ci)/local-evidence"
mkdir -p -m 0700 "$evidence"
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-local-install.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
install_candidate "$work/install" .cache/ci/local-install.log "${LOCAL_PACKAGE_DIR:-.cache/ci/packages}"

python3 -m unittest -v tools/test_bootstrap.py 2>&1 | tee .cache/ci/bootstrap-tests.log
export DEBUGLET_LOCAL_INSTALL_ROOT="$installed_root"
export DEBUGLET_LOCAL_SOURCE_ROOT="$PWD"
export DEBUGLET_LOCAL_SOURCE_SHA="$(git rev-parse HEAD)"
export DEBUGLET_LOCAL_EVIDENCE_DIR="$evidence"
"${GO:-go}" test -mod=readonly -json -tags=localdev_integration -count=1 -timeout=3m \
  ./internal/acceptance/localdev -run '^TestLocalDevelopment$' | tee .cache/ci/local-tests.json
python3 tools/check-evidence.py --test ./internal/acceptance/localdev:TestLocalDevelopment \
  --evidence .cache/ci/local-tests.json
bash scripts/ci-roles.sh
