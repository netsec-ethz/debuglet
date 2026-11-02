#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/ci-install-candidate.sh
mkdir -p .cache/ci/demo-evidence
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-demo-install.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
# Retry dependency transport failures before installation and acceptance. The
# acceptance test itself still runs exactly once, with its failure preserved.
for attempt in 1 2 3; do
    if timeout 180s "${GO:-go}" mod download; then
        break
    else
        status=$?
    fi
    if [[ $attempt == 3 ]]; then
        echo 'module download failed after three attempts' >&2
        exit "$status"
    fi
    echo "module download attempt $attempt failed; retrying" >&2
    sleep 2
done
install_candidate "$work/install" .cache/ci/demo-install.log "${DEMO_PACKAGE_DIR:-.cache/ci/packages}"
export DEBUGLET_DEMO_INSTALL_ROOT="$installed_root"
export DEBUGLET_DEMO_EVIDENCE_DIR="$(realpath .cache/ci/demo-evidence)"
"${GO:-go}" test -mod=readonly -json -tags=demoacceptance -count=1 -timeout=10m \
  ./internal/demo -run '^TestInstalledDemoAcceptance$' | tee .cache/ci/demo-tests.json
# Fail if the named test disappeared or skipped; an empty suite is not evidence.
python3 tools/check-evidence.py --test ./internal/demo:TestInstalledDemoAcceptance \
  --evidence .cache/ci/demo-tests.json
