#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

. scripts/ci-install-candidate.sh
mkdir -p .ci .cache/ci
evidence_root="$(realpath .cache/ci)/compatibility-evidence"
mkdir -m 0700 "$evidence_root"
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-compat-install.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
install_candidate "$work/install" .cache/ci/compatibility-install.log .cache/ci/packages \
    "${COMPAT_ARCHIVE:-}" "${COMPAT_SHA256SUMS:-}"
"${GO:-go}" build -mod=readonly -o .ci/local-compatibility ./internal/acceptance/canary
export DEBUGLET_CANARY_INSTALLED_ROOT="$installed_root"
export DEBUGLET_CANARY_EVIDENCE_DIR="$evidence_root"
export DEBUGLET_CANARY_DRIVER="$(realpath .ci/local-compatibility)"
export DEBUGLET_CANARY_ARCHIVE_SHA256="$archive_hash"
"${GO:-go}" test -mod=readonly -json -tags=canary_integration -count=1 -timeout=4m \
  ./internal/acceptance/canary -run '^TestCanaryLocal$' | tee .cache/ci/compatibility-tests.json
python3 tools/check-evidence.py --test ./internal/acceptance/canary:TestCanaryLocal \
  --evidence .cache/ci/compatibility-tests.json

# Guest ABI gate. The frozen guests of the published ABI must still execute on
# this candidate's host code, and the guests the candidate installs must import
# that ABI and nothing else. The installed root is the one verified above.
DEBUGLET_GUEST_ABI_INSTALLED_ROOT="$installed_root" \
  "${GO:-go}" test -mod=readonly -json -count=1 -timeout=8m \
  ./pkg/debuglet -run '^TestGuestABI' | tee .cache/ci/compatibility-guest-abi.json
# A selection that matched nothing, or a gate that skipped itself, also exits
# zero. Require the installed-guest check's own pass event.
python3 tools/check-evidence.py --test ./pkg/debuglet:TestGuestABIInstalledGuests \
  --evidence .cache/ci/compatibility-guest-abi.json
