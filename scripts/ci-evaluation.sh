#!/usr/bin/env bash
# The launcher supplies a loopback-only namespace and NET_ADMIN capability.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DEBUGLET_EVALUATION_ISOLATED:?Run through the isolated evaluation lane}"
: "${DEBUGLET_CI_JOB_IMAGE:?Missing pinned image identity}"
: "${DEBUGLET_CI_IMAGE_ID:?Missing resolved image identity}"
export GOPROXY=off GOSUMDB=off
mkdir -p .cache/ci/evaluation
evidence=$(mktemp -d "$PWD/.cache/ci/evaluation/run.XXXXXXXX")
work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-evaluation.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
git rev-parse HEAD > "$evidence/source.txt"
go version > "$evidence/toolchain.txt"
uname -sr >> "$evidence/toolchain.txt"
tc -V >> "$evidence/toolchain.txt"
make ci-build ci-package > "$evidence/package.log" 2>&1
. scripts/ci-install-candidate.sh
install_candidate "$work/install" "$evidence/install.log" .cache/ci/packages > "$evidence/verify.json"
"${GO:-go}" build -mod=readonly -o "$work/latency-native" ./examples/debuglets/go/latency/evaluation
GOOS=wasip1 GOARCH=wasm "${GO:-go}" build -mod=readonly -o "$work/latency.wasm" ./examples/debuglets/go/latency/evaluation
sha256sum "$work/latency-native" "$work/latency.wasm" > "$evidence/probe-hashes.txt"
export DEBUGLET_LOCAL_INSTALL_ROOT="$installed_root"
export DEBUGLET_LOCAL_SOURCE_SHA=$(git rev-parse HEAD)
export DEBUGLET_EVALUATION_EVIDENCE_DIR="$evidence"
export DEBUGLET_EVALUATION_NATIVE="$work/latency-native" DEBUGLET_EVALUATION_WASM="$work/latency.wasm"
"${GO:-go}" test -mod=readonly -json -tags=evaluation_integration -count=1 -timeout=10m \
    ./internal/acceptance/evaluation -run '^TestControlledNetworkEvaluation$' | tee "$evidence/tests.json"
python3 tools/check-evidence.py --evidence "$evidence/tests.json" \
    --test ./internal/acceptance/evaluation:TestControlledNetworkEvaluation
# Re-read the saved export files after the test has joined the daemons.
"${GO:-go}" run -mod=readonly ./internal/acceptance/evaluation "$evidence" > "$evidence/reproduced-summary.json"
python3 - "$evidence/summary.json" "$evidence/reproduced-summary.json" <<'PY'
import json, sys
with open(sys.argv[1]) as first, open(sys.argv[2]) as second:
    if json.load(first) != json.load(second):
        raise SystemExit('saved export analysis did not reproduce the same results')
PY
