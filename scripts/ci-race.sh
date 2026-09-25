#!/usr/bin/env bash
# Run the concurrency-sensitive native packages under the race detector and
# keep their Go JSON results. The caller passes explicit package roots, so WASI
# samples are never built or executed as host tests. Package parallelism is
# bounded: oversubscribing a shared runner turns bounded lifecycle waits into
# spurious failures.
set -euo pipefail
cd "$(dirname "$0")/.."
(( $# > 0 )) || { echo 'The race lane needs explicit native package roots.' >&2; exit 1; }
command -v python3 >/dev/null || {
    echo 'The race lane needs python3 to check its results; see docs/ci.md.' >&2
    exit 1
}
parallel="${CI_RACE_PACKAGE_PARALLEL:-2}"
[[ "$parallel" =~ ^[1-9][0-9]*$ ]] || {
    echo 'CI_RACE_PACKAGE_PARALLEL must be a positive integer.' >&2
    exit 1
}

mkdir -p .cache/ci
rm -f .cache/ci/race-tests.json
set +e
GORACE="strip_path_prefix=$PWD/" "${GO:-go}" test -mod=readonly -race -json -count=1 \
    -p "$parallel" -timeout="${CI_RACE_TIMEOUT:-5m}" "$@" | tee .cache/ci/race-tests.json
test_status=${PIPESTATUS[0]}
set -e

# Go treats a package without tests, and one whose tests all skipped, as a
# success; require executed tests and reject retained race reports.
check_status=0
python3 tools/check-race-evidence.py --evidence .cache/ci/race-tests.json \
    --budget-seconds "${CI_RACE_BUDGET_SECONDS:-240}" "$@" || check_status=$?
(( test_status == 0 )) || exit "$test_status"
exit "$check_status"
