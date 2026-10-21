#!/usr/bin/env bash
# Keep test failures authoritative while retaining coverage and timing evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache/ci/coverage
rm -f .cache/ci/coverage/* .cache/ci/tests.json
set +e
"${GO:-go}" test -mod=readonly -json -count=1 -coverprofile=.cache/ci/coverage/all.out \
    -timeout="${CI_TEST_TIMEOUT:-2m}" "$@" | tee .cache/ci/tests.json
statuses=("${PIPESTATUS[@]}")
set -e
report_status=0
if [[ -s .cache/ci/coverage/all.out ]]; then
    python3 tools/test-report.py || report_status=$?
    if (( report_status == 0 )); then
        for kind in source generated; do
            "${GO:-go}" tool cover -func=".cache/ci/coverage/$kind.out" > ".cache/ci/coverage/$kind.txt" || report_status=$?
            "${GO:-go}" tool cover -html=".cache/ci/coverage/$kind.out" -o ".cache/ci/coverage/$kind.html" || report_status=$?
        done
    fi
else
    echo 'Go test did not produce a coverage profile.' >&2
    report_status=1
fi
(( statuses[0] == 0 )) || exit "${statuses[0]}"
(( statuses[1] == 0 )) || exit "${statuses[1]}"
exit "$report_status"
