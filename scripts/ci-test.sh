#!/usr/bin/env bash
# Preserve go test's failure status while retaining structured test evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache/ci
"${GO:-go}" test -mod=readonly -json -count=1 \
    -timeout="${CI_TEST_TIMEOUT:-2m}" "$@" | tee .cache/ci/tests.json
