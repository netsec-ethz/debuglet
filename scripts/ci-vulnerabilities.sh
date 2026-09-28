#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cache/ci/vulnerabilities
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export GOTOOLCHAIN=local GOTELEMETRY=off
GOBIN="$work" "${GO:-go}" install golang.org/x/vuln/cmd/govulncheck@v1.7.0
scanner="$work/govulncheck"
# The known-vulnerable tutorial module is temporary and is never built or shipped.
mkdir "$work/fixture"
cat > "$work/fixture/go.mod" <<'EOF'
module fixture.invalid/vulnerability

go 1.25.0

require golang.org/x/text v0.3.5
EOF
cat > "$work/fixture/main.go" <<'EOF'
package main
import (
    "os"
    "golang.org/x/text/language"
)
func main() { _, _ = language.Parse(os.Args[1]) }
EOF
(cd "$work/fixture" && "${GO:-go}" mod download golang.org/x/text && "$scanner" -json ./...) \
    > .cache/ci/vulnerabilities/control.json
set +e
python3 tools/check-vulnerabilities.py .cache/ci/vulnerabilities/control.json \
    tools/vulnerability-exceptions.json > .cache/ci/vulnerabilities/control.txt
status=$?
set -e
[[ $status == 1 ]] || { echo 'known vulnerable fixture was not rejected' >&2; exit 1; }
grep -q 'GO-2021-0113' .cache/ci/vulnerabilities/control.txt
# JSON mode reports findings without a nonzero status; policy is checked separately.
"$scanner" -json ./api/... ./cmd/... ./internal/... ./pkg/... ./protocol/... \
    > .cache/ci/vulnerabilities/scan.json
python3 tools/check-vulnerabilities.py .cache/ci/vulnerabilities/scan.json \
    tools/vulnerability-exceptions.json | tee .cache/ci/vulnerabilities/summary.txt
