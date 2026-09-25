#!/usr/bin/env bash
# Report tracked Go files whose formatting differs from the supported
# toolchain's gofmt. The checkout is never rewritten: the developer applies the
# printed command. Only tracked files are examined, so ignored build and cache
# directories are never traversed and generated Go files are checked exactly
# like handwritten ones.
set -euo pipefail
cd "$(dirname "$0")/.."

git rev-parse --git-dir >/dev/null 2>&1 || {
    echo 'The formatting check reads tracked files from a git checkout.' >&2
    exit 1
}

# Use the gofmt of the pinned toolchain (mise.toml) rather than whatever gofmt
# happens to be on PATH; formatting differs between Go releases.
gofmt_bin="${GOFMT:-}"
if [[ -z "$gofmt_bin" ]]; then
    goroot="$("${GO:-go}" env GOROOT)"
    gofmt_bin="$goroot/bin/gofmt"
fi
[[ -x "$gofmt_bin" ]] || {
    echo "Missing gofmt from the supported Go toolchain: $gofmt_bin" >&2
    exit 1
}

files=()
while IFS= read -r -d '' file; do files+=("$file"); done < <(git ls-files -z -- '*.go')
(( ${#files[@]} > 0 )) || { echo 'No tracked Go source found.' >&2; exit 1; }

mkdir -p .cache/ci
report=.cache/ci/gofmt.txt
errors="$(mktemp "${TMPDIR:-/tmp}/debuglet-gofmt.XXXXXXXX")"
trap 'rm -f -- "$errors"' EXIT

set +e
"$gofmt_bin" -l -e -- "${files[@]}" 2>"$errors" | LC_ALL=C sort >"$report"
status=${PIPESTATUS[0]}
set -e
if (( status != 0 )); then
    cat -- "$errors" >&2
    echo "gofmt failed on tracked Go source (exit $status)." >&2
    exit 1
fi
if [[ -s "$errors" ]]; then
    cat -- "$errors" >&2
    echo 'gofmt reported errors on tracked Go source.' >&2
    exit 1
fi

if [[ -s "$report" ]]; then
    echo "Unformatted tracked Go files ($(wc -l <"$report" | tr -d ' ')), also listed in $report:" >&2
    sed 's/^/  /' "$report" >&2
    echo 'Format them with the supported toolchain, then commit the result:' >&2
    echo '  "$(go env GOROOT)/bin/gofmt" -w $(git ls-files "*.go")' >&2
    exit 1
fi

echo "gofmt: ${#files[@]} tracked Go files are formatted."
