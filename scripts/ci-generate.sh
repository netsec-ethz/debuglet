#!/usr/bin/env bash
# Regenerate the tracked protocol and database bindings with the generators
# pinned in mise.toml, then compare the result with the committed sources.
#
#   scripts/ci-generate.sh [check]      fail on any difference, keep the diff
#   scripts/ci-generate.sh write        replace the tracked generated sources
#   scripts/ci-generate.sh write-proto  only the protocol bindings
#   scripts/ci-generate.sh write-sql    only the database bindings
#
# Generation runs entirely through the Go toolchain. No protocol compiler and
# no distribution packages are installed; the pinned generators are fetched
# from the Go module proxy on their first use and served from the module cache
# afterwards. A generator that cannot be fetched, reports an unexpected
# version or fails, and every difference between a fresh generation and the
# committed sources, fails the run. Nothing outside the generated sources is
# written, and nothing is regenerated in place unless a write mode is asked
# for.
#
# This compares generator output with what is committed. It does not review
# whether a protocol change stays compatible on the wire, and it does not
# upgrade or inspect a database that already holds rows.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-check}"
case "$mode" in
check | write | write-proto | write-sql) ;;
*)
    echo "usage: scripts/ci-generate.sh [check|write|write-proto|write-sql]" >&2
    exit 2
    ;;
esac

GO="${GO:-go}"
evidence="${CI_GENERATION_EVIDENCE:-.cache/ci/generation}"

fail() {
    echo "ci-generate: $*" >&2
    exit 1
}

# mise.toml is the single place the generator versions are pinned.
mise_pin() {
    local key="$1" value
    value="$(sed -n -E "s#^[[:space:]]*\"?${key}\"?[[:space:]]*=[[:space:]]*\"([^\"]+)\".*#\1#p" mise.toml |
        head -n 1)"
    [[ -n "$value" ]] || fail "mise.toml does not pin $key"
    printf '%s' "$value"
}

# The generator directories recorded in sqlc.yml, as "key value" lines. A
# value that is not a quoted directory is rejected rather than silently
# skipped, so a reworded configuration cannot drop an input.
sqlc_entries() {
    local line trimmed value
    while IFS= read -r line; do
        trimmed="${line#"${line%%[![:space:]]*}"}"
        case "$trimmed" in
        queries:* | schema:* | out:*) ;;
        *) continue ;;
        esac
        value="$(printf '%s' "$trimmed" |
            sed -n -E 's#^[a-z]+:[[:space:]]*"([^"]+)"[[:space:]]*$#\1#p')"
        [[ -n "$value" ]] || fail "sqlc.yml: $trimmed does not name a quoted directory"
        printf '%s %s\n' "${trimmed%%:*}" "$value"
    done <sqlc.yml
}

command -v "$GO" >/dev/null || fail "no Go toolchain on PATH; see CONTRIBUTING.md"

protoc_pin="$(mise_pin protoc)"
protoc_gen_go_pin="$(mise_pin protoc-gen-go)"
protoc_gen_go_grpc_pin="$(mise_pin protoc-gen-go-grpc)"
sqlc_pin="$(mise_pin sqlc)"
buf_pin="$(mise_pin go:github.com/bufbuild/buf/cmd/buf)"

# The pinned sqlc release declares a newer Go than this project builds with,
# so it alone is compiled with the toolchain its own module names instead of
# whichever patch release happens to be current. A future sqlc that needs more
# than this fails the run rather than picking a toolchain on its own. Nothing
# else in this script or in the project uses it.
sqlc_toolchain="go1.26.2"

# The canonical protocol definition and the generator parameters that produced
# the committed sources.
proto_target="protocol/protocol.proto"
proto_parameter="paths=source_relative,Mschema.proto=."

# Both halves together produce this many files: two protocol bindings and eight
# database bindings. A comparison of fewer than that means the generators or
# the configuration stopped covering something, so it is a failure rather than
# a match. Raise it when a generator starts producing more.
minimum_generated=10

# protoc reports itself with a leading component that is not part of the
# release number pinned in mise.toml: release 34.0 reports 7.34.0, and that
# reported form is what the generated file headers record. Any mistake here
# shows up as a difference in the comparison below.
protoc_reported="7.${protoc_pin}"

want_proto=1
want_sql=1
case "$mode" in
write-proto) want_sql=0 ;;
write-sql) want_proto=0 ;;
esac

work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-generate.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
bin="$work/bin"
committed="$work/committed"
regenerated="$work/regenerated"
mkdir -p "$bin" "$committed" "$regenerated"

install_generator() {
    local module="$1" binary="$2" expected="$3" reported
    GOBIN="$bin" "$GO" install "$module" || fail "cannot install $module"
    [[ -x "$bin/$binary" ]] || fail "$module did not install $binary"
    reported="$("$bin/$binary" --version 2>&1)" || fail "$binary does not report its version"
    [[ "$reported" == "$expected" ]] ||
        fail "$binary reports \"$reported\" where mise.toml pins \"$expected\""
}

# Copy one repository-relative file into a comparison tree.
place() {
    local destination="$1" source="$2" relative="$3"
    mkdir -p "$destination/$(dirname "$relative")"
    cp "$source/$relative" "$destination/$relative"
}

# Generated bindings carry a header the hand-written files in the same
# directory do not, so stale output is found without a manifest.
sqlc_outputs() {
    local directory="$1" file
    for file in "$directory"/*.go; do
        [[ -f "$file" ]] || continue
        [[ "$(head -n 1 "$file")" == "// Code generated by sqlc. DO NOT EDIT." ]] || continue
        printf '%s\n' "$file"
    done
}

generate_proto() {
    install_generator "google.golang.org/protobuf/cmd/protoc-gen-go@v${protoc_gen_go_pin}" \
        protoc-gen-go "protoc-gen-go v${protoc_gen_go_pin}"
    install_generator "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${protoc_gen_go_grpc_pin}" \
        protoc-gen-go-grpc "protoc-gen-go-grpc ${protoc_gen_go_grpc_pin}"
    [[ -f "$proto_target" ]] || fail "$proto_target is missing"
    "$GO" run "github.com/bufbuild/buf/cmd/buf@v${buf_pin}" build \
        --as-file-descriptor-set -o "$work/protocol.descriptorset" ||
        fail "cannot compile $proto_target"
    "$GO" run -mod=readonly ./internal/protogen \
        -descriptor-set "$work/protocol.descriptorset" \
        -target "$proto_target" \
        -parameter "$proto_parameter" \
        -compiler-version "$protoc_reported" \
        -out "$regenerated" \
        "$bin/protoc-gen-go" "$bin/protoc-gen-go-grpc" ||
        fail "cannot generate the protocol bindings"

    local file
    for file in protocol/*.pb.go; do
        [[ -f "$file" ]] || continue
        place "$committed" . "$file"
    done
}

generate_sql() {
    local reported directory file relative mirror="$work/sql"
    reported="$(GOTOOLCHAIN="$sqlc_toolchain" "$GO" run "github.com/sqlc-dev/sqlc/cmd/sqlc@v${sqlc_pin}" version)" ||
        fail "cannot run sqlc v${sqlc_pin} with $sqlc_toolchain"
    [[ "$reported" == "v${sqlc_pin}" ]] ||
        fail "sqlc reports \"$reported\" where mise.toml pins \"v${sqlc_pin}\""

    # The generator reads its inputs from a copy, so a check writes nothing
    # into the checkout it is inspecting. The copy takes the directories as
    # they are: an untracked .sql file in one of them is generated from like
    # any other, in a check and in a write alike.
    mkdir -p "$mirror"
    cp sqlc.yml "$mirror/sqlc.yml"
    for directory in "${sqlc_inputs[@]}"; do
        [[ -d "$directory" ]] || fail "sqlc.yml names $directory, which is not a directory"
        mkdir -p "$mirror/$directory"
        cp -R "$directory/." "$mirror/$directory/"
    done
    (cd "$mirror" && GOTOOLCHAIN="$sqlc_toolchain" "$GO" run \
        "github.com/sqlc-dev/sqlc/cmd/sqlc@v${sqlc_pin}" generate) ||
        fail "cannot generate the database bindings"

    for directory in "${sqlc_generated[@]}"; do
        while IFS= read -r file; do
            place "$committed" . "$file"
        done < <(sqlc_outputs "$directory")
        [[ -d "$mirror/$directory" ]] || fail "sqlc wrote nothing to $directory"
        while IFS= read -r file; do
            relative="${file#"$mirror"/}"
            place "$regenerated" "$mirror" "$relative"
        done < <(sqlc_outputs "$mirror/$directory")
    done
}

# Replace the tracked generated sources with the fresh generation and drop the
# files the pinned generators no longer produce.
adopt() {
    local relative
    while IFS= read -r relative; do
        mkdir -p "$(dirname "$relative")"
        cp "$regenerated/$relative" "$relative"
        echo "ci-generate: wrote $relative"
    done < <(cd "$regenerated" && find . -type f | sed 's#^\./##' | sort)
    while IFS= read -r relative; do
        if [[ ! -f "$regenerated/$relative" ]]; then
            rm -f -- "$relative"
            echo "ci-generate: removed $relative, which the pinned generators no longer produce"
        fi
    done < <(cd "$committed" && find . -type f | sed 's#^\./##' | sort)
}

# Reading the configuration through a command substitution keeps a rejected
# sqlc.yml fatal instead of letting an unreadable line shorten the list.
sqlc_configured="$(sqlc_entries)"
sqlc_inputs=()
sqlc_generated=()
while read -r key value; do
    case "$key" in
    queries | schema) sqlc_inputs+=("$value") ;;
    out) sqlc_generated+=("$value") ;;
    esac
done <<<"$sqlc_configured"
((${#sqlc_inputs[@]} > 0)) || fail "sqlc.yml declares no query or schema directory"
((${#sqlc_generated[@]} > 0)) || fail "sqlc.yml declares no output directory"

# The artifact directory exists before the generators run, so a job that fails
# while generating still publishes whatever it managed to record.
if [[ "$mode" == check ]]; then
    mkdir -p "$evidence"
fi

((want_proto == 0)) || generate_proto
((want_sql == 0)) || generate_sql

if [[ "$mode" != check ]]; then
    adopt
    exit 0
fi

produced="$(cd "$regenerated" && find . -type f | wc -l | tr -d ' ')"
((produced >= minimum_generated)) ||
    fail "the pinned generators produced $produced files, fewer than the $minimum_generated this repository has"

# The comparison runs first: a generated source that was edited or deleted
# shows up as a difference rather than as a compile error in the checks below.
drifted=0
status=0
(cd "$work" && diff -ruN committed regenerated) >"$evidence/generation.diff" || status=$?
case "$status" in
0)
    rm -f "$evidence/generation.diff"
    (cd "$committed" && find . -type f | sed 's#^\./##' | sort) >"$evidence/compared.txt"
    echo "ci-generate: $(wc -l <"$evidence/compared.txt" | tr -d ' ') generated files match the pinned generators"
    ;;
1)
    drifted=1
    echo "ci-generate: the committed sources differ from a fresh generation:" >&2
    sed -n '1,200p' "$evidence/generation.diff" >&2
    echo "ci-generate: full difference in $evidence/generation.diff" >&2
    ;;
*)
    fail "cannot compare the committed sources with the fresh generation"
    ;;
esac

# Both results are reported even when the first one already failed, so one run
# says everything that is wrong.
checked=0
if ! "$GO" test -mod=readonly -json -count=1 -timeout="${CI_TEST_TIMEOUT:-2m}" \
    ./internal/schemacheck | tee "$evidence/schema-tests.json"; then
    checked=1
    echo "ci-generate: the schema checks failed; see $evidence/schema-tests.json" >&2
fi

if ((drifted == 1)); then
    echo "ci-generate: regenerate with scripts/ci-generate.sh write and commit the result" >&2
fi
((drifted == 0 && checked == 0)) || exit 1
