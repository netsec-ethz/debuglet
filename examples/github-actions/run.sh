#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
set +x
set -euo pipefail
: "${DEBUGLET_CONSOLE_URL:?}" "${DEBUGLET_ENDPOINT:?}" "${DEBUGLET_EXECUTOR:?}" "${DEBUGLET_TARGET:?}"
: "${DEBUGLET_TOKEN_FILE:?}" "${DEBUGLET_WASM:?}" "${DEBUGLET_MAX_CONNECT_MS:?}"
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
result_dir=${DEBUGLET_RESULTS_DIR:-$PWD/results}
mkdir -p "$result_dir"
result_dir=$(cd -- "$result_dir" && pwd)
destination=$(python3 -c 'import ipaddress,os,urllib.parse; u=urllib.parse.urlsplit("//"+os.environ["DEBUGLET_TARGET"]); assert u.port and not u.path; print(ipaddress.ip_address(u.hostname))')
private_dir=$(mktemp -d)
chmod 700 "$private_dir"
cli=("${DBL:-dbl}" --config "$private_dir/connections.json" --output json)
run_id=
read_run_id() {
    python3 -c 'import json,sys,uuid; r=json.load(open(sys.argv[1])); print(uuid.UUID(r["id"]))' "$result_dir/receipt.json"
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [[ -z $run_id && -s $result_dir/receipt.json ]]; then
        run_id=$(read_run_id 2>/dev/null) || true
    fi
    if [[ -n $run_id && $status -ne 0 ]]; then
        "${cli[@]}" --timeout 5s cancel "$run_id" > "$result_dir/cancel.json" 2> "$result_dir/cancel.stderr" || true
        "${cli[@]}" --timeout 5s export "$run_id" > "$result_dir/result-after-cancel.json" 2> "$result_dir/export-after-cancel.stderr" || true
    fi
    rm -rf -- "$private_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
"${cli[@]}" connect "$DEBUGLET_ENDPOINT" --name ci > /dev/null
"${cli[@]}" login --token-file "$DEBUGLET_TOKEN_FILE" --credential-store file > /dev/null
# The host budget bounds work even if the runner is force-killed before cleanup.
run_status=0
"${cli[@]}" --timeout 45s run --wasm "$DEBUGLET_WASM" --executor "$DEBUGLET_EXECUTOR" \
    --protocol tcp --allow "$destination" --duration 10s --floor-bps 0 --ceil-bps 1000000 \
    --allow-remote-test --wait -- "$DEBUGLET_TARGET" \
    > "$result_dir/receipt.json" 2> "$result_dir/run.stderr" || run_status=$?
run_id=$(read_run_id)
printf '%s/debuglet/%s\n' "${DEBUGLET_CONSOLE_URL%/}" "$run_id" | tee "$result_dir/run-url.txt"
# Workload exit and final output delivery are independent. Wait briefly for the
# final retained chunks; assert_result rejects truncation or an unfinished stream.
for attempt in {1..10}; do
    "${cli[@]}" --timeout 5s export "$run_id" > "$result_dir/result.json"
    if python3 -c 'import json,sys; sys.exit(json.load(open(sys.argv[1]))["output"]["status"]["state"] != "complete")' "$result_dir/result.json"; then
        break
    fi
    sleep 1
done
[[ $run_status -eq 0 ]] || exit "$run_status"
python3 "$script_dir/assert_result.py" "$result_dir/result.json" "$DEBUGLET_TARGET" "$DEBUGLET_MAX_CONNECT_MS"
