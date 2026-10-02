#!/usr/bin/env bash
# Run the compiled shared-worker witnesses in one disposable cgroup delegation.
set -euo pipefail
cd "$(dirname "$0")/.."

evidence="$PWD/.cache/ci/ci-image-evidence/shared-workers"
mkdir -p "$evidence"
rm -f "$evidence/summary.json" "$evidence/cgroup-path.txt" "$evidence/cleanup.json"
for binary in debuglet.test executor.test test2json; do
    [[ -x .cache/ci/shared-workers/$binary ]] || {
        echo "Missing $binary; run the pinned kernel build first." >&2
        exit 1
    }
done

unit="debuglet-ci-shared-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$.service"
runner=(systemd-run --user)
manager=(systemctl --user)
identity=()
if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    runner=(sudo -n systemd-run)
    manager=(sudo -n systemctl)
    identity=(--property="User=$(id -u)" --property="Group=$(id -g)" --property=CapabilityBoundingSet=)
fi
cleanup() {
    local status=$? root=""
    # systemd owns this exact transient unit and kills its entire cgroup on
    # stop. Never enumerate, kill or remove any other unit or host subtree.
    "${manager[@]}" stop "$unit" >/dev/null 2>&1 || true
    if [[ -f $evidence/cgroup-path.txt ]]; then
        root=$(cat "$evidence/cgroup-path.txt")
        for _ in {1..20}; do
            [[ ! -e $root ]] && break
            sleep 0.1
        done
        if [[ -e $root ]]; then
            echo "Shared-worker unit cgroup remains after stop: $root" >&2
            status=1
        fi
    fi
    python3 - "$evidence/cleanup.json" "$unit" "$root" "$status" <<'PY'
import json, os, sys
destination, unit, root, status = sys.argv[1:]
with open(destination, 'w', encoding='utf-8') as output:
    json.dump({'unit': unit, 'cgroup': root, 'removed': bool(root) and not os.path.exists(root),
               'test_status': int(status)}, output, indent=2)
    output.write('\n')
PY
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Clear inherited Actions credentials and require an unprivileged test driver.
# The existing eBPF container keeps its original namespace/mount boundary.
# A local reproduction uses the user's existing systemd manager.
"${runner[@]}" --quiet --wait --pipe --collect --unit="$unit" \
    "${identity[@]}" --property="Delegate=cpu memory pids" \
    --property=MemoryMax=5G --property=MemorySwapMax=0 --property=CPUQuota=300% \
    --property=TasksMax=512 --property=RuntimeMaxSec=240 --property=TimeoutStopSec=10 \
    --property=NoNewPrivileges=yes \
    --property="WorkingDirectory=$PWD" \
    /usr/bin/env -i PATH=/usr/bin:/bin GOMAXPROCS=3 \
    /usr/bin/python3 "$PWD/deploy/ci/shared-workers.py" "$unit"
