#!/usr/bin/env bash
# Run in an isolated Linux container: this attaches eBPF to its loopback.
set -euo pipefail

cd "$(dirname "$0")/.."
if [[ $(uname -s) != Linux ]]; then
    echo "Kernel checks require an isolated Linux kernel runner." >&2
    exit 1
fi

for tool in clang llvm-strip gcc python3; do
    command -v "$tool" >/dev/null || {
        echo "Kernel checks require $tool; see docs/ci-images.md." >&2
        exit 1
    }
done

ci_go=${GO:-go}
export GOFLAGS="${GOFLAGS:-} -mod=readonly"
export BPF2GO_CFLAGS="${BPF2GO_CFLAGS:-} -I/usr/include/$(gcc -print-multiarch)"

mkdir -p .cache/ci

# Record the job container boundary, then bracket the kernel
# work with ownership snapshots. The comparison runs even when the checks below
# fail and never replaces their exit status with its own.
python3 deploy/ci/kernel-isolation.py assert
python3 deploy/ci/kernel-isolation.py snapshot before
release_ownership() {
    local status=$?
    python3 deploy/ci/kernel-isolation.py snapshot after || status=1
    python3 deploy/ci/kernel-isolation.py compare || status=1
    exit "$status"
}
trap release_ownership EXIT

# Test the committed objects: these are the bytes ci-build embeds.
sha256sum internal/executor/{ratelimit,tagger}/ebpf/*.o > .cache/ci/ebpf-objects-before.sha256
"$ci_go" test -json -count=1 -timeout="${CI_TEST_TIMEOUT:-2m}" \
    ./internal/executor/tagger/ebpf ./internal/executor/ratelimit/ebpf \
    | tee .cache/ci/kernel-tests.json

# Go considers t.Skip a successful exit, so enforce actual kernel evidence.
python3 - .cache/ci/kernel-tests.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as results:
    events = [json.loads(line) for line in results if line.strip()]

skips = [e for e in events if e.get("Action") == "skip"]
for event in skips:
    print(f"Unexpected skip: {event.get('Package')} {event.get('Test', '')}", file=sys.stderr)

required = {
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestBPFLinuxLoad"),
    ("github.com/netsec-ethz/debuglet/internal/executor/ratelimit/ebpf", "TestBPFCounterLinuxLoad"),
}
passed = {(e.get("Package"), e.get("Test")) for e in events if e.get("Action") == "pass"}
missing = required - passed
for package, test in sorted(missing):
    print(f"Missing passing {package}/{test}; kernel checks did not run.", file=sys.stderr)
if skips or missing:
    sys.exit(1)
print("Tagger load and packet-counter load/close checks passed with zero skipped tests.")
PY

# Separately prove that the checked-in C sources compile with this toolchain.
# Compiler-version differences can change the bytecode. Record both hashes;
# generated objects are not substituted into ci-build's diagnostic artifacts.
"$ci_go" generate ./internal/executor/ratelimit/ebpf ./internal/executor/tagger/ebpf
sha256sum internal/executor/{ratelimit,tagger}/ebpf/*.o > .cache/ci/ebpf-objects-after.sha256

# Say plainly whether this image's compiler reproduced the committed bytes, so
# a changed toolchain input is visible in the job log instead of only in two
# hash files.
mkdir -p .cache/ci/ci-image-evidence
if diff -u .cache/ci/ebpf-objects-before.sha256 .cache/ci/ebpf-objects-after.sha256 \
    > .cache/ci/ci-image-evidence/ebpf-objects-reproduced.txt; then
    echo "Regenerating the eBPF objects reproduced the committed bytes."
else
    echo "Regenerated eBPF objects differ from the committed bytes; see" \
        ".cache/ci/ci-image-evidence/ebpf-objects-reproduced.txt."
fi
