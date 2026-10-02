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
        echo "Kernel checks require $tool; see docs/development/ci-images.md." >&2
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
sha256sum internal/executor/{ratelimit,tagger}/ebpf/*_bpfel.{o,go} > .cache/ci/ebpf-generated-before.sha256
"$ci_go" test -json -count=1 -timeout="${CI_TEST_TIMEOUT:-2m}" \
    ./internal/executor/tagger ./internal/executor/tagger/ebpf ./internal/executor/ratelimit/ebpf \
    | tee .cache/ci/kernel-tests.json
# Only the capability selection test here: it needs the loaded eBPF counter.
"$ci_go" test -json -count=1 -timeout="${CI_TEST_TIMEOUT:-2m}" \
    -run '^TestHeterogeneousExecutorCapabilitiesSelection$' ./internal/executor \
    | tee -a .cache/ci/kernel-tests.json
# Only the tagged-run listener test here: it needs the loaded eBPF tagger.
"$ci_go" test -json -count=1 -timeout="${CI_TEST_TIMEOUT:-2m}" \
    -run '^TestKernelTaggedRunBindsIPv4Only$' ./internal/executor/debuglet \
    | tee -a .cache/ci/kernel-tests.json

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
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestKernelTagMatchesGoTagger"),
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestKernelTagVectorsV1"),
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestLegacyTCAttachesAndRemovesOnlyItsFilter"),
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestCaptureTCPTagsVerifyAtReceiver"),
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestDisclosureFollowsKernelSlot"),
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger/ebpf", "TestDisclosureWaitsForEveryTagger"),
    ("github.com/netsec-ethz/debuglet/internal/executor/tagger", "TestTaggedDatagramsReachTheWire"),
    ("github.com/netsec-ethz/debuglet/internal/executor/ratelimit/ebpf", "TestBPFCounterLinuxLoad"),
    ("github.com/netsec-ethz/debuglet/internal/executor", "TestHeterogeneousExecutorCapabilitiesSelection"),
    ("github.com/netsec-ethz/debuglet/internal/executor/debuglet", "TestKernelTaggedRunBindsIPv4Only"),
}
passed = {(e.get("Package"), e.get("Test")) for e in events if e.get("Action") == "pass"}
missing = required - passed
for package, test in sorted(missing):
    print(f"Missing passing {package}/{test}; kernel checks did not run.", file=sys.stderr)
if skips or missing:
    sys.exit(1)
print("Tagger load, kernel/Go tag parity, debuglet-tag-v1 kernel vectors, legacy tc, receiver-verified TCP tagging, kernel-slot TESLA disclosure, user-space datagram tagging, packet-counter, heterogeneous capability-selection and IPv4-only tagged-run listener checks passed with zero skipped tests.")
PY

# Regenerate only after loading the committed objects. The pinned tools image
# and module's bpf2go pin must reproduce both object bytes and Go wrappers.
# A failure remains generation drift, separate from the retained load evidence.
"$ci_go" generate ./internal/executor/ratelimit/ebpf ./internal/executor/tagger/ebpf
sha256sum internal/executor/{ratelimit,tagger}/ebpf/*.o > .cache/ci/ebpf-objects-after.sha256
sha256sum internal/executor/{ratelimit,tagger}/ebpf/*_bpfel.{o,go} > .cache/ci/ebpf-generated-after.sha256

mkdir -p .cache/ci/ci-image-evidence
if diff -u .cache/ci/ebpf-generated-before.sha256 .cache/ci/ebpf-generated-after.sha256 \
    > .cache/ci/ci-image-evidence/ebpf-objects-reproduced.txt; then
    echo "Regenerating the eBPF objects and Go wrappers reproduced the committed bytes."
else
    echo "eBPF generated-source drift: regenerate the objects and Go wrappers in the pinned tools image." >&2
    echo "See .cache/ci/ci-image-evidence/ebpf-objects-reproduced.txt; kernel-load results are recorded separately." >&2
    exit 1
fi

# The shared-worker witnesses need a delegated cgroup, which is deliberately
# absent from this eBPF container. Build with the same pinned toolchain here;
# ci-github.sh runs only these binaries in a bounded, owned host unit afterward.
mkdir -p .cache/ci/shared-workers
"$ci_go" test -race -c -o .cache/ci/shared-workers/debuglet.test ./internal/executor/debuglet
"$ci_go" test -race -c -o .cache/ci/shared-workers/executor.test ./internal/executor
cp "$("$ci_go" tool -n test2json)" .cache/ci/shared-workers/test2json
