#!/usr/bin/env bash
# Check that a CI lane received the pinned image it is supposed to run on, and
# record the toolchain versions that produced its results.
#
# Usage: bash deploy/ci/verify-image.sh <base|kernel|local>
#
# The check is offline. It fails when the job image differs from the pinned
# reference, when a required tool is missing, or when an installed package
# version differs from deploy/ci/packages.txt, so a substituted toolchain
# cannot pass unnoticed.
set -euo pipefail

cd "$(dirname "$0")/../.."

lane=${1:-}
case "$lane" in
    base | kernel | local) ;;
    *)
        echo "usage: $0 <base|kernel|local>" >&2
        exit 2
        ;;
esac

# shellcheck source=deploy/ci/images.env
. deploy/ci/images.env

case "$lane" in
    base)
        expected_image="${DEBUGLET_CI_BASE_IMAGE}@${DEBUGLET_CI_BASE_DIGEST}"
        required_tools=(go gcc python3 git tar sha256sum)
        pinned_packages=false
        ;;
    kernel)
        expected_image="${DEBUGLET_CI_TOOLS_IMAGE}"
        required_tools=(go gcc clang llvm-strip python3 bpftool git tar sha256sum)
        pinned_packages=true
        ;;
    local)
        expected_image="${DEBUGLET_CI_TOOLS_IMAGE}"
        required_tools=(go gcc python3 unzip git tar sha256sum)
        pinned_packages=true
        ;;
esac

failures=()
fail() { failures+=("$1"); }

# The explicit launcher supplies the reference and inspected image identity.
# Outside CI these fields may be absent for local reproduction.
job_image=${DEBUGLET_CI_JOB_IMAGE:-}
if [[ ${GITHUB_ACTIONS:-} == true && ( -z $job_image || -z ${DEBUGLET_CI_IMAGE_ID:-} ) ]]; then
    fail "GitHub CI must use scripts/ci-github.sh to record its container image"
fi
normalized_job_image=${job_image#docker.io/library/}
normalized_job_image=${normalized_job_image#docker.io/}
if [[ -n $job_image && $normalized_job_image != "$expected_image" ]]; then
    fail "job image $job_image is not the pinned $expected_image"
fi

for tool in "${required_tools[@]}"; do
    command -v "$tool" > /dev/null || fail "$lane lane requires $tool; it is not in the image"
done

go_version=""
if command -v go > /dev/null; then
    go_version=$(go env GOVERSION)
    [[ $go_version == "$DEBUGLET_CI_GO_VERSION" ]] \
        || fail "Go is $go_version but the pinned toolchain is $DEBUGLET_CI_GO_VERSION"
fi

# Both sides normalise packages.txt the same way, so the digest baked into the
# image binds it to this checked-in pin list.
normalize_pins() {
    sed -e 's/#.*//' deploy/ci/packages.txt | awk 'NF == 2 { print $1 " " $2 }' | LC_ALL=C sort
}

toolchain_digest=""
image_tools_image=""
if [[ $pinned_packages == true ]]; then
    if [[ ! -d /etc/debuglet-ci ]]; then
        fail "image does not carry /etc/debuglet-ci; it was not built from deploy/ci/Dockerfile"
    else
        expected_digest=$(normalize_pins | sha256sum | cut -d' ' -f1)
        toolchain_digest=$(cat /etc/debuglet-ci/toolchain.sha256)
        [[ $toolchain_digest == "$expected_digest" ]] \
            || fail "image toolchain digest $toolchain_digest does not match deploy/ci/packages.txt ($expected_digest)"
        image_tools_image=$(sed -n 's/^DEBUGLET_CI_TOOLS_IMAGE=//p' /etc/debuglet-ci/image.env)
        [[ $image_tools_image == "$DEBUGLET_CI_TOOLS_IMAGE" ]] \
            || fail "image was built as $image_tools_image but the lane expects $DEBUGLET_CI_TOOLS_IMAGE"
    fi
    while read -r name version; do
        installed=$(dpkg-query -W -f='${Version}' "$name" 2> /dev/null || true)
        [[ $installed == "$version" ]] \
            || fail "package $name is $installed but deploy/ci/packages.txt pins $version"
    done < <(normalize_pins)
fi

evidence_dir=.cache/ci/ci-image-evidence
mkdir -p "$evidence_dir"

python3 - "$evidence_dir/$lane-image.json" "$lane" "$expected_image" "$job_image" \
    "$go_version" "$toolchain_digest" "${failures[@]+"${failures[@]}"}" <<'PY'
import json
import os
import shutil
import subprocess
import sys

destination, lane, expected_image, job_image, go_version, toolchain_digest = sys.argv[1:7]
failures = sys.argv[7:]


def version_of(*command):
    binary = shutil.which(command[0])
    if binary is None:
        return None
    try:
        output = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False
        )
    except OSError as error:
        return f"unavailable: {error}"
    text = (output.stdout or output.stderr).strip().splitlines()
    return text[0] if text else None


def packages():
    try:
        with open("/etc/debuglet-ci/installed.txt", encoding="utf-8") as installed:
            return dict(line.split() for line in installed if line.split())
    except OSError:
        return {}


evidence = {
    "lane": lane,
    "expected_image": expected_image,
    "job_image": job_image or None,
    "image_id": os.environ.get("DEBUGLET_CI_IMAGE_ID"),
    "pipeline": {
        key.lower(): os.environ.get(key)
        for key in (
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "GITHUB_JOB",
            "GITHUB_SHA",
            "GITHUB_REF",
            "GITHUB_REF_PROTECTED",
            "RUNNER_NAME",
            "RUNNER_ENVIRONMENT",
        )
    },
    "go_version": go_version or None,
    "toolchain_digest": toolchain_digest or None,
    "tools": {
        "go": version_of("go", "version"),
        "gcc": version_of("gcc", "--version"),
        "clang": version_of("clang", "--version"),
        "llvm-strip": version_of("llvm-strip", "--version"),
        "python3": version_of("python3", "--version"),
        "bpftool": version_of("bpftool", "version"),
        "unzip": version_of("unzip", "-v"),
    },
    "packages": packages(),
    "failures": failures,
}

with open(destination, "w", encoding="utf-8") as output:
    json.dump(evidence, output, indent=2, sort_keys=True)
    output.write("\n")

summary = {
    key: evidence[key]
    for key in ("lane", "expected_image", "job_image", "go_version", "toolchain_digest")
}
print(json.dumps(summary, indent=2, sort_keys=True))
PY

if ((${#failures[@]} > 0)); then
    printf 'CI image check failed:\n' >&2
    printf '  %s\n' "${failures[@]}" >&2
    exit 1
fi

echo "CI image check passed for the $lane lane on $expected_image."
