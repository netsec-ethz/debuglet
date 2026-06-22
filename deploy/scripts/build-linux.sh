#!/usr/bin/env bash
# Build Linux x86_64 deployment artifacts via Docker.
#
# Outputs to deploy/dist/:
#   debuglet-dispatcher   - dispatcher binary
#   debuglet-executor     - executor binary (CGO_ENABLED=0, wazero runtime)
#   tagger.o              - Compiled eBPF TC egress program
#
# Usage:  ./deploy/scripts/build-linux.sh [--no-bpf]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/../dist"
BUILD_BPF=true

for arg in "$@"; do
    [ "$arg" = "--no-bpf" ] && BUILD_BPF=false
done

mkdir -p "${DIST_DIR}"

# ---- Compile eBPF tagger.o -----------------------------------------------
if $BUILD_BPF; then
    echo "==> Compiling eBPF tagger.o (linux/amd64)..."
    docker run --rm \
        --platform linux/amd64 \
        -v "${ROOT_DIR}/internal/executor/bpf/c":/bpf \
        -w /bpf \
        ubuntu:24.04 \
        bash -c "
            apt-get update -q && apt-get install -qy --no-install-recommends clang libbpf-dev linux-headers-generic 2>/dev/null
            clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
                -I/usr/include/x86_64-linux-gnu \
                -c tagger.c -o tagger.o
        "
    cp "${ROOT_DIR}/internal/executor/bpf/c/tagger.o" "${DIST_DIR}/tagger.o"
    echo "    -> ${DIST_DIR}/tagger.o"
fi

# ---- Build dispatcher --------------------------------------------------------
echo "==> Building dispatcher (linux/amd64)..."
docker build \
    -f "${ROOT_DIR}/build/package/dispatcher.Dockerfile" \
    --target builder \
    --platform linux/amd64 \
    -t debuglet-dispatcher-builder \
    "${ROOT_DIR}"

CID=$(docker create --platform linux/amd64 debuglet-dispatcher-builder)
docker cp "${CID}:/debuglet-dispatcher" "${DIST_DIR}/debuglet-dispatcher"
docker rm "${CID}" >/dev/null
chmod +x "${DIST_DIR}/debuglet-dispatcher"
echo "    -> ${DIST_DIR}/debuglet-dispatcher"

# ---- Build executor ----------------------------------------------------------
echo "==> Building executor (linux/amd64)..."
docker build \
    -f "${ROOT_DIR}/build/package/executor.Dockerfile" \
    --target builder \
    --platform linux/amd64 \
    -t debuglet-executor-builder \
    "${ROOT_DIR}"

CID=$(docker create --platform linux/amd64 debuglet-executor-builder)
docker cp "${CID}:/debuglet-executor" "${DIST_DIR}/debuglet-executor"
docker rm "${CID}" >/dev/null
chmod +x "${DIST_DIR}/debuglet-executor"
echo "    -> ${DIST_DIR}/debuglet-executor"

echo ""
echo "Build complete:"
ls -lh "${DIST_DIR}/"
