#!/usr/bin/env bash
# Build Linux x86_64 deployment artifacts via Docker.
#
# Outputs to deploy/dist/:
#   debuglet-dispatcher   - dispatcher binary
#   debuglet-executor     - executor binary (CGO_ENABLED=0, wazero runtime)
#
# Usage:  ./deploy/scripts/build-linux.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/../dist"

mkdir -p "${DIST_DIR}"

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
