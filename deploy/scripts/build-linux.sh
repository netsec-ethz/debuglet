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
    -f "${ROOT_DIR}/deploy/docker/dispatcher.Dockerfile" \
    --platform linux/amd64 \
    --output ${DIST_DIR} \
    "${ROOT_DIR}"

echo "    -> ${DIST_DIR}/debuglet-dispatcher"

# ---- Build executor ----------------------------------------------------------
echo "==> Building executor (linux/amd64)..."
docker build \
    -f "${ROOT_DIR}/deploy/docker/executor.Dockerfile" \
    --platform linux/amd64 \
    --output ${DIST_DIR} \
    "${ROOT_DIR}"

echo "    -> ${DIST_DIR}/debuglet-executor"

echo ""
echo "Build complete:"
ls -lh "${DIST_DIR}/"
