#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec "${GO:-go}" run -mod=readonly ./internal/packaging package \
  -dist "${CI_DIST:-.cache/ci/dist}" -out "${CI_PACKAGE_DIR:-.cache/ci/packages}"
