#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
package_dir=${CI_PACKAGE_DIR:-.cache/ci/packages}
"${GO:-go}" run -mod=readonly ./internal/packaging package \
  -dist "${CI_DIST:-.cache/ci/dist}" -out "$package_dir"
for component in cli executor dispatcher; do
  "${GO:-go}" run -mod=readonly ./internal/packaging package \
    -dist "${CI_DIST:-.cache/ci/dist}" -out "$package_dir/$component" -component "$component"
done
