#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/ci-install-candidate.sh
bash scripts/package.sh
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-package-check.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
prefix="$work/prefix with spaces"
install_candidate "$prefix" .cache/ci/package-install.log "${CI_PACKAGE_DIR:-.cache/ci/packages}" \
    > .cache/ci/package-install.json
# The same exact candidate must be safely rerunnable.
sh "$(dirname "$archive")/install.sh" --archive "$archive" --checksums "$checksums" \
    --version "$version" --prefix "$prefix" >> .cache/ci/package-install.log
