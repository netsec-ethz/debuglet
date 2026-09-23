#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/package.sh
package_dir="${CI_PACKAGE_DIR:-.cache/ci/packages}"
archives=("$package_dir"/debuglet-v*-linux-amd64.tar.gz)
[[ ${#archives[@]} == 1 && -f "${archives[0]}" ]] || { echo 'expected one candidate archive' >&2; exit 1; }
archive="$(realpath "${archives[0]}")"
package_dir="$(realpath "$package_dir")"
version="${archive##*/debuglet-}"; version="${version%-linux-amd64.tar.gz}"
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-package-check.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
prefix="$work/prefix with spaces"
# Verify both downloaded files before executing the candidate-specific installer.
(cd "$package_dir" && sha256sum --check SHA256SUMS)
sh "$package_dir/install.sh" --archive "$archive" --checksums "$package_dir/SHA256SUMS" \
  --version "$version" --prefix "$prefix" > .cache/ci/package-install.log
"${GO:-go}" run -mod=readonly ./internal/packaging verify \
  -installed-root "$prefix/lib/debuglet/$version" > .cache/ci/package-install.json
# The same exact candidate must be safely rerunnable.
sh "$package_dir/install.sh" --archive "$archive" --checksums "$package_dir/SHA256SUMS" \
  --version "$version" --prefix "$prefix" >> .cache/ci/package-install.log
