#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
package_dir="$(realpath "${DEMO_PACKAGE_DIR:-.cache/ci/packages}")"
archives=("$package_dir"/debuglet-v*-linux-amd64.tar.gz)
[[ ${#archives[@]} == 1 && -f "${archives[0]}" ]] || { echo 'expected one candidate archive' >&2; exit 1; }
archive="${archives[0]}"
version="${archive##*/debuglet-}"; version="${version%-linux-amd64.tar.gz}"
mkdir -p .cache/ci/demo-evidence
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-demo-install.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
(cd "$package_dir" && sha256sum --check SHA256SUMS)
sh "$package_dir/install.sh" --archive "$archive" --checksums "$package_dir/SHA256SUMS" \
  --version "$version" --prefix "$work/install" > .cache/ci/demo-install.log
export DEBUGLET_DEMO_INSTALL_ROOT="$work/install/lib/debuglet/$version"
export DEBUGLET_DEMO_EVIDENCE_DIR="$(realpath .cache/ci/demo-evidence)"
"${GO:-go}" test -mod=readonly -json -tags=demoacceptance -count=1 -timeout=10m \
  ./internal/demo -run '^TestInstalledDemoAcceptance$' | tee .cache/ci/demo-tests.json
# Fail if the named test disappeared or skipped; an empty suite is not evidence.
"${GO:-go}" run -mod=readonly ./internal/packaging check-demo-evidence \
  -evidence .cache/ci/demo-tests.json
