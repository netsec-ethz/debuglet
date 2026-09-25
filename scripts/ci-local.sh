#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

package_dir="$(realpath "${LOCAL_PACKAGE_DIR:-.cache/ci/packages}")"
archives=("$package_dir"/debuglet-v*-linux-amd64.tar.gz)
[[ ${#archives[@]} == 1 && -f "${archives[0]}" ]] || { echo 'expected one candidate archive' >&2; exit 1; }
archive="${archives[0]}"
version="${archive##*/debuglet-}"; version="${version%-linux-amd64.tar.gz}"
mkdir -p .cache/ci
evidence="$(realpath .cache/ci)/local-evidence"
mkdir -p -m 0700 "$evidence"
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-local-install.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
(cd "$package_dir" && sha256sum --check --strict SHA256SUMS)
sh "$package_dir/install.sh" --archive "$archive" --checksums "$package_dir/SHA256SUMS" \
  --version "$version" --prefix "$work/install" > .cache/ci/local-install.log
"${GO:-go}" run -mod=readonly ./internal/packaging verify \
  -installed-root "$work/install/lib/debuglet/$version"

python3 -m unittest -v tools/test_bootstrap.py 2>&1 | tee .cache/ci/bootstrap-tests.log
export DEBUGLET_LOCAL_INSTALL_ROOT="$work/install/lib/debuglet/$version"
export DEBUGLET_LOCAL_SOURCE_ROOT="$PWD"
export DEBUGLET_LOCAL_SOURCE_SHA="$(git rev-parse HEAD)"
export DEBUGLET_LOCAL_EVIDENCE_DIR="$evidence"
"${GO:-go}" test -mod=readonly -json -tags=localdev_integration -count=1 -timeout=3m \
  ./internal/acceptance/localdev -run '^TestLocalDevelopment$' | tee .cache/ci/local-tests.json
"${GO:-go}" run -mod=readonly ./internal/packaging check-local-evidence \
  -evidence .cache/ci/local-tests.json
bash scripts/ci-roles.sh
