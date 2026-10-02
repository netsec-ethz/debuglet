#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/ci-install-candidate.sh
bash scripts/package.sh
(cd "${CI_PACKAGE_DIR:-.cache/ci/packages}" && sha256sum --check --strict SHA256SUMS-compatibility)
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-package-check.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
prefix="$work/prefix with spaces"
install_candidate "$prefix" .cache/ci/package-install.log "${CI_PACKAGE_DIR:-.cache/ci/packages}" \
    > .cache/ci/package-install.json
# The same exact candidate must be safely rerunnable.
sh "$(dirname "$archive")/install.sh" --archive "$archive" --checksums "$checksums" \
    --version "$version" --prefix "$prefix" >> .cache/ci/package-install.log

# Role packages coexist at one prefix and only publish their own command link.
role_prefix="$work/roles with spaces"
for component in cli executor dispatcher; do
    package_dir="${CI_PACKAGE_DIR:-.cache/ci/packages}/$component"
    role_archive="$package_dir/debuglet-$component-$version-linux-amd64.tar.gz"
    (cd "$package_dir" && sha256sum --check --strict "SHA256SUMS-$component")
    for attempt in 1 2; do
        sh "$package_dir/install-$component.sh" --archive "$role_archive" --checksums "$package_dir/SHA256SUMS-$component" \
            --version "$version" --prefix "$role_prefix" >> .cache/ci/package-install.log
    done
    "${GO:-go}" run -mod=readonly ./internal/packaging verify \
        -installed-root "$role_prefix/lib/debuglet/$component/$version" \
        > ".cache/ci/package-install-$component.json"
    binary=debuglet-$component
    [[ "$component" != cli ]] || binary=dbl
    "$role_prefix/bin/$binary" --help >> .cache/ci/package-install.log 2>&1
    [[ $(find "$role_prefix/lib/debuglet/$component/$version/bin" -type f | wc -l) == 1 ]]
done
for binary in dbl debuglet-executor debuglet-dispatcher; do
    [[ -x "$role_prefix/bin/$binary" ]]
done
