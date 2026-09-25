#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -n "${COMPAT_ARCHIVE:-}" ]]; then
  archive="$(realpath -e "$COMPAT_ARCHIVE")"
else
  archives=(.cache/ci/packages/debuglet-v*-linux-amd64.tar.gz)
  [[ ${#archives[@]} == 1 && -f "${archives[0]}" ]] || { echo 'expected one candidate archive' >&2; exit 1; }
  archive="$(realpath -e "${archives[0]}")"
fi
package_dir="$(dirname "$archive")"
checksums="$(realpath -e "${COMPAT_SHA256SUMS:-$package_dir/SHA256SUMS}")"
archive_name="$(basename "$archive")"
[[ "$archive_name" =~ ^debuglet-v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?-linux-amd64\.tar\.gz$ ]] || { echo 'invalid candidate archive name' >&2; exit 1; }
[[ -f "$archive" && -f "$package_dir/install.sh" && -f "$checksums" ]] || { echo 'missing candidate inputs' >&2; exit 1; }
version="${archive_name#debuglet-}"; version="${version%-linux-amd64.tar.gz}"

# Accept only the two expected checksum records, then verify both bytes before
# running any installer. Neither the archive path nor manifest permits URLs.
archive_hash= installer_hash=
while read -r hash filename extra || [[ -n "${hash:-}${filename:-}${extra:-}" ]]; do
  [[ "$hash" =~ ^[0-9a-f]{64}$ && -z "$extra" ]] || { echo 'invalid candidate checksums' >&2; exit 1; }
  case "$filename" in
    "$archive_name") [[ -z "$archive_hash" ]] || exit 1; archive_hash="$hash" ;;
    install.sh) [[ -z "$installer_hash" ]] || exit 1; installer_hash="$hash" ;;
    *) echo 'unexpected candidate checksum member' >&2; exit 1 ;;
  esac
done < "$checksums"
[[ -n "$archive_hash" && -n "$installer_hash" ]] || { echo 'candidate checksums are incomplete' >&2; exit 1; }
(cd "$package_dir" && sha256sum --check --strict "$checksums")

mkdir -p .ci .cache/ci
evidence_root="$(realpath .cache/ci)/compatibility-evidence"
mkdir -m 0700 "$evidence_root"
work="$(mktemp -d "${TMPDIR:-/tmp}/debuglet-compat-install.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
sh "$package_dir/install.sh" --archive "$archive" --checksums "$checksums" \
  --version "$version" --prefix "$work/install" > .cache/ci/compatibility-install.log
"${GO:-go}" run -mod=readonly ./internal/packaging verify \
  -installed-root "$work/install/lib/debuglet/$version"
"${GO:-go}" build -mod=readonly -o .ci/local-compatibility ./internal/acceptance/canary
export DEBUGLET_CANARY_INSTALLED_ROOT="$work/install/lib/debuglet/$version"
export DEBUGLET_CANARY_EVIDENCE_DIR="$evidence_root"
export DEBUGLET_CANARY_DRIVER="$(realpath .ci/local-compatibility)"
export DEBUGLET_CANARY_ARCHIVE_SHA256="$archive_hash"
"${GO:-go}" test -mod=readonly -json -tags=canary_integration -count=1 -timeout=4m \
  ./internal/acceptance/canary -run '^TestCanaryLocal$' | tee .cache/ci/compatibility-tests.json
"${GO:-go}" run -mod=readonly ./internal/packaging check-compatibility-evidence \
  -evidence .cache/ci/compatibility-tests.json

# Guest ABI gate. The frozen guests of the published ABI must still execute on
# this candidate's host code, and the guests the candidate installs must import
# that ABI and nothing else. The installed root is the one verified above.
DEBUGLET_GUEST_ABI_INSTALLED_ROOT="$work/install/lib/debuglet/$version" \
  "${GO:-go}" test -mod=readonly -json -count=1 -timeout=8m \
  ./pkg/debuglet -run '^TestGuestABI' | tee .cache/ci/compatibility-guest-abi.json
# A selection that matched nothing, or a gate that skipped itself, also exits
# zero. Require the installed-guest check's own pass event.
"${GO:-go}" run -mod=readonly ./internal/packaging check-guest-abi-evidence \
  -evidence .cache/ci/compatibility-guest-abi.json
