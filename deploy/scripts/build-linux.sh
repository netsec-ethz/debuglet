#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich

# Extract the verified release package the deployment installs.
#
# Nothing is compiled here. The package comes from the payload stage of
# deploy/docker/debuglet.Dockerfile: the packaging tool compiles the binaries
# with the pinned Go 1.25.11 toolchain from a clean committed checkout, the
# candidate is verified against its own SHA256SUMS, and the package's own
# installer installs it. This script copies that package out, so a managed
# host receives the same bytes, verified the same way, as an installed package
# and as the deployment images.
#
# Outputs to deploy/dist/:
#   debuglet-VERSION-linux-amd64.tar.gz   the release archive
#   SHA256SUMS                            digests of the archive and installer
#   install.sh                            the candidate's own installer
#   manifest.json                         the payload manifest
#   release.json                          the application half of the
#                                         deployment record: version, source
#                                         revision, toolchain and digests
#
# The Ansible payload role copies these to a managed host, checks the archive
# against the digest recorded here, and runs the installer. No Go toolchain,
# no package manager and no bootstrap helper is installed on a managed host.
#
# The checkout must be clean and committed; the packaging tool refuses to
# stamp a version onto a modified source tree.
#
# Usage:  ./deploy/scripts/build-linux.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/../dist"
PAYLOAD_IMAGE="${DEBUGLET_PAYLOAD_IMAGE:-debuglet-payload:local}"
PACKAGE_DIR=/usr/src/debuglet/.cache/ci/packages

mkdir -p "${DIST_DIR}"

echo "==> Building the release payload (linux/amd64)..."
docker build \
	--platform linux/amd64 \
	-f "${ROOT_DIR}/deploy/docker/debuglet.Dockerfile" \
	--target payload \
	-t "${PAYLOAD_IMAGE}" \
	"${ROOT_DIR}"

container="$(docker create "${PAYLOAD_IMAGE}")"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true' EXIT

echo "==> Extracting the verified package..."
archive_name="$(docker run --rm --network none --entrypoint /bin/sh "${PAYLOAD_IMAGE}" \
	-c "cd ${PACKAGE_DIR} && ls debuglet-v*-linux-amd64.tar.gz")"
for file in "${archive_name}" SHA256SUMS install.sh; do
	docker cp -L "${container}:${PACKAGE_DIR}/${file}" "${DIST_DIR}/${file}"
	echo "    -> ${DIST_DIR}/${file}"
done

docker run --rm --network none --entrypoint /bin/sh "${PAYLOAD_IMAGE}" \
	-c 'cat /opt/debuglet/lib/debuglet/*/share/debuglet/manifest.json' \
	>"${DIST_DIR}/manifest.json"
echo "    -> ${DIST_DIR}/manifest.json"

# The package is verified here, before anything is recorded or deployed: the
# digests in SHA256SUMS are the ones the installer checks on the managed host,
# and release.json repeats the archive digest so the role can refuse an
# archive that changed on the way there.
echo "==> Verifying the extracted package..."
(cd "${DIST_DIR}" && sha256sum --check SHA256SUMS)

version="${archive_name##debuglet-}"
version="${version%-linux-amd64.tar.gz}"
archive_sha256="$(cd "${DIST_DIR}" && sha256sum "${archive_name}" | cut -d' ' -f1)"
installer_sha256="$(cd "${DIST_DIR}" && sha256sum install.sh | cut -d' ' -f1)"
source_sha="$(sed -n 's/.*"source_sha"[[:space:]]*:[[:space:]]*"\([0-9a-f]*\)".*/\1/p' \
	"${DIST_DIR}/manifest.json" | head -1)"
go_version="$(sed -n 's/.*"go_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
	"${DIST_DIR}/manifest.json" | head -1)"
[ -n "${source_sha}" ] && [ -n "${go_version}" ] ||
	{ echo 'the payload manifest names no source revision or toolchain' >&2; exit 1; }

cat >"${DIST_DIR}/release.json" <<JSON
{
  "schema_version": 1,
  "version": "${version}",
  "source_sha": "${source_sha}",
  "go_version": "${go_version}",
  "archive": "${archive_name}",
  "archive_sha256": "${archive_sha256}",
  "installer_sha256": "${installer_sha256}"
}
JSON
echo "    -> ${DIST_DIR}/release.json"

echo ""
echo "Release ${version} from ${source_sha}, built with ${go_version}:"
ls -lh "${DIST_DIR}/"
