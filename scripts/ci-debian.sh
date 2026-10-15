#!/usr/bin/env bash
# Run real apt authentication and package installation in a fresh Ubuntu image.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux ]] || { echo 'Debian checks require a Linux Docker host.' >&2; exit 1; }
packages=$(realpath -e "${CI_DEBIAN_PACKAGE_DIR:-${CI_PACKAGE_DIR:-.cache/ci/packages}/debian}")
[[ -f "$packages/deb-packages.json" ]] || { echo 'Build the Debian packages first.' >&2; exit 1; }
mkdir -p .cache/ci
work=$(mktemp -d "$PWD/.cache/ci/debian-fixture.XXXXXXXX")
image=${DEBUGLET_DEBIAN_TEST_IMAGE:-debuglet-debian-test:ubuntu24.04}
name="debuglet-debian-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
cleanup() {
    local status=$?
    docker rm -f "$name-prepare" "$name-check" >/dev/null 2>&1 || true
    rm -rf -- "$work"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ -z ${DEBUGLET_DEBIAN_TEST_IMAGE:-} ]]; then
    docker build -t "$image" -f deploy/ci/debian-fixture.Dockerfile deploy/ci
fi
docker image inspect --format '{{.Id}}' "$image" > .cache/ci/debian-image.txt
docker run --rm --name "$name-prepare" --network none --cpus=2 --memory=1g --pids-limit=128 \
    --user "$(id -u):$(id -g)" --cap-drop=ALL --security-opt=no-new-privileges \
    --mount "type=bind,src=$PWD,dst=/source,readonly" \
    --mount "type=bind,src=$packages,dst=/packages,readonly" \
    --mount "type=bind,src=$work,dst=/work" \
    --entrypoint sh "$image" -ec '
      command -v apt-ftparchive dpkg-deb gpg gpgv >/dev/null
      python3 -m unittest discover -s /source/deploy/debian -p test_package.py -v >&2
      python3 -m unittest discover -s /source/tools -p test_apt_repository.py -v >&2
      exec python3 /source/deploy/ci/debian-prepare.py
    ' \
    > .cache/ci/debian-prepare.jsonl
docker run --rm --name "$name-check" --network none --cpus=2 --memory=1g --pids-limit=128 \
    --cap-add=SYS_PTRACE --security-opt=no-new-privileges --env DEBUGLET_DEBIAN_FIXTURE=1 \
    --mount "type=bind,src=$PWD,dst=/source,readonly" \
    --mount "type=bind,src=$packages,dst=/packages,readonly" \
    --mount "type=bind,src=$work,dst=/fixture,readonly" \
    --entrypoint python3 "$image" /source/deploy/ci/debian-check.py \
    --repository /fixture/repository --key /fixture/key.asc --wrong-key /fixture/wrong-key.asc \
    --inventory /packages/deb-packages.json | tee .cache/ci/debian-check.jsonl
