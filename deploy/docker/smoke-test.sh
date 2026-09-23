#!/usr/bin/env bash
# Build the Debuglet deployment images and check them in isolation.
#
# For each of the two role images this:
#   1. builds it from this checkout,
#   2. reads the packaged version and source revision out of the image and
#      compares them with the checkout the build came from,
#   3. starts the image on a loopback-only network with an explicit temporary
#      configuration and waits for the daemon's readiness record,
#   4. removes every container and temporary file it created.
#
# Nothing is published to a host interface and nothing is deployed. The
# executor is checked against the dispatcher image started by the same run, so
# both role images are exercised against each other over loopback only.
#
# Usage:
#   deploy/docker/smoke-test.sh [TAG]
#
# TAG names the images that are built (default "smoke"), so parallel checkouts
# can run this without colliding. Build and container logs are removed after a
# successful run and retained, with their path printed, after a failure.
#
# A run removes every container and temporary file it made, but leaves the two
# tagged role images behind, along with the intermediate stages the classic
# builder keeps as its cache. Remove them yourself when they are no longer
# wanted.

set -euo pipefail

tag=${1:-smoke}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dockerfile=deploy/docker/debuglet.Dockerfile

dispatcher_image="debuglet-dispatcher:${tag}"
executor_image="debuglet-executor:${tag}"
dispatcher_role="debuglet-smoke-dispatcher-role-${tag}"
dispatcher_daemon="debuglet-smoke-dispatcher-${tag}"
executor_role="debuglet-smoke-executor-role-${tag}"
executor_daemon="debuglet-smoke-executor-${tag}"
containers=(
	"$dispatcher_role" "$dispatcher_daemon" "$executor_role" "$executor_daemon"
)

logs=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-smoke-logs.XXXXXXXX")
work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-smoke.XXXXXXXX")
chmod 700 "$work"
mkdir -m 700 "$work/dispatcher" "$work/executor"
ready_timeout=${DEBUGLET_SMOKE_TIMEOUT:-120}
runtime_user="$(id -u):$(id -g)"
failed=1

cleanup() {
	for container in "${containers[@]}"; do
		if [ "$failed" -ne 0 ] && docker container inspect "$container" >/dev/null 2>&1; then
			docker logs "$container" >"$logs/$container.log" 2>&1 || true
		fi
		docker rm -f "$container" >/dev/null 2>&1 || true
	done
	rm -rf -- "$work"
	if [ "$failed" -eq 0 ]; then
		rm -rf -- "$logs"
	else
		printf 'smoke: build and container logs retained in %s\n' "$logs" >&2
	fi
}
trap cleanup EXIT INT TERM

note() { printf '==> %s\n' "$*"; }

build() {
	local target=$1 image=$2 log="$logs/build-$1.log"
	note "building $image ($target)"
	if ! docker build --platform linux/amd64 --pull=false -f "$dockerfile" \
		--target "$target" -t "$image" "$root" >"$log" 2>&1; then
		printf 'smoke: docker build --target %s failed; see %s\n' "$target" "$log" >&2
		tail -40 "$log" >&2
		return 1
	fi
}

# json_string extracts one top-level string field from a JSON object without
# assuming how the encoder indented it.
json_string() {
	local field=$1
	tr -d ' \t\n' | grep -o "\"$field\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}

check_identity() {
	local image=$1 revision expected version manifest
	expected=$(git -C "$root" rev-parse HEAD)
	local reported
	reported=$(docker run --rm --network none --entrypoint /opt/debuglet/bin/dbl \
		"$image" --output json version)
	revision=$(printf '%s' "$reported" | json_string revision)
	version=$(printf '%s' "$reported" | json_string version)
	if [ "$revision" != "$expected" ]; then
		printf 'smoke: %s reports revision %s, expected %s\n' "$image" "$revision" "$expected" >&2
		return 1
	fi
	manifest=$(docker run --rm --network none --entrypoint /bin/cat \
		"$image" "/opt/debuglet/lib/debuglet/$version/share/debuglet/manifest.json")
	local toolchain
	toolchain=$(printf '%s' "$manifest" | json_string go_version)
	if [ "$toolchain" != "go1.25.11" ]; then
		printf 'smoke: %s was built with %s, expected go1.25.11\n' "$image" "$toolchain" >&2
		return 1
	fi
	note "$image is $version from $revision, built with $toolchain"
}

await() {
	local path=$1 container=$2 waited=0
	while [ ! -e "$path" ]; do
		if ! docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
			printf 'smoke: %s exited before publishing %s\n' "$container" "$(basename "$path")" >&2
			return 1
		fi
		if [ "$waited" -ge "$ready_timeout" ]; then
			printf 'smoke: %s did not publish %s within %ss\n' "$container" "$(basename "$path")" "$ready_timeout" >&2
			return 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
}

build dispatcher "$dispatcher_image"
build executor "$executor_image"

check_identity "$dispatcher_image"
check_identity "$executor_image"

# The role commands manage a private state directory: they bootstrap a fresh
# database and write the daemon configuration the product itself generates.
# Running them first gives the daemon checks below a real temporary
# configuration without a second, hand-maintained copy of the config schema.
note "starting the dispatcher image's local role on loopback"
docker run --detach --name "$dispatcher_role" --network none --user "$runtime_user" \
	--volume "$work/dispatcher:/state" --entrypoint /opt/debuglet/bin/dbl \
	"$dispatcher_image" --config /state/dbl.toml --output json \
	dispatcher up --name smoke --state-dir /state/role --port 9000 --grpc-port 9001 >/dev/null
await "$work/dispatcher/role/ready.json" "$dispatcher_role"
docker stop --time 30 "$dispatcher_role" >/dev/null
docker rm -f "$dispatcher_role" >/dev/null

note "starting the dispatcher image with an explicit temporary configuration"
docker run --detach --name "$dispatcher_daemon" --network none --user "$runtime_user" \
	--volume "$work/dispatcher:/state" "$dispatcher_image" \
	--config /state/role/service.toml --ready-file /state/dispatcher-ready.json >/dev/null
await "$work/dispatcher/dispatcher-ready.json" "$dispatcher_daemon"

# The executor containers join the dispatcher container's network namespace, so
# the whole check stays on a loopback interface no other process can reach.
note "registering the executor image with the dispatcher image over loopback"
docker run --detach --name "$executor_role" --network "container:$dispatcher_daemon" \
	--user "$runtime_user" --volume "$work/executor:/state" \
	--entrypoint /opt/debuglet/bin/dbl "$executor_image" \
	--config /state/dbl.toml --output json \
	executor up --name smoke --state-dir /state/role --dispatcher http://127.0.0.1:9000 >/dev/null
await "$work/executor/role/ready.json" "$executor_role"
docker stop --time 30 "$executor_role" >/dev/null
docker rm -f "$executor_role" >/dev/null

note "starting the executor image with an explicit temporary configuration"
docker run --detach --name "$executor_daemon" --network "container:$dispatcher_daemon" \
	--user "$runtime_user" --volume "$work/executor:/state" "$executor_image" \
	--config /state/role/service.toml --ready-file /state/executor-ready.json >/dev/null
await "$work/executor/executor-ready.json" "$executor_daemon"

failed=0
note "both images built, identified and reached readiness"
printf 'images: %s %s\n' "$dispatcher_image" "$executor_image"
