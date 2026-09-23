#!/usr/bin/env bash
# Check the local TEST compose rig end to end, in isolation.
#
# This builds the rig's two images from this checkout, creates the databases
# the documented way, starts the services, waits until the dispatcher's HTTP
# API reports a ready executor, registers an account and logs in, submits one
# TEST sample and waits for it to finish, restarts both services and reads the
# same run back from the restarted dispatcher, then removes everything it
# created, volumes and images included.
#
# Usage:
#   deploy/docker/compose-smoke.sh [PROJECT]
#
# PROJECT is the compose project name (default "debuglet-compose-smoke"), so
# parallel checkouts can run this without colliding. DEBUGLET_LOCAL_HTTP
# selects the loopback address the dispatcher's API is published on (default
# 127.0.0.1:9000); use a free port when something else already listens there.
#
# Everything stays on loopback: the API is published to a loopback address
# only and the submission is made from inside the rig. A pass says that the
# rig builds, seeds, registers an executor, accepts an account the CLI
# registered, runs one TEST sample under that credential and keeps its result
# across a restart. It says nothing about remote topology, SCION operation,
# traffic policy or production readiness.

set -euo pipefail

project=${1:-debuglet-compose-smoke}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
endpoint=${DEBUGLET_LOCAL_HTTP:-127.0.0.1:9000}
ready_timeout=${DEBUGLET_SMOKE_TIMEOUT:-180}
compose=(docker compose -p "$project" -f "$root/docker-compose.yml")
logs=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-compose-smoke.XXXXXXXX")
failed=1

cleanup() {
	if [ "$failed" -ne 0 ]; then
		"${compose[@]}" logs --no-color >"$logs/services.log" 2>&1 || true
	fi
	# The account key, the recovery code and the session are written inside
	# the dispatcher container. Remove them before the container is, so an
	# interrupted run leaves no credential in one that survives.
	"${compose[@]}" exec -T dispatcher rm -f /tmp/smoke.toml /tmp/credentials.json \
		/tmp/smoke-key.txt /tmp/smoke-recovery.txt >/dev/null 2>&1 || true
	"${compose[@]}" --profile seed --profile tls-edge down -v --rmi local \
		--remove-orphans >>"$logs/down.log" 2>&1 || true
	if [ "$failed" -eq 0 ]; then
		rm -rf -- "$logs"
	else
		printf 'compose-smoke: logs retained in %s\n' "$logs" >&2
	fi
}
trap cleanup EXIT INT TERM

note() { printf '==> %s\n' "$*"; }

api() {
	curl --silent --show-error --max-time 10 "http://${endpoint}$1"
}

# Every submission route needs a credential, and this rig cannot serve the
# credential-free server.local_development profile: it leaves bind_host unset
# so the compose network reaches the listeners, which is also what lets the
# port be published, and that profile is refused unless bind_host is loopback.
# So the rig registers its own account with the installed CLI and keeps the
# session in the dispatcher container, where a restart leaves it in place.
cli() {
	"${compose[@]}" exec -T dispatcher /opt/debuglet/bin/dbl \
		--config /tmp/smoke.toml --output json "$@"
}

# await_ready polls the published API until one executor reports ready. Both
# the dispatcher's own answer and the registry it serves are observed, so this
# is the rig's actual discovery path and not a container state.
await_ready() {
	local waited=0 nodes
	while :; do
		if nodes=$(api /executors 2>/dev/null) &&
			printf '%s' "$nodes" | tr -d ' \n' | grep -q '"ready":true'; then
			printf '%s\n' "$nodes"
			return 0
		fi
		if [ "$waited" -ge "$ready_timeout" ]; then
			printf 'compose-smoke: no ready executor within %ss (last answer: %s)\n' \
				"$ready_timeout" "${nodes:-none}" >&2
			return 1
		fi
		sleep 2
		waited=$((waited + 2))
	done
}

# json_string extracts one top-level string field from a JSON object without
# assuming how the encoder indented it.
json_string() {
	local field=$1
	tr -d ' \t\n' | grep -o "\"$field\":\"[^\"]*\"" | head -1 | cut -d'"' -f4
}

# A run that did not reach its cleanup leaves the volumes, and with them the
# smoke account; the credential files the CLI writes must not exist either, and
# it refuses to overwrite them. Start from nothing.
note "removing anything an earlier run under this name left behind"
"${compose[@]}" --profile seed --profile tls-edge down -v --remove-orphans \
	>"$logs/down.log" 2>&1 || true

note "building the rig ($project)"
"${compose[@]}" build dispatcher executor >"$logs/build.log" 2>&1 ||
	{ tail -40 "$logs/build.log" >&2; exit 1; }

note "creating the databases with the packaged migrations"
"${compose[@]}" --profile seed run --rm seed

note "starting the rig"
"${compose[@]}" up -d dispatcher executor

note "waiting for the dispatcher API on http://${endpoint} to report a ready executor"
nodes=$(await_ready)
printf 'executors: %s\n' "$nodes"
version=$(api /version)
printf 'version: %s\n' "$version"

note "registering an account and logging in from inside the rig"
cli connect "http://127.0.0.1:9000" >"$logs/connect.log"
cli login --register smoke --account-key-file /tmp/smoke-key.txt \
	--recovery-file /tmp/smoke-recovery.txt >"$logs/login.log"

note "submitting one TEST sample from inside the rig"
receipt=$(cli run --sample hello --duration 10s --wait)
printf 'receipt: %s\n' "$receipt"
run_id=$(printf '%s' "$receipt" | json_string id)
state=$(printf '%s' "$receipt" | json_string state)
[ -n "$run_id" ] || { echo 'compose-smoke: the submission returned no run id' >&2; exit 1; }
printf 'run %s finished in state %s\n' "$run_id" "$state"

# The executor lives in the dispatcher's network namespace, so it has to be
# out of the way while the dispatcher is down: restarting both at once leaves
# it trying to join a namespace that no longer exists. Stopping it first and
# starting it afterwards is the supported order, and still stops and starts
# both daemons.
note "restarting both services"
"${compose[@]}" stop executor
"${compose[@]}" restart dispatcher
"${compose[@]}" start executor
await_ready >/dev/null
note "reading the same run back from the restarted dispatcher"
retained=$(cli status "$run_id")
printf 'retained: %s\n' "$retained"
retained_state=$(printf '%s' "$retained" | json_string state)
[ -n "$retained_state" ] || { echo 'compose-smoke: the run was not retained' >&2; exit 1; }
if [ "$retained_state" != "$state" ]; then
	printf 'compose-smoke: run %s was %s before the restart and %s after\n' \
		"$run_id" "$state" "$retained_state" >&2
	exit 1
fi

failed=0
note "the rig built, seeded, discovered an executor, ran $run_id and kept it across a restart"
