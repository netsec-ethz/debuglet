#!/bin/sh
# Create the two daemon databases the local TEST compose rig reads.
#
# A daemon opens the database its configuration names and never creates the
# schema, so the rig's volumes have to hold one before the first start. This
# runs inside the rig's own image and uses the packaged CLI to do it: the
# local services apply the packaged migrations to a fresh private state
# directory, and the resulting schema is copied into the volumes. No migration
# tool, no Go toolchain and no network are involved.
#
# docker-compose.yml runs this as the "seed" service:
#
#   docker compose --profile seed run --rm seed
#
# Each database holds the packaged schema and its migration record, and
# nothing a running service wrote: the services that create them are stopped
# before anything is recorded in them, and the dispatcher's is taken from a
# dispatcher no executor ever registered with.
#
# Repeating it is safe: a database that already exists is kept, so rerunning
# after a restart or a rebuild never discards recorded runs. Remove the
# volumes (`docker compose down -v`) to start from an empty rig.
#
# The volumes are mounted at /seed/dispatcher and /seed/executor, each the
# directory the matching service sees as /var/lib/debuglet.

set -eu

timeout=${DEBUGLET_SEED_TIMEOUT:-60}
missing=

for role in dispatcher executor; do
	target=/seed/$role/$role.db
	[ -d "/seed/$role" ] || { echo "seed: /seed/$role is not mounted" >&2; exit 1; }
	if [ -e "$target" ]; then
		printf 'seed: %s already exists; keeping it\n' "$target"
	else
		missing="$missing $role"
	fi
done
if [ -z "$missing" ]; then
	echo 'seed: both databases are present'
	exit 0
fi

work=$(mktemp -d /tmp/debuglet-seed.XXXXXXXX)
state=$work/state
mkdir -p "$state"
up_pid=
cleanup() {
	status=$?
	if [ -n "$up_pid" ]; then
		kill -TERM "$up_pid" 2>/dev/null || true
		wait "$up_pid" 2>/dev/null || true
	fi
	rm -rf -- "$work"
	exit "$status"
}
trap cleanup EXIT INT TERM

# Wait for a local service to publish the record that says its database is
# migrated and open, then stop it so the file is closed and carries no
# journal.
run_until() {
	ready=$1
	shift
	dbl --config "$work/dbl.toml" --output json "$@" >"$work/up.json" 2>"$work/up.log" &
	up_pid=$!
	waited=0
	while [ ! -e "$ready" ]; do
		if ! kill -0 "$up_pid" 2>/dev/null; then
			echo 'seed: the local service exited before it was ready' >&2
			cat "$work/up.log" "$work/up.json" >&2 || true
			exit 1
		fi
		if [ "$waited" -ge "$timeout" ]; then
			echo "seed: the local service was not ready within ${timeout}s" >&2
			cat "$work/up.log" >&2 || true
			exit 1
		fi
		sleep 1
		waited=$((waited + 1))
	done
	kill -TERM "$up_pid"
	wait "$up_pid" 2>/dev/null || true
	up_pid=
}

publish() {
	role=$1 source=$2
	[ -f "$source" ] || { echo "seed: the local service left no $role database" >&2; exit 1; }
	for sidecar in "$source-wal" "$source-shm" "$source-journal"; do
		[ ! -e "$sidecar" ] || { echo "seed: $role database was not closed cleanly" >&2; exit 1; }
	done
	target=/seed/$role/$role.db
	cp -- "$source" "$target.partial"
	chmod 600 "$target.partial"
	mv -- "$target.partial" "$target"
	printf 'seed: wrote %s\n' "$target"
}

# Each database is taken from a service that never recorded anything in it.
# The dispatcher runs on its own, so no executor registers with it and its
# tables stay empty; the executor's database comes from a combined
# environment, whose dispatcher database is discarded with the run.
for role in $missing; do
	case $role in
		dispatcher)
			printf 'seed: creating the packaged dispatcher schema\n'
			run_until "$state/dispatcher/ready.json" dispatcher up \
				--name seed --state-dir "$state/dispatcher" --port 0 --grpc-port 0
			publish dispatcher "$state/dispatcher/dispatcher.sqlite"
			;;
		executor)
			printf 'seed: creating the packaged executor schema\n'
			run_until "$state/local/environment.json" up --state-dir "$state/local" --port 0
			publish executor "$state/local/executor.sqlite"
			;;
	esac
done

echo 'seed: the rig can be started now'
