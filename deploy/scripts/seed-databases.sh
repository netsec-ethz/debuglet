#!/bin/bash
# Create deployment seeds with the daemons in the verified release payload.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
dist=$root/deploy/dist
image=${DEBUGLET_PAYLOAD_IMAGE:-debuglet-payload:local}
[ -f "$dist/manifest.json" ] || { echo 'run make deploy-build first' >&2; exit 1; }
version=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$dist/manifest.json" | head -1)
[ -n "$version" ] || { echo 'release manifest has no version' >&2; exit 1; }
work=$(mktemp -d "$dist/.seed.XXXXXXXX")
container=
cleanup() {
 status=$?
 trap - EXIT
 if [ -n "$container" ]; then docker rm -f "$container" >/dev/null 2>&1 || status=1; fi
 rm -rf -- "$work"
 exit "$status"
}
trap cleanup EXIT
container=$(docker create --network none --entrypoint /bin/sh "$image" -ec '
 umask 077
 mkdir /seed
 for role in dispatcher executor; do
  /opt/debuglet/bin/debuglet-$role -init-database /seed/$role-seed.db
 done
')
docker cp "$container:/opt/debuglet/lib/debuglet/$version/share/debuglet/manifest.json" "$work/manifest.json"
cmp -- "$dist/manifest.json" "$work/manifest.json" || {
 echo 'payload image differs from the built release; run make deploy-build first' >&2
 exit 1
}
docker start --attach "$container"
[ "$(docker inspect --format '{{.State.ExitCode}}' "$container")" = 0 ]
for role in dispatcher executor; do
 docker cp "$container:/seed/$role-seed.db" "$work/$role-seed.db"
 chmod 600 "$work/$role-seed.db"
 mv -f -- "$work/$role-seed.db" "$dist/$role-seed.db"
done
