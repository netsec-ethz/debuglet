# Managed role services

`dbl service install` writes a unit like the two in this directory, one per
installed role instance, and then owns exactly that unit. The files here are
reference copies for a version `0.0.0-reference` package installed under
`/usr/local`: the renderer in `internal/demo/service` produces them byte for
byte, and a test in that package compares its output against these files, so a
change to the generated unit cannot land without updating this reference.

They are not deployed by anything. The profile, the paths, what the unit states
and why, and the drain semantics are described in
[Managed services](../../docs/operations/services.md).

## Repeat the installed-profile check

`smoke-test.py` exercises a full installed package in a new, disposable
Docker container with systemd as PID 1. It installs and removes managed roles,
checks readiness, runs TEST work, restarts and drains an executor, and checks
retained state and doctor/startup agreement. Never run it against a host or a
container that already has managed roles.

Use Linux amd64, Docker Engine with cgroup v2 and permission to create the
container below, Bash, `sha256sum`, and `mktemp`. Run from the source checkout
containing this fixture. Set `DEBUGLET_FIXTURE_PACKAGES` to an absolute directory
containing exactly one full package's archive, `install.sh` and `SHA256SUMS`,
and set `DEBUGLET_FIXTURE_VERSION` to that archive's version. Obtain all three
from the same trusted build or release. The container needs systemd, Python 3,
util-linux and an unprivileged `debuglet` account; the commands create these.

The hosting container needs `CAP_SYS_ADMIN`, unconfined seccomp/AppArmor and a
writable **private** cgroup namespace for systemd. These are fixture-hosting
permissions, not capabilities given to Debuglet daemons. Do not substitute
host networking, host cgroups or `--privileged`. Package/fixture mounts are
read-only; the fixture itself has no external network.

```bash
(
  set -euo pipefail
  version=${DEBUGLET_FIXTURE_VERSION:?set the full package version}
  packages=$(cd "${DEBUGLET_FIXTURE_PACKAGES:?set the package directory}" && pwd)
  fixture="$PWD/deploy/systemd/smoke-test.py"
  test -f "$fixture"
  (cd "$packages" && sha256sum --check --strict SHA256SUMS)
  context=$(mktemp -d)
  name="debuglet-systemd-check-$$"
  image="debuglet-systemd-check:$$"
  container_id=
  if docker container inspect "$name" >/dev/null 2>&1 || docker image inspect "$image" >/dev/null 2>&1; then
    rm -rf -- "$context"
    printf 'Fixture name already exists; choose a fresh shell.\n' >&2
    exit 1
  fi
  cleanup() {
    result=$?
    trap - EXIT
    if [ -n "$container_id" ]; then
      docker logs "$container_id" || true
      docker stop --time 20 "$container_id" >/dev/null || true
      docker rm -f "$container_id" >/dev/null || result=1
    fi
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf -- "$context"
    exit "$result"
  }
  trap cleanup EXIT
  cat > "$context/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates curl python3 util-linux && apt-get clean
ENV container=docker
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
DOCKER
  docker build -t "$image" "$context"
  container_id=$(docker create -t --name "$name" --network none --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp --cap-add SYS_ADMIN \
    --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
    --mount "type=bind,src=$packages,dst=/packages,readonly" \
    --mount "type=bind,src=$fixture,dst=/fixture.py,readonly" \
    --entrypoint /bin/sh "$image" \
    -c 'mount -o remount,rw /sys/fs/cgroup && exec /lib/systemd/systemd')
  docker start "$container_id" >/dev/null
  for attempt in {1..60}; do
    if docker exec "$container_id" systemctl is-system-running --quiet; then break; fi
    sleep 1
  done
  docker exec "$container_id" systemctl is-system-running --quiet
  docker exec "$container_id" useradd --system --user-group \
    --home-dir /var/lib/debuglet --shell /usr/sbin/nologin debuglet
  docker exec "$container_id" sh /packages/install.sh \
    --archive "/packages/debuglet-$version-linux-amd64.tar.gz" \
    --checksums /packages/SHA256SUMS --version "$version" --prefix /usr/local
  docker exec -e DEBUGLET_SERVICE_FIXTURE=1 "$container_id" python3 /fixture.py
)
```

The script prints JSON observations and exits zero when its assertions pass;
a failed assertion returns nonzero. The outer shell removes only its owned
container, image and temporary build directory, including on failure. It does
not remove the supplied package. The [tested profile](../../docs/operations/services.md#tested-managed-profile)
records the exact observed environment; apt packages in a later image build
may differ, so retain the fixture's environment output when repeating it.
