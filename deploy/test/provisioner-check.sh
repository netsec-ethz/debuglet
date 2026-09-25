#!/usr/bin/env bash
# Build the pinned provisioner and check the deployment playbooks inside it.
#
# The provisioner is the machine that runs a deployment. This builds it from
# the inputs pinned in deploy/provisioner.env — a base image pinned by digest,
# Python dependencies installed by digest, collections verified against their
# recorded digests — and then runs the playbooks inside that container against
# a temporary directory tree. Nothing is installed on this machine, no
# inventory is read and no managed host is contacted.
#
# Checked:
#   1. the provisioner image builds from the pinned inputs alone,
#   2. it carries the pinned Ansible and the pinned collections, and its
#      recorded identity matches deploy/provisioner.env,
#   3. the deployment preflight accepts it,
#   4. a changed dependency digest stops a deployment in the preflight,
#   5. a provisioner without a record stops a deployment in the preflight,
#   6. deploy/test/ansible-render.sh passes inside it, which renders and
#      applies the roles and checks that a repeat run changes nothing.
#
# It needs a built release package in deploy/dist:
#
#   ./deploy/scripts/build-linux.sh
#   deploy/test/provisioner-check.sh
#
# The provisioner image is left behind: it is the thing a deployment runs in.
# Remove it with `docker rmi` when it is no longer wanted.

set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
pins=$root/deploy/provisioner.env
failures=0

command -v docker >/dev/null || { echo 'missing docker' >&2; exit 2; }
[ -f "$pins" ] || { echo "missing $pins" >&2; exit 2; }
[ -f "$root/deploy/dist/release.json" ] || {
	echo 'missing deploy/dist/release.json; build the release package with ./deploy/scripts/build-linux.sh' >&2
	exit 2
}

set -a
# shellcheck disable=SC1090
. "$pins"
set +a

work=$(mktemp -d "${TMPDIR:-/tmp}/debuglet-provisioner-check.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM

check() {
	local name=$1 outcome=$2
	if [ "$outcome" = pass ]; then
		printf 'ok   %s\n' "$name"
	else
		printf 'FAIL %s\n' "$name" >&2
		failures=$((failures + 1))
	fi
}

note() { printf '==> %s\n' "$*"; }

note "building $DEBUGLET_PROVISIONER_IMAGE from the pinned inputs"
if docker build --platform linux/amd64 \
	-f "$root/deploy/docker/provisioner.Dockerfile" \
	--build-arg BASE_IMAGE="$DEBUGLET_PROVISIONER_BASE_IMAGE" \
	--build-arg BASE_DIGEST="$DEBUGLET_PROVISIONER_BASE_DIGEST" \
	--build-arg DEBIAN_SNAPSHOT="$DEBUGLET_PROVISIONER_DEBIAN_SNAPSHOT" \
	--build-arg OPENSSH_CLIENT_VERSION="$DEBUGLET_PROVISIONER_OPENSSH_CLIENT_VERSION" \
	--build-arg ANSIBLE_CORE_VERSION="$DEBUGLET_ANSIBLE_CORE_VERSION" \
	--build-arg COLLECTION_COMMUNITY_GENERAL_VERSION="$DEBUGLET_COLLECTION_COMMUNITY_GENERAL_VERSION" \
	--build-arg COLLECTION_COMMUNITY_GENERAL_SHA256="$DEBUGLET_COLLECTION_COMMUNITY_GENERAL_SHA256" \
	--build-arg COLLECTION_LIBRARY_INVENTORY_FILTERING_VERSION="$DEBUGLET_COLLECTION_LIBRARY_INVENTORY_FILTERING_VERSION" \
	--build-arg COLLECTION_LIBRARY_INVENTORY_FILTERING_SHA256="$DEBUGLET_COLLECTION_LIBRARY_INVENTORY_FILTERING_SHA256" \
	--build-arg REQUIREMENTS_SHA256="$DEBUGLET_PROVISIONER_REQUIREMENTS_SHA256" \
	--build-arg COLLECTIONS_SHA256="$DEBUGLET_PROVISIONER_COLLECTIONS_SHA256" \
	--build-arg GOOSE_VERSION="$DEBUGLET_GOOSE_VERSION" \
	--build-arg GOOSE_SHA256="$DEBUGLET_GOOSE_SHA256" \
	-t "$DEBUGLET_PROVISIONER_IMAGE" "$root" >"$work/build.log" 2>&1; then
	check 'the provisioner image builds from the pinned inputs' pass
else
	check 'the provisioner image builds from the pinned inputs' fail
	tail -30 "$work/build.log" >&2
	printf '%s check(s) failed\n' "$failures" >&2
	exit 1
fi

# Every command below runs in a throwaway container with the repository
# mounted read-only and no network.
provision() {
	docker run --rm --platform linux/amd64 --network none \
		--volume "$root:/repository:ro" --workdir /repository \
		"$@"
}

note "checking the provisioner's own identity"
version=$(provision "$DEBUGLET_PROVISIONER_IMAGE" ansible --version | head -1)
case $version in
	*"core $DEBUGLET_ANSIBLE_CORE_VERSION"*) check 'it carries the pinned ansible-core' pass ;;
	*) check 'it carries the pinned ansible-core' fail; printf '     %s\n' "$version" >&2 ;;
esac

if provision "$DEBUGLET_PROVISIONER_IMAGE" ssh -V >"$work/ssh-version.log" 2>&1; then
	check 'it carries the OpenSSH client Ansible uses' pass
else
	check 'it carries the OpenSSH client Ansible uses' fail
	cat "$work/ssh-version.log" >&2
fi

collections=$(provision "$DEBUGLET_PROVISIONER_IMAGE" ansible-galaxy collection list 2>/dev/null)
for pinned in \
	"community.general $DEBUGLET_COLLECTION_COMMUNITY_GENERAL_VERSION" \
	"community.library_inventory_filtering_v1 $DEBUGLET_COLLECTION_LIBRARY_INVENTORY_FILTERING_VERSION"; do
	name=${pinned% *} want=${pinned#* }
	got=$(printf '%s\n' "$collections" | awk -v n="$name" '$1 == n { print $2; exit }')
	if [ "$got" = "$want" ]; then
		check "it carries $name $want" pass
	else
		check "it carries $name $want" fail
		printf '     installed: %s\n' "${got:-none}" >&2
	fi
done

record=$(provision "$DEBUGLET_PROVISIONER_IMAGE" cat /etc/debuglet/provisioner.json)
for pinned in "$DEBUGLET_PROVISIONER_BASE_DIGEST" "$DEBUGLET_PROVISIONER_DEBIAN_SNAPSHOT" \
	"$DEBUGLET_PROVISIONER_OPENSSH_CLIENT_VERSION" "$DEBUGLET_ANSIBLE_CORE_VERSION" \
	"$DEBUGLET_PROVISIONER_REQUIREMENTS_SHA256" "$DEBUGLET_PROVISIONER_COLLECTIONS_SHA256" \
	"$DEBUGLET_GOOSE_VERSION" "$DEBUGLET_GOOSE_SHA256"; do
	case $record in
		*"$pinned"*) check "its record names $pinned" pass ;;
		*) check "its record names $pinned" fail ;;
	esac
done

# A fixture inventory for the preflight alone. It names no real host and is
# never connected to.
cat >"$work/inventory.yml" <<'EOF'
all:
  children:
    dispatcher:
      hosts:
        dispatcher.fixture.invalid: {}
    executors:
      hosts:
        executor.fixture.invalid:
          executor_id: 5fe02882-0410-416c-9935-235090bcba0d
EOF
printf 'fixture.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIXTURE\n' >"$work/known_hosts"

preflight() {
	provision --volume "$work:/fixture" --workdir /repository/deploy/ansible \
		"$DEBUGLET_PROVISIONER_IMAGE" \
		ansible-playbook -i /fixture/inventory.yml -c local \
		-e ansible_connection=local -e known_hosts_file=/fixture/known_hosts \
		preflight-provisioner.yml "$@"
}

note "checking the deployment preflight against the provisioner"
if preflight >"$work/preflight.log" 2>&1; then
	check 'the preflight accepts the pinned provisioner' pass
else
	check 'the preflight accepts the pinned provisioner' fail
	tail -20 "$work/preflight.log" >&2
fi

# A changed dependency digest must stop a deployment before it reaches a host.
sed 's/^DEBUGLET_PROVISIONER_REQUIREMENTS_SHA256=.*/DEBUGLET_PROVISIONER_REQUIREMENTS_SHA256=0000000000000000000000000000000000000000000000000000000000000000/' \
	"$pins" >"$work/tampered.env"
if preflight -e provisioner_pins_file=/fixture/tampered.env >"$work/tampered.log" 2>&1; then
	check 'a changed dependency digest stops the deployment' fail
	tail -20 "$work/tampered.log" >&2
elif grep -q 'does not match the digest pinned' "$work/tampered.log"; then
	check 'a changed dependency digest stops the deployment' pass
else
	check 'a changed dependency digest stops the deployment' fail
	tail -20 "$work/tampered.log" >&2
fi

if preflight -e provisioner_record_file=/fixture/absent.json >"$work/norecord.log" 2>&1; then
	check 'an unidentified provisioner stops the deployment' fail
	tail -20 "$work/norecord.log" >&2
elif grep -q 'No provisioner record' "$work/norecord.log"; then
	check 'an unidentified provisioner stops the deployment' pass
else
	check 'an unidentified provisioner stops the deployment' fail
	tail -20 "$work/norecord.log" >&2
fi

note "rendering and applying the roles inside the provisioner"
if provision "$DEBUGLET_PROVISIONER_IMAGE" bash deploy/test/ansible-render.sh; then
	check 'the deployment render checks pass in the provisioner' pass
else
	check 'the deployment render checks pass in the provisioner' fail
fi

if [ "$failures" -ne 0 ]; then
	printf '%s check(s) failed\n' "$failures" >&2
	exit 1
fi
printf 'the pinned provisioner builds, identifies itself and renders the playbooks\n'
printf 'provisioner image: %s\n' "$DEBUGLET_PROVISIONER_IMAGE"
