#!/usr/bin/env bash
# Run a deployment command in the pinned provisioner container.
#
# A deployment runs from a provisioner built only from the inputs pinned in
# deploy/provisioner.env, so that the Ansible version, the collections and
# their digests are the ones this revision of the repository describes. The
# playbooks refuse to run anywhere else: deploy/ansible/preflight.yml compares
# the running provisioner with those pins before any task reaches a host.
#
# Usage:
#   deploy/scripts/provisioner.sh ansible-playbook -i hosts.yml site.yml \
#       -e dispatcher_addr=dispatcher.example.com \
#       -e dispatcher_base_url=debuglet.example.com
#   deploy/scripts/provisioner.sh ansible-inventory -i hosts.yml --list
#   DEBUGLET_PROVISIONER_WRITE_DIR=$PWD/deploy/dist DEBUGLET_PROVISIONER_AS_CALLER=1 \
#       deploy/scripts/provisioner.sh goose -dir /repository/... sqlite3 /output/x.db up
#
# The command runs with the repository mounted read-only at /repository and the
# working directory set to deploy/ansible, so inventory and playbook paths are the
# ones the deployment documentation uses. The image is built if it is absent;
# deploy/test/provisioner-check.sh builds and checks it.
#
# SSH material is passed through read-only when it exists: the agent socket in
# SSH_AUTH_SOCK, and ~/.ssh for a key or a client configuration. Nothing else
# from this machine is visible to the container, and nothing is installed on
# this machine.

set -euo pipefail

[ "$#" -gt 0 ] || { echo 'usage: deploy/scripts/provisioner.sh COMMAND [ARGS...]' >&2; exit 2; }

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
pins=$root/deploy/provisioner.env
[ -f "$pins" ] || { echo "missing $pins" >&2; exit 2; }

set -a
# shellcheck disable=SC1090
. "$pins"
set +a

if ! docker image inspect "$DEBUGLET_PROVISIONER_IMAGE" >/dev/null 2>&1; then
	printf 'provisioner: building %s from the pinned inputs\n' "$DEBUGLET_PROVISIONER_IMAGE" >&2
	docker build --platform linux/amd64 \
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
		-t "$DEBUGLET_PROVISIONER_IMAGE" "$root" >&2
fi

# The playbooks only read the repository: inventories, host keys, the release
# package and the templates. Nothing a deployment writes belongs here.
mounts=(--volume "$root:/repository:ro")
# `make deploy-seed-db` is the one command here that produces a file instead of
# changing a host. It names the directory that receives it, which becomes the
# only writable path in the container.
if [ -n "${DEBUGLET_PROVISIONER_WRITE_DIR:-}" ]; then
	case $DEBUGLET_PROVISIONER_WRITE_DIR in
		/*) ;;
		*) echo "DEBUGLET_PROVISIONER_WRITE_DIR must be an absolute path, got $DEBUGLET_PROVISIONER_WRITE_DIR" >&2; exit 2 ;;
	esac
	[ -d "$DEBUGLET_PROVISIONER_WRITE_DIR" ] ||
		{ echo "DEBUGLET_PROVISIONER_WRITE_DIR is not a directory: $DEBUGLET_PROVISIONER_WRITE_DIR" >&2; exit 2; }
	mounts+=(--volume "$DEBUGLET_PROVISIONER_WRITE_DIR:/output")
fi
# Separate from the mount: only a command that writes a file wants the
# caller's identity. Ansible runs as root, which is what reads the ~/.ssh
# below and what the container's own home is.
if [ -n "${DEBUGLET_PROVISIONER_AS_CALLER:-}" ]; then
	mounts+=(--user "$(id -u):$(id -g)")
fi
if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "${SSH_AUTH_SOCK}" ]; then
	mounts+=(--volume "$SSH_AUTH_SOCK:/ssh-agent" --env SSH_AUTH_SOCK=/ssh-agent)
fi
if [ -d "${HOME:-}/.ssh" ]; then
	mounts+=(--volume "$HOME/.ssh:/root/.ssh:ro")
fi

exec docker run --rm --platform linux/amd64 --interactive --tty="$([ -t 0 ] && echo true || echo false)" \
	"${mounts[@]}" --workdir /repository/deploy/ansible \
	"$DEBUGLET_PROVISIONER_IMAGE" "$@"
