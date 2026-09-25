# The Debuglet deployment provisioner.
#
# The provisioner is the machine that runs the Ansible playbooks. It is built
# here so that it is reproducible and identified: the base image is pinned by
# digest, every Python dependency is installed by digest from
# deploy/ansible/requirements.txt, and every collection is verified against
# the digest recorded in deploy/provisioner.env before it is installed.
# Nothing is resolved at run time, and nothing is installed on a managed host.
#
# Build it from the repository root, with the values from
# deploy/provisioner.env:
#
#   set -a && . deploy/provisioner.env && set +a
#   docker build --platform linux/amd64 \
#       -f deploy/docker/provisioner.Dockerfile \
#       --build-arg BASE_IMAGE="$DEBUGLET_PROVISIONER_BASE_IMAGE" \
#       --build-arg BASE_DIGEST="$DEBUGLET_PROVISIONER_BASE_DIGEST" \
#       ... -t "$DEBUGLET_PROVISIONER_IMAGE" .
#
# deploy/test/provisioner-check.sh builds it exactly that way and then renders
# and checks the playbooks inside it, which is the only supported way to run a
# deployment: a provisioner that differs from these inputs is refused by
# deploy/ansible/preflight-provisioner.yml before any host is touched.
#
# The image carries the playbooks' dependencies and nothing else. The
# repository is mounted into it at run time, so the image does not have to be
# rebuilt when a playbook changes — only when a pinned dependency does.

ARG BASE_IMAGE=python:3.13-slim
ARG BASE_DIGEST=sha256:b04b5d7233d2ad9c379e22ea8927cd1378cd15c60d4ef876c065b25ea8fb3bf3
ARG DEBIAN_SNAPSHOT=20260623T000000Z
ARG OPENSSH_CLIENT_VERSION=1:10.0p1-7+deb13u4

FROM ${BASE_IMAGE}@${BASE_DIGEST} AS provisioner

# Repeated as build arguments so the record below and the preflight that reads
# it name the same values as deploy/provisioner.env.
ARG BASE_IMAGE
ARG BASE_DIGEST
ARG ANSIBLE_CORE_VERSION
ARG COLLECTION_COMMUNITY_GENERAL_VERSION
ARG COLLECTION_COMMUNITY_GENERAL_SHA256
ARG COLLECTION_LIBRARY_INVENTORY_FILTERING_VERSION
ARG COLLECTION_LIBRARY_INVENTORY_FILTERING_SHA256
ARG REQUIREMENTS_SHA256
ARG COLLECTIONS_SHA256
ARG GOOSE_VERSION
ARG GOOSE_SHA256
ARG DEBIAN_SNAPSHOT
ARG OPENSSH_CLIENT_VERSION

ENV ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /provisioner
COPY deploy/ansible/requirements.txt deploy/ansible/requirements.yml ./

# CI runs this image directly, rather than mounting it through a Docker daemon.
# Pin the SSH client to a dated Debian snapshot so a rebuild does not pick up
# an arbitrary OS package revision. The provisioner base is Debian trixie.
RUN set -eu; \
	rm -f /etc/apt/sources.list.d/debian.sources; \
	printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list; \
	printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' "$DEBIAN_SNAPSHOT" >> /etc/apt/sources.list; \
	apt-get update; \
	apt-get install -y --no-install-recommends "openssh-client=$OPENSSH_CLIENT_VERSION"; \
	rm -rf /var/lib/apt/lists/*

# The manifests are checked against the recorded digests before they are used,
# so an image can never be built from a manifest that the repository's pinned
# values do not describe.
RUN set -eu; \
	printf '%s  requirements.txt\n' "$REQUIREMENTS_SHA256" | sha256sum -c -; \
	printf '%s  requirements.yml\n' "$COLLECTIONS_SHA256" | sha256sum -c -

# --require-hashes makes a digest mandatory for every resolved distribution,
# so this installs exactly the files requirements.txt names or fails.
RUN pip install --require-hashes --no-deps -r requirements.txt

# Collections are downloaded as artifacts, verified against their recorded
# digests, and only then installed.
RUN set -eu; \
	ansible-galaxy collection download -r requirements.yml -p /tmp/collections; \
	cd /tmp/collections; \
	printf '%s  community-general-%s.tar.gz\n' \
		"$COLLECTION_COMMUNITY_GENERAL_SHA256" \
		"$COLLECTION_COMMUNITY_GENERAL_VERSION" | sha256sum -c -; \
	printf '%s  community-library_inventory_filtering_v1-%s.tar.gz\n' \
		"$COLLECTION_LIBRARY_INVENTORY_FILTERING_SHA256" \
		"$COLLECTION_LIBRARY_INVENTORY_FILTERING_VERSION" | sha256sum -c -; \
	ansible-galaxy collection install --no-deps -p "$ANSIBLE_COLLECTIONS_PATH" \
		"community-general-${COLLECTION_COMMUNITY_GENERAL_VERSION}.tar.gz" \
		"community-library_inventory_filtering_v1-${COLLECTION_LIBRARY_INVENTORY_FILTERING_VERSION}.tar.gz"; \
	rm -rf /tmp/collections

# goose writes the schema-only databases a deployment installs, so it is an
# input of the provisioner like the rest and is verified against its pinned
# digest before it is kept. The interpreter already in the image fetches it,
# so the image needs no download tool of its own.
RUN set -eu; \
	python -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], "/usr/local/bin/goose")' \
		"https://github.com/pressly/goose/releases/download/v${GOOSE_VERSION}/goose_linux_x86_64"; \
	printf '%s  /usr/local/bin/goose\n' "$GOOSE_SHA256" | sha256sum -c -; \
	chmod 0755 /usr/local/bin/goose; \
	goose --version

# The provisioner's identity, read by deploy/ansible/preflight-provisioner.yml
# and recorded in the deployment record on every managed host.
RUN set -eu; \
	mkdir -p /etc/debuglet; \
	printf '{\n' >/etc/debuglet/provisioner.json; \
	printf '  "schema_version": 1,\n' >>/etc/debuglet/provisioner.json; \
	printf '  "base_image": "%s",\n' "$BASE_IMAGE" >>/etc/debuglet/provisioner.json; \
	printf '  "base_digest": "%s",\n' "$BASE_DIGEST" >>/etc/debuglet/provisioner.json; \
	printf '  "ansible_core_version": "%s",\n' "$ANSIBLE_CORE_VERSION" >>/etc/debuglet/provisioner.json; \
	printf '  "requirements_sha256": "%s",\n' "$REQUIREMENTS_SHA256" >>/etc/debuglet/provisioner.json; \
	printf '  "collections_sha256": "%s",\n' "$COLLECTIONS_SHA256" >>/etc/debuglet/provisioner.json; \
	printf '  "goose_version": "%s",\n' "$GOOSE_VERSION" >>/etc/debuglet/provisioner.json; \
	printf '  "goose_sha256": "%s"\n' "$GOOSE_SHA256" >>/etc/debuglet/provisioner.json; \
	printf '}\n' >>/etc/debuglet/provisioner.json; \
	chmod 0444 /etc/debuglet/provisioner.json

WORKDIR /repository
ENTRYPOINT []
CMD ["ansible-playbook", "--version"]
