# Debuglet deployment images.
#
# Both role images carry the same release payload that `scripts/package.sh`
# produces: the binaries are compiled by internal/packaging with the pinned
# Go 1.25.11 toolchain, packaged, verified against the candidate's own
# SHA256SUMS by `scripts/ci-package.sh`, and installed by the package's own
# installer. The images add no second build or stamping path, so
# `dbl version` inside either image reports the packaged version and the
# source revision the payload was built from, exactly as an installed
# package does.
#
# Build both images from the repository root:
#
#   docker build --platform linux/amd64 -f deploy/docker/debuglet.Dockerfile \
#       --target dispatcher -t debuglet-dispatcher .
#   docker build --platform linux/amd64 -f deploy/docker/debuglet.Dockerfile \
#       --target executor -t debuglet-executor .
#
# The payload is Linux amd64 only, so --platform is required when the daemon
# defaults to another architecture.
#
# The build context is the repository root and must be a clean committed
# checkout including .git: the packaging tool refuses to stamp a version onto
# a modified or unidentified source tree. `deploy/docker/smoke-test.sh` builds
# both targets and checks them; `deploy/scripts/build-linux.sh` extracts the
# same payload's daemon binaries for the Ansible deployment.

# Both base images are pinned by digest so a rebuild of one source revision
# resolves the same bytes. The builder digest is the same one the pipeline
# images use; move deploy/ci/images.env and this line together. The only
# unpinned input below is the ca-certificates package apt installs.
ARG GO_IMAGE=golang:1.25.11-bookworm@sha256:b96f24a8d7d010ea0acb9c3ba99064740f02b6b984612b28bd3c9c5ab9453e38
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

FROM ${GO_IMAGE} AS payload
ENV GOTOOLCHAIN=local
WORKDIR /usr/src/debuglet
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The context is copied into a fresh root-owned directory, so git needs to be
# told that this checkout is the one it was asked about.
RUN git config --global --add safe.directory /usr/src/debuglet
# The same two steps as the private CI build and package jobs. Both refuse to
# run against a modified checkout, so the payload identifies exactly this
# source revision.
RUN go run -mod=readonly ./internal/packaging build -dist .cache/ci/dist
RUN bash scripts/ci-package.sh
# Install the verified candidate with its own installer. The role binaries get
# stable names next to the CLI link the installer creates; the payload itself
# stays in the versioned directory the manifest describes.
RUN set -eu; \
	archive=$(ls .cache/ci/packages/debuglet-v*-linux-amd64.tar.gz); \
	version=${archive##*/debuglet-}; version=${version%-linux-amd64.tar.gz}; \
	sh .cache/ci/packages/install.sh \
		--archive "$archive" \
		--checksums .cache/ci/packages/SHA256SUMS \
		--version "$version" \
		--prefix /opt/debuglet; \
	for role in dispatcher executor; do \
		ln -s "../lib/debuglet/$version/bin/debuglet-$role" \
			"/opt/debuglet/bin/debuglet-$role"; \
	done

FROM ${RUNTIME_IMAGE} AS runtime
RUN set -eu; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates; \
	rm -rf /var/lib/apt/lists/*
COPY --from=payload /opt/debuglet /opt/debuglet
ENV PATH=/opt/debuglet/bin:$PATH

FROM runtime AS dispatcher
# HTTP/yamux and gRPC. TLS termination is a separate concern; see
# docker-compose.yml for the local nginx rig.
EXPOSE 9000 9001
ENTRYPOINT ["debuglet-dispatcher"]
CMD ["--config", "/etc/debuglet/dispatcher/dispatcher.toml"]

FROM runtime AS executor
ENTRYPOINT ["debuglet-executor"]
CMD ["--config", "/etc/debuglet/executor/executor.toml"]
