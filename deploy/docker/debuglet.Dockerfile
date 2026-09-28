# Build role-only Linux amd64 images with --target cli, executor or dispatcher.
# --target full keeps the CLI, both daemons and samples for local development.
# All targets use the same compiled candidate and verified package installer.
# Build from a clean committed repository root including .git.

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
# The same two steps as the CI build and package jobs. Both refuse to
# run against a modified checkout, so the payload identifies exactly this
# source revision.
RUN go run -mod=readonly ./internal/packaging build -dist .cache/ci/dist
RUN bash scripts/ci-package.sh
# Keep the full installation available to the deployment payload extractor.
RUN set -eu; \
	archive=$(ls .cache/ci/packages/debuglet-v*-linux-amd64.tar.gz); \
	version=${archive##*/debuglet-}; version=${version%-linux-amd64.tar.gz}; \
	sh .cache/ci/packages/install.sh --archive "$archive" \
		--checksums .cache/ci/packages/SHA256SUMS --version "$version" --prefix /opt/debuglet; \
	for role in dispatcher executor; do \
		ln -s "../lib/debuglet/$version/bin/debuglet-$role" "/opt/debuglet/bin/debuglet-$role"; \
	done; \
	for role in cli dispatcher executor; do \
		sh ".cache/ci/packages/$role/install-$role.sh" \
			--archive ".cache/ci/packages/$role/debuglet-$role-$version-linux-amd64.tar.gz" \
			--checksums ".cache/ci/packages/$role/SHA256SUMS-$role" \
			--version "$version" --prefix "/opt/debuglet-$role"; \
	done

FROM ${RUNTIME_IMAGE} AS runtime
RUN set -eu; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates; \
	rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/debuglet/bin:$PATH

FROM runtime AS full
COPY --from=payload /opt/debuglet /opt/debuglet
ENTRYPOINT ["dbl"]
CMD ["--help"]

FROM runtime AS cli
COPY --from=payload /opt/debuglet-cli /opt/debuglet
ENTRYPOINT ["dbl"]
CMD ["--help"]

FROM runtime AS dispatcher
COPY --from=payload /opt/debuglet-dispatcher /opt/debuglet
# HTTP/yamux and gRPC. TLS termination is a separate concern; see
# docker-compose.yml for the local nginx rig.
EXPOSE 9000 9001
ENTRYPOINT ["debuglet-dispatcher"]
CMD ["--config", "/etc/debuglet/dispatcher/dispatcher.toml"]

FROM runtime AS executor
COPY --from=payload /opt/debuglet-executor /opt/debuglet
ENTRYPOINT ["debuglet-executor"]
CMD ["--config", "/etc/debuglet/executor/executor.toml"]
