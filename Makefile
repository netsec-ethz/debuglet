# Project settings
.DEFAULT_GOAL := all
EXECUTOR_BINARY = debuglet-executor
DISPATCHER_BINARY = debuglet-dispatcher

# Go command
GO ?= go

# CI uses explicit native package roots so WASI examples are built for
# their actual target instead of being treated as host programs.
CI_PACKAGES = ./api/... ./cmd/... ./internal/... ./pkg/... ./protocol/...
CI_TEST_TIMEOUT ?= 4m
CI_DIST ?= .cache/ci/dist

# Race-detector lane: the scheduler, session/transport, registry and
# owned-resource cleanup packages whose regressions depend on concurrent
# lifecycles. These are explicit native roots for the same reason as above.
# Keep the lane bounded; see docs/ci.md for the budget and what it excludes.
CI_RACE_PACKAGES = \
	./internal/connections \
	./internal/controlsession \
	./internal/dispatcher \
	./internal/dispatcher/resource/schedule \
	./internal/dispatcher/resource/schedule/dyn \
	./internal/dispatcher/transport/rpc \
	./internal/executor/debuglet \
	./internal/executor/debuglet/socket \
	./internal/executor/debuglet/wasm \
	./internal/executor/debuglet/wasm/hostconn \
	./internal/executor/ratelimit/fallback \
	./internal/executor/scheduler/memory \
	./internal/executor/transport/rpc \
	./internal/readiness
CI_RACE_TIMEOUT ?= 5m
CI_RACE_BUDGET_SECONDS ?= 240
CI_RACE_PACKAGE_PARALLEL ?= 2

.PHONY: ci-test ci-vet ci-fmt ci-race ci-build ci-kernel ci-package ci-demo ci-compatibility ci-local

ci-test:
	python3 -m unittest -v tools/test_make_targets.py tools/test_ci_github.py
	GO="$(GO)" CI_TEST_TIMEOUT="$(CI_TEST_TIMEOUT)" bash scripts/ci-test.sh $(CI_PACKAGES)

ci-vet:
	$(GO) vet -mod=readonly $(CI_PACKAGES)

# Report tracked Go files that the pinned toolchain would reformat.
ci-fmt:
	GO="$(GO)" bash scripts/ci-fmt.sh

# Concurrency regressions under the race detector, with their JSON results.
ci-race:
	GO="$(GO)" CI_RACE_TIMEOUT="$(CI_RACE_TIMEOUT)" \
	CI_RACE_BUDGET_SECONDS="$(CI_RACE_BUDGET_SECONDS)" \
	CI_RACE_PACKAGE_PARALLEL="$(CI_RACE_PACKAGE_PARALLEL)" \
	bash scripts/ci-race.sh $(CI_RACE_PACKAGES)

# Build from committed eBPF objects. ci-kernel loads those bytes, then
# regenerates them to check compiler compatibility in the hosted Linux VM.
ci-build:
	GO="$(GO)" $(GO) run -mod=readonly ./internal/packaging build -dist "$(CI_DIST)"

ci-package:
	GO="$(GO)" CI_DIST="$(CI_DIST)" bash scripts/ci-package.sh

ci-demo:
	GO="$(GO)" bash scripts/ci-demo.sh

ci-compatibility:
	GO="$(GO)" COMPAT_ARCHIVE="$(COMPAT_ARCHIVE)" COMPAT_SHA256SUMS="$(COMPAT_SHA256SUMS)" bash scripts/ci-compatibility.sh

ci-local:
	GO="$(GO)" bash scripts/ci-local.sh

ci-kernel:
	GO="$(GO)" CI_TEST_TIMEOUT="$(CI_TEST_TIMEOUT)" bash scripts/ci-kernel.sh

# Goose command (installed via mise, see mise.toml) — avoid `go run
# .../goose@version`, which rebuilds goose from source on every invocation
# since it's not mise's already-installed binary.
GOOSE ?= goose

# --------------------------------------------------------------------
# Toolchains for building debuglet WASM samples (override as needed).
# Go needs nothing extra. The others are only required to build their
# respective samples:
#   C      : a wasm32-wasi clang (wasi-sdk). Set WASI_SDK=/path/to/wasi-sdk
#            (then CLANG defaults to $(WASI_SDK)/bin/clang), or set CLANG directly.
#   Rust   : rustup target add wasm32-wasip1
#   JS     : javy (https://github.com/bytecodealliance/javy)
# --------------------------------------------------------------------
WASI_SDK    ?=
CLANG       ?= $(if $(WASI_SDK),$(WASI_SDK)/bin/clang,clang)
CARGO       ?= cargo
JAVY        ?= javy
RUST_TARGET ?= wasm32-wasip1

.PHONY: all deps build clean docker-build docker-up-executor docker-up-dispatcher docker-up-all docker-down generate-certs dispatcher d executor e wasm proto setcaps test coverage benchmark memory memory-view deploy-build deploy-certs deploy deploy-dispatcher deploy-executors deploy-update-addr deploy-update-config bootstrap-sudo generate-sql

all: deps build

# --------------------------------------------------------------------
# Install Go dependencies for local build
# --------------------------------------------------------------------
deps:
	$(GO) mod tidy

# --------------------------------------------------------------------
# Build local binaries
# --------------------------------------------------------------------
build-exec:
	# clang's bpf target never searches the multiarch include dir (unlike
	# its native target, where it auto-probes gcc for this), so
	# <asm/types.h> from linux-libc-dev is invisible to it by default even
	# with gcc installed. Point bpf2go's clang invocation at it explicitly.
	BPF2GO_CFLAGS="-I/usr/include/$$(gcc -print-multiarch)" $(GO) generate ./...
	$(GO) build -o $(EXECUTOR_BINARY) ./cmd/executor

build-disp:
	$(GO) build -o $(DISPATCHER_BINARY) ./cmd/dispatcher

build: build-exec build-disp

# --------------------------------------------------------------------
# Run locally
# --------------------------------------------------------------------
dispatcher d:
	@$(GO) run cmd/dispatcher/main.go -config local/configs/dispatcher/dispatcher.toml

executor e:
ifdef EBPF
	$(MAKE) build-exec
	sudo ./$(EXECUTOR_BINARY) -config local/configs/executor/executor.toml
else
	@$(GO) run cmd/executor/main.go -config local/configs/executor/executor.toml
endif

# Build a debuglet sample to $(SAMPLE_DIR)/debuglet.wasm. The language is
# detected from the entrypoint file present in SAMPLE_DIR.
#   Usage: make wasm SAMPLE_DIR=local/wasm_samples/<lang>/<sample>
wasm:
	@if [ -z "$(SAMPLE_DIR)" ]; then echo "SAMPLE_DIR is required. Usage: make wasm SAMPLE_DIR=..."; exit 1; fi
	@set -e; out="$(SAMPLE_DIR)/debuglet.wasm"; \
	if [ -f "$(SAMPLE_DIR)/Cargo.toml" ]; then \
		echo "[rust] building $(SAMPLE_DIR)"; \
		( cd "$(SAMPLE_DIR)" && $(CARGO) build --release --target $(RUST_TARGET) ); \
		cp "$(SAMPLE_DIR)/target/$(RUST_TARGET)/release/debuglet.wasm" "$$out"; \
	elif [ -f "$(SAMPLE_DIR)/main.go" ]; then \
		echo "[go] building $(SAMPLE_DIR)"; \
		GOOS=wasip1 GOARCH=wasm $(GO) build -o "$$out" "$(SAMPLE_DIR)/main.go"; \
	elif [ -f "$(SAMPLE_DIR)/main.c" ]; then \
		echo "[c] building $(SAMPLE_DIR) with $(CLANG)"; \
		$(CLANG) -O2 "$(SAMPLE_DIR)/main.c" -lm -o "$$out"; \
	elif [ -f "$(SAMPLE_DIR)/main.js" ]; then \
		echo "[js] building $(SAMPLE_DIR) with $(JAVY)"; \
		$(JAVY) build "$(SAMPLE_DIR)/main.js" -o "$$out"; \
	else \
		echo "no recognized entrypoint (Cargo.toml/main.go/main.c/main.js) in $(SAMPLE_DIR)"; exit 1; \
	fi; \
	echo "wrote $$out"

# Regenerate the protocol bindings from protocol/protocol.proto with the
# generators pinned in mise.toml. The result is what the pinned protocol
# compiler produces, and scripts/ci-generate.sh rejects any difference between
# it and the committed sources. Both targets fetch the pinned generators from
# the Go module proxy the first time they are used. See docs/generation.md.
proto:
	GO="$(GO)" bash scripts/ci-generate.sh write-proto

# Regenerate the dispatcher and executor database bindings with the pinned
# sqlc, reading the query and schema directories named in sqlc.yml.
generate-sql:
	GO="$(GO)" bash scripts/ci-generate.sh write-sql

setcaps: build
	sudo setcap cap_net_admin,cap_bpf+ep ./$(EXECUTOR_BINARY)

test:
	$(GO) test $$($(GO) list ./... | grep -v /local/) -v

coverage:
	$(GO) test -coverprofile .testCoverage.txt $$($(GO) list ./... | grep -v /local/)

benchmark:
	mkdir -p benchmarks
	$(GO) test $$($(GO) list ./... | grep -v /local/) -bench=. -count=10 -benchtime=5s | tee benchmarks/bench.txt
	benchstat benchmarks/bench.txt

MEMORY_PACKAGE = ./internal/dispatcher/resource
MEMORY_BENCHMARK = ^BenchmarkDestinationsInsert/Initial10000$$
MEMORY_PROFILE ?= benchmarks/dispatcher-resource-mem.out
MEMORY_TIMEOUT ?= 30s

memory:
	@mkdir -p '$(dir $(MEMORY_PROFILE))'
	@set -eu; \
	profile_tmp=$$(mktemp '$(dir $(MEMORY_PROFILE)).memory-profile.XXXXXX'); \
	report_tmp=$$(mktemp '$(dir $(MEMORY_PROFILE)).memory-report.XXXXXX'); \
	trap 'rm -f "$$profile_tmp" "$$report_tmp"' EXIT HUP INT TERM; \
	if ! $(GO) test $(MEMORY_PACKAGE) -run '^$$' -bench '$(MEMORY_BENCHMARK)' -benchtime=1x -count=1 -timeout '$(MEMORY_TIMEOUT)' -memprofile "$$profile_tmp" >"$$report_tmp" 2>&1; then \
		cat "$$report_tmp" >&2; exit 1; \
	fi; \
	cat "$$report_tmp"; \
	if ! grep -Eq '^BenchmarkDestinationsInsert/Initial10000(-[0-9]+)?[[:space:]]+[1-9][0-9]*[[:space:]]' "$$report_tmp"; then \
		echo "memory benchmark did not run: BenchmarkDestinationsInsert/Initial10000" >&2; exit 1; \
	fi; \
	test -s "$$profile_tmp" || { echo "memory profile was not created: $(MEMORY_PROFILE)" >&2; exit 1; }; \
	mv "$$profile_tmp" '$(MEMORY_PROFILE)'; \
	echo "wrote $(MEMORY_PROFILE)"

memory-view:
	@test -s '$(MEMORY_PROFILE)' || { echo "memory profile is missing or empty; run 'make memory' first" >&2; exit 1; }
	$(GO) tool pprof -http=:8080 '$(MEMORY_PROFILE)'

# --------------------------------------------------------------------
# Database
# --------------------------------------------------------------------
upgrade:
	mkdir -p .data
	GOOSE_MIGRATION_DIR=./internal/dispatcher/database/migrations $(GOOSE) sqlite3 .data/dispatcher.db up
	GOOSE_MIGRATION_DIR=./internal/executor/database/migrations $(GOOSE) sqlite3 .data/executor.db up

downgrade:
	GOOSE_MIGRATION_DIR=./internal/dispatcher/database/migrations $(GOOSE) sqlite3 .data/dispatcher.db down
	GOOSE_MIGRATION_DIR=./internal/executor/database/migrations $(GOOSE) sqlite3 .data/executor.db down

# --------------------------------------------------------------------
# Docker orchestration
# --------------------------------------------------------------------
docker-build:
	docker compose build

docker-up-executor:
	docker compose up -d executor

docker-up-dispatcher:
	docker compose up -d dispatcher

docker-up-all:
	docker compose up -d

docker-down:
	docker compose down

# --------------------------------------------------------------------
# Generate self-signed certificates for local development in local/configs.
# A client matches a certificate by its subjectAltName, so both carry the
# loopback names, and each names the role it may be used for. The local
# configurations run with TLS disabled and do not read these; deployment
# material is a different thing, see deploy/scripts/generate-certs.sh.
# --------------------------------------------------------------------
generate-certs:
	@mkdir -p local/configs/executor local/configs/dispatcher
	@echo "Generating executor certificates..."
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout local/configs/executor/client.key -out local/configs/executor/client.crt -subj "/CN=executor" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=clientAuth" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Generating dispatcher certificates..."
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout local/configs/dispatcher/server.key -out local/configs/dispatcher/server.crt -subj "/CN=dispatcher" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# --------------------------------------------------------------------
# Remote deployment (requires: docker). deploy-certs additionally runs openssl
# through deploy/scripts/generate-certs.sh and shells out to python3 to read
# the executor identities out of the inventory.
# --------------------------------------------------------------------
# Deployment runs in the pinned provisioner container, which carries the
# Ansible version and collections deploy/provisioner.env pins; the playbooks
# refuse to run anywhere else. deploy/scripts/provisioner.sh builds it if it
# is absent and runs one command in it.
ANSIBLE_PLAYBOOK ?= ../scripts/provisioner.sh ansible-playbook
ANSIBLE_INVENTORY ?= ../scripts/provisioner.sh ansible-inventory

# Select the matching inventory and environment. Each environment owns its
# executor accounts, service units, configuration, state and installed binaries.
INVENTORY ?= hosts.yml
DEPLOY_ENV ?= prod
ENV_VARS = -e @vars/$(DEPLOY_ENV).yml

# Build Linux x86_64 binaries via Docker → deploy/dist/
deploy-build:
	chmod +x deploy/scripts/build-linux.sh
	deploy/scripts/build-linux.sh

# Generate schema-only executor/dispatcher SQLite DBs → deploy/dist/*-seed.db.
# The ansible roles install these on first deploy only (they never overwrite
# an existing DB, so persisted state survives redeploys). Not committed to
# git: deploy/dist/ is gitignored and these are regenerated from the
# migrations directories on every build, same as the binaries in this
# directory.
#
# goose runs in the pinned provisioner, which is the only tool version a
# deployment is allowed to have used: the databases go to every managed host,
# so the migration tool that wrote them is pinned like the rest. deploy/dist is
# the one directory the container may write to.
DEPLOY_GOOSE = DEBUGLET_PROVISIONER_WRITE_DIR=$(CURDIR)/deploy/dist \
	DEBUGLET_PROVISIONER_AS_CALLER=1 deploy/scripts/provisioner.sh goose
deploy-seed-db:
	mkdir -p deploy/dist
	rm -f deploy/dist/executor-seed.db
	$(DEPLOY_GOOSE) -dir /repository/internal/executor/database/migrations \
		sqlite3 /output/executor-seed.db up
	rm -f deploy/dist/dispatcher-seed.db
	$(DEPLOY_GOOSE) -dir /repository/internal/dispatcher/database/migrations \
		sqlite3 /output/dispatcher-seed.db up

# Generate CA + dispatcher + executor TLS certs → deploy/certs/, then install
# them. Extracts executor IDs from the selected inventory and environment.
# DISPATCHER_SANS is required: an executor verifies the dispatcher against the
# name it dialled, so the certificate has to carry it.
#   make deploy-certs DISPATCHER_SANS="DNS:dispatcher.example.com,IP:203.0.113.10"
#   make deploy-certs DISPATCHER_SANS=... EXECUTOR_IDS="uuid1 uuid2"
deploy-certs:
	chmod +x deploy/scripts/generate-certs.sh
	@if [ -z "$(DISPATCHER_SANS)" ]; then \
		echo "make deploy-certs requires DISPATCHER_SANS, for example" >&2; \
		echo "  make deploy-certs DISPATCHER_SANS=\"DNS:dispatcher.example.com\"" >&2; \
		exit 2; \
	fi
	@if [ -z "$(EXECUTOR_IDS)" ]; then \
		inventory=$$(cd deploy/ansible && $(ANSIBLE_INVENTORY) -i "$(INVENTORY)" $(ENV_VARS) --list) || \
			{ echo "Could not read Ansible inventory" >&2; exit 1; }; \
		EXECUTOR_IDS=$$(printf '%s\n' "$$inventory" | python3 deploy/scripts/executor-ids.py) || exit 1; \
		echo "Auto-extracted executor IDs: $$EXECUTOR_IDS"; \
		DISPATCHER_SANS="$(DISPATCHER_SANS)" deploy/scripts/generate-certs.sh $$EXECUTOR_IDS; \
	else \
		DISPATCHER_SANS="$(DISPATCHER_SANS)" deploy/scripts/generate-certs.sh $(EXECUTOR_IDS); \
	fi
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) deploy-certs.yml

# Full deploy: build → dispatcher → all executors
deploy: deploy-build deploy-seed-db
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) site.yml

# Deploy only the dispatcher
deploy-dispatcher: deploy-build deploy-seed-db
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) deploy-dispatcher.yml

# One-time bootstrap: grant passwordless sudo on dispatcher/executor nodes.
# Run this first on any host whose user requires a sudo password.
# Example: make bootstrap-sudo LIMIT=executor.example.com
bootstrap-sudo:
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) bootstrap-sudo.yml -K \
		$(if $(LIMIT),--limit $(LIMIT),)

# Deploy only the executors (or pass LIMIT=hostname to target one)
deploy-executors: deploy-build deploy-seed-db
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) deploy-executors.yml \
		$(if $(LIMIT),--limit $(LIMIT),)

# Push a new dispatcher address to all running executors (no binary redeploy)
# Example: make deploy-update-addr DISPATCHER_ADDR=new-host.example.com:9001
deploy-update-addr:
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) update-dispatcher-addr.yml \
		$(if $(DISPATCHER_ADDR),-e "dispatcher_addr=$(DISPATCHER_ADDR)",)

# Re-render dispatcher + executor configs and restart changed services (no
# binary redeploy). DEPLOY_VERSION defaults to `git describe`, so a deploy from
# a tagged commit reports v0.1.0 rather than an opaque SHA, and a deploy from an
# uncommitted tree is visibly suffixed -dirty.
# Example: make deploy-update-config
#          make deploy-update-config DEPLOY_VERSION=v1.2.3
DEPLOY_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
deploy-update-config:
	cd deploy/ansible && $(ANSIBLE_PLAYBOOK) -i "$(INVENTORY)" $(ENV_VARS) update-config.yml \
		$(if $(DEPLOY_VERSION),-e "deploy_version=$(DEPLOY_VERSION)",)

# --------------------------------------------------------------------
# Clean local build artifacts
# --------------------------------------------------------------------
clean:
	rm -f $(EXECUTOR_BINARY) $(DISPATCHER_BINARY)
