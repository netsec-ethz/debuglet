# Project settings
EXECUTOR_BINARY = debuglet-executor
DISPATCHER_BINARY = debuglet-dispatcher

# Go command
GO ?= go

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

.PHONY: all deps build clean docker-build docker-up-executor docker-up-dispatcher docker-up-all docker-down generate-certs dispatcher d executor e wasm proto setcaps test coverage deploy-build deploy-certs deploy deploy-dispatcher deploy-executors deploy-update-addr deploy-update-config bootstrap-sudo

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
	@out="$(SAMPLE_DIR)/debuglet.wasm"; \
	if [ -f "$(SAMPLE_DIR)/Cargo.toml" ]; then \
		echo "[rust] building $(SAMPLE_DIR)"; \
		( cd "$(SAMPLE_DIR)" && $(CARGO) build --release --target $(RUST_TARGET) ) && \
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

proto:
	protoc \
	  --go_out=. --go_opt=paths=source_relative,Mschema.proto=. \
	  --go-grpc_out=. --go-grpc_opt=paths=source_relative,Mschema.proto=. \
	  protocol/protocol.proto

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

memory:
	mkdir -p benchmarks
	$(GO) test ./internal/executor/engine/ -bench=. -memprofile benchmarks/engine-mem.out
	$(GO) tool pprof -http=:8080 benchmarks/engine-mem.out

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
# Generate test certificates in configs directory
# --------------------------------------------------------------------
generate-certs:
	@mkdir -p configs/executor configs/dispatcher
	@echo "Generating executor certificates..."
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout local/configs/executor/client.key -out local/configs/executor/client.crt -subj "/CN=executor"
	@echo "Generating dispatcher certificates..."
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout local/configs/dispatcher/server.key -out local/configs/dispatcher/server.crt -subj "/CN=dispatcher"

# --------------------------------------------------------------------
# Remote deployment (requires: docker, ansible, openssl)
# --------------------------------------------------------------------

# Ansible inventory to target — hosts.yml (prod) by default, or
# hosts.dev.yml for the dev environment:
#   make deploy-dispatcher INVENTORY=hosts.dev.yml DEPLOY_ENV=dev
INVENTORY ?= hosts.yml

# Environment whose vars file is layered on top of group_vars — must match
# INVENTORY. It decides the names an executor deploy claims on each machine
# (debuglet-<env> user, /etc/debuglet/executor-<env>, debuglet-executor-<env>
# unit), so pointing a prod-env run at the dev inventory would take over the
# prod executor's install. See deploy/ansible/vars/.
DEPLOY_ENV ?= prod
ENV_VARS := -e @vars/$(DEPLOY_ENV).yml

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
deploy-seed-db:
	mkdir -p deploy/dist
	rm -f deploy/dist/executor-seed.db
	GOOSE_MIGRATION_DIR=./internal/executor/database/migrations \
		$(GOOSE) sqlite3 deploy/dist/executor-seed.db up
	rm -f deploy/dist/dispatcher-seed.db
	GOOSE_MIGRATION_DIR=./internal/dispatcher/database/migrations \
		$(GOOSE) sqlite3 deploy/dist/dispatcher-seed.db up

# Generate CA + dispatcher + executor TLS certs → deploy/certs/
# Extracts executor IDs automatically from deploy/ansible/$(INVENTORY).
# Override by passing EXECUTOR_IDS manually:
#   make deploy-certs EXECUTOR_IDS="id1 id2"
deploy-certs:
	chmod +x deploy/scripts/generate-certs.sh
	@if [ -z "$(EXECUTOR_IDS)" ]; then \
		EXECUTOR_IDS=$$(cd deploy/ansible && ansible-inventory -i $(INVENTORY) --list 2>/dev/null | python3 -c "\
import sys, json; \
inv = json.load(sys.stdin); \
groups = inv.get('executors', {}).get('children', {}); \
hosts = [h for g in groups.values() for h in g.get('hosts', {}).keys()]; \
meta = inv.get('_meta', {}).get('hostvars', {}); \
ids = [meta.get(h, {}).get('executor_id', h) for h in hosts]; \
print(' '.join(ids))" 2>/dev/null); \
		echo "Auto-extracted executor IDs: $$EXECUTOR_IDS"; \
		deploy/scripts/generate-certs.sh $$EXECUTOR_IDS; \
	else \
		deploy/scripts/generate-certs.sh $(EXECUTOR_IDS); \
	fi
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) $(ENV_VARS) deploy-certs.yml

# Full deploy: build → dispatcher → all executors
deploy: deploy-build deploy-seed-db
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) $(ENV_VARS) site.yml

# Deploy only the dispatcher
deploy-dispatcher: deploy-build deploy-seed-db
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) $(ENV_VARS) deploy-dispatcher.yml

# One-time bootstrap: grant passwordless sudo on dispatcher/executor nodes.
# Run this first on any host whose user requires a sudo password.
# Example: make bootstrap-sudo LIMIT=ordroid-ethz
#          make bootstrap-sudo INVENTORY=hosts.dev.yml LIMIT=172.31.201.110
bootstrap-sudo:
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) bootstrap-sudo.yml -K \
		$(if $(LIMIT),--limit $(LIMIT),)

# Deploy only the executors (or pass LIMIT=hostname to target one)
deploy-executors: deploy-build deploy-seed-db
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) $(ENV_VARS) deploy-executors.yml \
		$(if $(LIMIT),--limit $(LIMIT),)

# Push a new dispatcher address to all running executors (no binary redeploy)
# Example: make deploy-update-addr DISPATCHER_ADDR=new-host.example.com:9001
deploy-update-addr:
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) $(ENV_VARS) update-dispatcher-addr.yml \
		$(if $(DISPATCHER_ADDR),-e "dispatcher_addr=$(DISPATCHER_ADDR)",)

# Re-render dispatcher + executor configs and restart changed services (no
# binary redeploy). DEPLOY_VERSION defaults to the current git short SHA.
# Example: make deploy-update-config
#          make deploy-update-config DEPLOY_VERSION=v1.2.3
DEPLOY_VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null)
deploy-update-config:
	cd deploy/ansible && ansible-playbook -i $(INVENTORY) $(ENV_VARS) update-config.yml \
		$(if $(DEPLOY_VERSION),-e "deploy_version=$(DEPLOY_VERSION)",)

# --------------------------------------------------------------------
# Clean local build artifacts
# --------------------------------------------------------------------
clean:
	rm -f $(EXECUTOR_BINARY) $(DISPATCHER_BINARY)
