# Project settings
EXECUTOR_BINARY = debuglet-executor
DISPATCHER_BINARY = debuglet-dispatcher

# Go command
GO ?= go

.PHONY: all deps build clean docker-build docker-up-executor docker-up-dispatcher docker-up-all docker-down generate-certs dispatcher d executor e wasm proto setcaps test coverage deploy-build deploy-certs deploy deploy-dispatcher deploy-executors deploy-update-addr bootstrap-sudo

all: deps build

# --------------------------------------------------------------------
# Install Go dependencies for local build
# --------------------------------------------------------------------
deps:
	$(GO) mod download

# --------------------------------------------------------------------
# Build local binaries
# --------------------------------------------------------------------
build-exec:
	$(GO) build -o $(EXECUTOR_BINARY) ./cmd/executor

build-disp:
	$(GO) build -o $(DISPATCHER_BINARY) ./cmd/dispatcher

build: build-exec build-disp

# --------------------------------------------------------------------
# Run locally
# --------------------------------------------------------------------
dispatcher d:
	@$(GO) run cmd/dispatcher/main.go -config local/configs/dispatcher.toml

executor e:
	sudo -E mise x -- go run cmd/executor/main.go -config local/configs/executor.toml

wasm:
	@if [ -z "$(SAMPLE_DIR)" ]; then echo "SAMPLE_DIR is required. Usage: make wasm SAMPLE_DIR=..."; exit 1; fi
	GOOS=wasip1 GOARCH=wasm $(GO) build -o $(SAMPLE_DIR)/debuglet.wasm $(SAMPLE_DIR)/main.go

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

# Build Linux x86_64 binaries via Docker → deploy/dist/
deploy-build:
	chmod +x deploy/scripts/build-linux.sh
	deploy/scripts/build-linux.sh

# Generate CA + dispatcher + executor TLS certs → deploy/certs/
# EXECUTOR_IDS: space-separated list matching executor_id in inventory/hosts.yml
# Example: make deploy-certs EXECUTOR_IDS="executor-node1 executor-node2"
deploy-certs:
	chmod +x deploy/scripts/generate-certs.sh
	deploy/scripts/generate-certs.sh $(EXECUTOR_IDS)

# Full deploy: build → certs → dispatcher → all executors
deploy: deploy-build
	cd deploy/ansible && ansible-playbook playbooks/site.yml

# Deploy only the dispatcher
deploy-dispatcher: deploy-build
	cd deploy/ansible && ansible-playbook playbooks/deploy-dispatcher.yml

# One-time bootstrap: grant passwordless sudo on executor nodes.
# Run this first on any host whose user requires a sudo password.
# Example: make bootstrap-sudo LIMIT=ordroid-ethz
bootstrap-sudo:
	cd deploy/ansible && ansible-playbook playbooks/bootstrap-sudo.yml -K \
		$(if $(LIMIT),--limit $(LIMIT),)

# Deploy only the executors (or pass LIMIT=hostname to target one)
deploy-executors: deploy-build
	cd deploy/ansible && ansible-playbook playbooks/deploy-executors.yml \
		$(if $(LIMIT),--limit $(LIMIT),)

# Push a new dispatcher address to all running executors (no binary redeploy)
# Example: make deploy-update-addr DISPATCHER_ADDR=new-host.example.com:9001
deploy-update-addr:
	cd deploy/ansible && ansible-playbook playbooks/update-dispatcher-addr.yml \
		$(if $(DISPATCHER_ADDR),-e "dispatcher_addr=$(DISPATCHER_ADDR)",)

# --------------------------------------------------------------------
# Clean local build artifacts
# --------------------------------------------------------------------
clean:
	rm -f $(EXECUTOR_BINARY) $(DISPATCHER_BINARY)

# --------------------------------------------------------------------
# Install systemd services
# --------------------------------------------------------------------

SYSTEMD_PATH = /etc/systemd/system

systemd-install: build-disp
	sudo cp build/dispatcher.service $(SYSTEMD_PATH)/debuglet-dispatcher.service
	sudo systemctl daemon-reload
	sudo systemctl enable debuglet-dispatcher.service
	sudo systemctl restart debuglet-dispatcher.service

systemd-uninstall: build-disp
	sudo systemctl stop debuglet-dispatcher.service || true
	sudo systemctl disable debuglet-dispatcher.service || true
	sudo rm -f $(SYSTEMD_PATH)/debuglet-dispatcher.service
	sudo systemctl daemon-reload
