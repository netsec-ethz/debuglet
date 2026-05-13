# Project settings
EXECUTOR_BINARY = debuglet-executor
DISPATCHER_BINARY = debuglet-dispatcher

# Go command
GO ?= go

.PHONY: all deps build clean docker-build docker-up-executor docker-up-dispatcher docker-up-all docker-down generate-certs dispatcher d executor e wasm proto test coverage

all: deps build

# --------------------------------------------------------------------
# Install Go dependencies for local build
# --------------------------------------------------------------------
deps:
	$(GO) mod tidy
	$(GO) get github.com/wasmerio/wasmer-go/wasmer

# --------------------------------------------------------------------
# Build local binaries
# --------------------------------------------------------------------
build:
	$(GO) build -o $(EXECUTOR_BINARY) ./cmd/executor
	$(GO) build -o $(DISPATCHER_BINARY) ./cmd/dispatcher

# --------------------------------------------------------------------
# Run locally
# --------------------------------------------------------------------
dispatcher d:
	@$(GO) run cmd/dispatcher/main.go -config local/configs/dispatcher.toml

executor e:
	@$(GO) run cmd/executor/main.go -config local/configs/executor.toml

wasm:
	@if [ -z "$(SAMPLE_DIR)" ]; then echo "SAMPLE_DIR is required. Usage: make wasm SAMPLE_DIR=..."; exit 1; fi
	GOOS=wasip1 GOARCH=wasm $(GO) build -buildmode=c-shared -o $(SAMPLE_DIR)/debuglet.wasm $(SAMPLE_DIR)/main.go

proto:
	protoc \
	  --go_out=. --go_opt=paths=source_relative,Mschema.proto=. \
	  --go-grpc_out=. --go-grpc_opt=paths=source_relative,Mschema.proto=. \
	  protocol/protocol.proto

test:
	$(GO) test $$($(GO) list ./... | grep -v /local/)

coverage:
	$(GO) test -coverprofile .testCoverage.txt $$($(GO) list ./... | grep -v /local/)

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
# Clean local build artifacts
# --------------------------------------------------------------------
clean:
	rm -f $(EXECUTOR_BINARY) $(DISPATCHER_BINARY)
