# Project settings
EXECUTOR_BINARY = debuglet-executor
DISPATCHER_BINARY = debuglet-dispatcher

# Go command
GO ?= go

.PHONY: all deps build clean docker-build docker-up-executor docker-up-dispatcher docker-up-all docker-down generate-certs

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
