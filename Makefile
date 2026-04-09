# Project settings
BINARY_NAME = debuglet-executor
SERVICE_NAME = debuglet-executor.service
INSTALL_PATH = /usr/local/bin/$(BINARY_NAME)
SERVICE_PATH = /etc/systemd/system/$(SERVICE_NAME)
CONFIG_PATH = /etc/debuglet/executor
LOG__PATH = /var/log/debuglet
LOG_DIR = /var/log/debuglet
SERVICE_USER = debuglet

# Go command (allow override: make GO=go1.23 build)
GO ?= go

all: deps build

# --------------------------------------------------------------------
# Install Go dependencies
# --------------------------------------------------------------------
deps:
	$(GO) mod tidy
	$(GO) get github.com/wasmerio/wasmer-go/wasmer
	sudo cp $(HOME)/go/pkg/mod/github.com/wasmerio/wasmer-go@v1.0.4/wasmer/packaged/lib/linux-amd64/libwasmer.so /usr/local/lib/
	sudo ldconfig

# --------------------------------------------------------------------
# Build binary
# --------------------------------------------------------------------
build:
	$(GO) build -o $(BINARY_NAME) ./cmd/executor

# --------------------------------------------------------------------
# Install binary + systemd service
# --------------------------------------------------------------------
install: build
	@echo "Installing binary to $(INSTALL_PATH)"
	sudo cp $(BINARY_NAME) $(INSTALL_PATH)
	sudo chmod 755 $(INSTALL_PATH)

	@echo "Setting up log directory..."
	sudo mkdir -p $(LOG_DIR)
	sudo chown $(SERVICE_USER):$(SERVICE_USER) $(LOG_DIR)
	sudo chmod 755 $(LOG_DIR)

	@echo "Installing systemd service..."
	sudo cp $(SERVICE_NAME) $(SERVICE_PATH)
	sudo chmod 644 $(SERVICE_PATH)

	sudo systemctl daemon-reload
	sudo systemctl enable $(SERVICE_NAME)
	sudo systemctl restart $(SERVICE_NAME)

	@echo "Installation complete."

create-user:
	@if d -u $(SERVICE_USER) >/dev/null 2>&1; then \
		echo "User $(SERVICE_USER) exists"; \
	else \
		sudo useradd --system --no-create-home --shell /usr/sbin/nologin $(SERVICE_USER); \
	fi

config: create-user
	sudo mkdir -p $(CONFIG_PATH)
	sudo mkdir -p $(LOG__PATH)
	sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $(CONFIG_PATH)/client.key -out $(CONFIG_PATH)/client.crt -subj "/CN=executor"
	sudo cp executor.toml $(CONFIG_PATH)
	sudo chown -R $(SERVICE_USER):$(SERVICE_USER) $(CONFIG_PATH) $(LOG__PATH)	

# --------------------------------------------------------------------
# Remove everything
# --------------------------------------------------------------------
uninstall:
	@echo "Stopping service..."
	sudo systemctl stop $(SERVICE_NAME)
	sudo systemctl disable $(SERVICE_NAME)

	@echo "Removing binary..."
	sudo rm -f $(INSTALL_PATH)

	@echo "Removing service..."
	sudo rm -f $(SERVICE_PATH)
	sudo systemctl daemon-reload

	@echo "Uninstall done."

# --------------------------------------------------------------------
# Clean local build artifacts
# --------------------------------------------------------------------
clean:
	rm -f $(BINARY_NAME)