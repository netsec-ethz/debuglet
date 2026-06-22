# Build Stage
FROM golang:1.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -o /debuglet-executor ./cmd/executor

# Runtime Stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates openssl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /debuglet-executor /usr/local/bin/debuglet-executor
# The exact version depends on go.mod. Assuming 1.0.4 based on Makefile
RUN ldconfig

RUN useradd --system --no-create-home --shell /usr/sbin/nologin debuglet
USER debuglet

ENTRYPOINT ["/usr/local/bin/debuglet-executor"]
