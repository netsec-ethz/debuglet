# Build Stage
FROM golang:1.25 AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    gcc-multilib

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/executor ./cmd/executor
COPY internal/executor ./internal/executor
COPY protocol ./protocol

RUN go generate ./...
RUN CGO_ENABLED=0 go build -o /debuglet-executor ./cmd/executor

# Runtime Stage
FROM scratch
COPY --from=builder /debuglet-executor /debuglet-executor
EXPOSE 9001
ENTRYPOINT ["/debuglet-executor"]
