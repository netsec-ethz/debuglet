# Build Stage
FROM golang:1.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /debuglet-dispatcher ./cmd/dispatcher

# Runtime Stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /debuglet-dispatcher /usr/local/bin/debuglet-dispatcher

RUN useradd --system --no-create-home --shell /usr/sbin/nologin debuglet
USER debuglet

EXPOSE 9001

ENTRYPOINT ["/usr/local/bin/debuglet-dispatcher"]
