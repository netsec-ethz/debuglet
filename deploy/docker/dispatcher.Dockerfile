# Build Stage
FROM golang:1.25 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/dispatcher ./cmd/dispatcher
COPY internal/dispatcher ./internal/dispatcher
COPY protocol ./protocol

RUN go install github.com/sqlc-dev/sqlc/cmd/sqlc@1.31.1
RUN go install github.com/pressly/goose/v3/cmd/goose@3.27.3
RUN go generate ./...
RUN CGO_ENABLED=0 go build -o /debuglet-dispatcher ./cmd/dispatcher

# Runtime Stage
FROM scratch
COPY --from=builder /debuglet-dispatcher /
EXPOSE 9000 9001 9002
ENTRYPOINT ["/debuglet-dispatcher"]
