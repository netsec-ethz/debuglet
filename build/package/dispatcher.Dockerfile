# Build Stage
FROM golang:1.25 AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/dispatcher ./cmd/dispatcher
COPY internal/dispatcher ./internal/dispatcher
COPY protocol ./protocol

RUN CGO_ENABLED=0 go build -o /debuglet-dispatcher ./cmd/dispatcher

# Runtime Stage
FROM scratch
COPY --from=builder /debuglet-dispatcher /debuglet-dispatcher
EXPOSE 9001
ENTRYPOINT ["/debuglet-dispatcher"]
