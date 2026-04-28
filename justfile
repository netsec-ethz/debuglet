# https://just.systems

alias d := dispatcher

dispatcher:
    go run cmd/dispatcher/main.go -config local/configs/dispatcher.toml

alias e := executor

executor:
    go run cmd/executor/main.go -config local/configs/executor.toml

wasm SAMPLE_DIR:
    GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o {{ SAMPLE_DIR }}/debuglet.wasm {{ SAMPLE_DIR }}/main.go

proto:
    protoc \
      --go_out=. --go_opt=paths=source_relative,Mschema.proto=. \
      --go-grpc_out=. --go-grpc_opt=paths=source_relative,Mschema.proto=. \
      protocol/protocol.proto
