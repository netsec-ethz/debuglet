# https://just.systems

alias d := dispatcher
dispatcher:
    go run cmd/dispatcher/main.go -config local-config/dispatcher.toml

alias e := executor
executor:
    go run cmd/executor/main.go -config local-config/executor.toml
