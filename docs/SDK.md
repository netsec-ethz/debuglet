# Go client library

[`pkg/client`](../pkg/client) is the supported Go library for applications that submit debuglets and read their results from a dispatcher. It is a **client library**, not the SDK for writing a debuglet; use [`pkg/debuglet`](DEBUGLETS.md) for that.

## Use it

Create a client with a dispatcher endpoint and a credential, then create an intent and submit a debuglet. The working example is in [`examples/client`](../examples/client).

```go
client, err := client.New(client.Options{
    Endpoint: "https://dispatcher.example",
    Credential: sessionToken,
})
if err != nil { /* handle error */ }
```

The library follows the HTTP API contract, including authentication, request validation, submission, state, logs, and cancellation. Pin the module version you test and treat the [OpenAPI document](../api/openapi.yaml) as the wire-level reference.

## Choose an integration surface

| Need | Use |
| --- | --- |
| Shell workflow, demos, and operations | [`dbl`](CLI.md) |
| Go application that calls a dispatcher | `pkg/client` |
| WebAssembly measurement written in Go | [`pkg/debuglet`](DEBUGLETS.md) |
| Another language | [HTTP API](API.md) |
