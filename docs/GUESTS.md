# Write a debuglet

A **debuglet** is the small WebAssembly program an executor runs for one measurement. Debuglets are WASI Preview 1 command modules. Their output becomes the measurement output that a client reads with `dbl logs` or the API.

## Start from an example

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/hello-local
dbl run --wasm examples/debuglets/go/hello-local/debuglet.wasm --wait
```

The [examples](../examples/debuglets) show supported patterns. Build Go debuglets for `GOOS=wasip1 GOARCH=wasm` and import `github.com/netsec-ethz/debuglet/pkg/debuglet` when you need Debuglet network operations.

## Runtime model

A debuglet has no host filesystem or ordinary host sockets. The executor provides the network operations allowed by the submitted and operator policies. It enforces the job's time and bandwidth budgets. A policy failure or host-call failure ends the debuglet; write useful progress to standard output before network operations.

The stable host ABI is `debuglet-go-wasi-imports-v1`. The Go package hides its low-level imports behind familiar connection types. Use the package API and examples rather than binding the ABI directly.

## Compatibility

Build and test debuglets against the Debuglet release you plan to use. The executor records the guest ABI in its installation manifest. A debuglet must target an ABI the executor supports.
