# Go debuglets

Go is the supported language for writing debuglets. Build a normal `main` package for `GOOS=wasip1 GOARCH=wasm` and use [`pkg/debuglet`](../../../pkg/debuglet) for network operations.

## Start here

| Example | What it shows |
| --- | --- |
| `hello-local` | Arguments and output, with no network access. |
| `latency` | TCP round-trip time. |
| `http_get` | A plaintext HTTP request. |
| `dns` | A DNS lookup over UDP. |
| `throughput` | Sending data to a TCP sink. |
| `listen_tcp`, `listen_udp` | Inbound listeners. |

`ping`, `send_tcp`, and `download` need capabilities or a target that a normal local setup may not provide. They are references, not quickstarts.

## Build and submit

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/latency
dbl run --wasm examples/debuglets/go/latency/debuglet.wasm \
  --allow 127.0.0.1 --wait -- -addr 127.0.0.1:8080 -count 3
```

The debuglet can reach only destinations permitted by both the submitted policy and the executor configuration. Write progress to standard output: it becomes the measurement log.

See [Write a debuglet](../../../docs/debuglets.md) for the SDK and runtime model, and [the shared examples guide](../README.md) for language support.
