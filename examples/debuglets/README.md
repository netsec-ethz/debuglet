# Debuglet examples

A **debuglet** is a WASI WebAssembly program that an executor runs for one measurement. Start with the Go examples: they are built and exercised by this repository. The Rust and C directories are experimental and are not part of the supported workflow: their bindings cover part of the host interface, and the repository runs one retained guest per language against the executor's engine. Python and JavaScript are not currently supported; see [Guest languages](../../docs/development/guest-languages.md).

## Choose an example

| Language | Status | Start here |
| --- | --- | --- |
| Go | Supported | [`go/hello-local`](go/hello-local) for output; [`go/latency`](go/latency) for TCP; [`go/throughput`](go/throughput) for a local TCP sender. |
| Rust | Experimental: TCP, TLS, listener and ICMPv4 bindings | [`rust/README.md`](rust/README.md) |
| C | Experimental: TCP, TLS, listener and ICMPv4 declarations | [`c/README.md`](c/README.md) |

## Build and run

From the repository root:

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/hello-local
dbl run --wasm examples/debuglets/go/hello-local/debuglet.wasm --wait
```

For network measurements, add the target to `--allow` and pass any program arguments after `--`. Only measure systems you are authorized to measure.

```sh
dbl run --wasm examples/debuglets/go/latency/debuglet.wasm \
  --allow 127.0.0.1 --wait -- -addr 127.0.0.1:8080 -count 3
```

See [Write a debuglet](../../docs/debuglets.md) for the execution model and SDK. Use `dbl demo` for a complete self-contained local walkthrough.
