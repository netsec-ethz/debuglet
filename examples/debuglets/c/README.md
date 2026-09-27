# C debuglets

These examples are experimental and are not built or run by the project checks. Use the [Go examples](../go/README.md) for supported development.

The examples use [`common/debuglet_api.h`](common/debuglet_api.h) to call the executor's WebAssembly imports. Build with [wasi-sdk](https://github.com/WebAssembly/wasi-sdk):

```sh
make wasm SAMPLE_DIR=examples/debuglets/c/helloworld WASI_SDK=/path/to/wasi-sdk
dbl run --wasm examples/debuglets/c/helloworld/debuglet.wasm --wait
```

Network examples also need an allowed destination and the corresponding executor capability. A build does not validate runtime compatibility.
