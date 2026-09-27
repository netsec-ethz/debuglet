# Rust debuglets

These examples are experimental. The project does not build or run them in CI, and their bindings are not covered by the supported compatibility path. Use the [Go examples](../go/README.md) for supported development.

The crates target `wasm32-wasip1`. To explore them, install that Rust target, build one example, and submit the resulting `debuglet.wasm`:

```sh
rustup target add wasm32-wasip1
make wasm SAMPLE_DIR=examples/debuglets/rust/helloworld
dbl run --wasm examples/debuglets/rust/helloworld/debuglet.wasm --wait
```

Treat a successful build as an experiment, not a guarantee of executor compatibility.
