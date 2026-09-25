# Rust measurements

**Experimental. Not a supported quickstart.** Nothing in this repository builds,
executes or checks these crates, and no Rust toolchain is part of the pinned
build. Their bindings are not covered by the guest ABI compatibility suite, so a
successful build establishes nothing about how they behave on an executor. Use
the [Go samples](../go/README.md) for supported measurements.

The Rust examples are ordinary binary crates built for `wasm32-wasip1`. The
executor records stdout/stderr, and guest arguments arrive without a
program-name element. See the [shared guide](../README.md) and the
[guest guide](../../../docs/GUESTS.md) for the imports they call.

## Samples

- `helloworld`: output only.
- `ping`: ICMPv4 echo latency.
- `throughput`: TCP sender.
- `debuglet`: a local SDK crate wrapping the executor's custom host imports.

Each example names its binary `debuglet`; `make wasm` copies the resulting module into the sample directory.

## SDK

Add the local crate to a sample's `Cargo.toml`:

```toml
[dependencies]
debuglet = { path = "../debuglet" }
```

The SDK provides `connect_tcp`, `connect_tls`, `connect_icmp4`, and `accept_tcp`, returning `Result<Conn, ConnectError>`. Use `Conn::send` and `Conn::receive` for data; dropping the connection closes its host socket. Listener and ICMP operations need the corresponding executor configuration.

One host call transfers at most 8192 bytes, so `Conn::send` of a larger buffer sends only the first 8192 and `Conn::receive` fills a larger buffer only that far. A refused or disallowed destination ends the job inside the host call instead of returning an error.

Parse user arguments directly from `std::env::args()`; its first item is the first supplied guest argument.

## Build and submit

```sh
rustup target add wasm32-wasip1
make wasm SAMPLE_DIR=local/wasm_samples/rust/helloworld
dbl run --wasm local/wasm_samples/rust/helloworld/debuglet.wasm \
  --executor EXECUTOR_ID --wait
```

Run the build from the repository root and replace `EXECUTOR_ID` with a node from `dbl nodes`. A successful build does not verify runtime compatibility; the installed demo uses the Go guest path.
