# Rust debuglets

These examples and the `debuglet` crate are experimental. They are maintained with the repository as experimental; there is no separate release or version promise. The `guest-languages` CI job rebuilds them and tests fresh source-package consumers. Use the [Go examples](../go/README.md) for supported development; the Go SDK in [`pkg/debuglet`](../../../pkg/debuglet) is the complete reference for the host interface.

## What is checked

The crate's imports are part of guest ABI `debuglet-go-wasi-imports-v1` and use exactly the signatures that ABI freezes. A Rust guest built on the crate is retained in [`pkg/debuglet/testdata/guest_rust`](../../../pkg/debuglet/testdata/guest_rust), and `TestForeignGuestsOnCurrentHost` runs it on the executor's engine: a TCP read until end of stream, a listener that echoes one message, and a refused connection. The retained module and its source-hash record are deliberately updated when the crate changes; CI checks the rebuild.

Tested toolchain: Rust 1.90.0 (`rust:1.90-bookworm` container) with the `wasm32-wasip1` target. The crate declares `rust-version = "1.78"`, the first release with that target name.

## Host semantics

- One host call transfers at most 8192 bytes (`debuglet::MAX_IO_BYTES`). `Conn::receive` fills at most that much; `Conn::send` splits a longer TCP payload into several calls and panics on a longer ICMP datagram rather than truncating it.
- `Conn::receive` returns the byte count, and 0 at a clean end of stream (TCP) or for an empty datagram (ICMP). It never sees a negative count.
- Errors are not returned as values. A refused, unreachable or disallowed destination, a read or write error, an invalid handle and a buffer outside the module's memory abort the guest inside the host call. The job ends with what the guest printed before.
- `accept_tcp` needs the job's TCP listener capability. The executor reports the listener's address to the submitter.

Not provided by the crate: UDP sockets, the address getters (`get_tcp_addr`, `get_udp_addr`, `get_remote_addr`), `drain_connection`, and the recoverable sockets of the optional `debuglet_io_v1` module.

## Build an example

```sh
rustup target add wasm32-wasip1
make wasm SAMPLE_DIR=examples/debuglets/rust/helloworld
dbl run --wasm examples/debuglets/rust/helloworld/debuglet.wasm --wait
```

## Use the crate in your own project

The crate is not published to a registry (`publish = false`). Depend on it by path from a checkout, or by git:

```toml
[dependencies]
# from a checkout
debuglet = { path = "/path/to/debuglet/examples/debuglets/rust/debuglet" }
# or from the repository
debuglet = { git = "https://github.com/netsec-ethz/debuglet" }
```

Cargo finds the crate by name inside the repository. Pin a revision with `rev = "<commit>"` for reproducible builds. Both forms were checked from an empty project:

```sh
cargo new --bin hello && cd hello
cargo add debuglet --git https://github.com/netsec-ethz/debuglet   # or: --path <checkout>/examples/debuglets/rust/debuglet
cargo build --release --target wasm32-wasip1
```

The crate is licensed under the Apache License 2.0, like the rest of the repository.

### Rebuild and consumer validation

From the repository root on Linux amd64, run
`bash scripts/ci-guest-languages.sh`. CI uses the same digest-pinned compilers
to rebuild the retained fixtures, check source/binary hashes and run fresh
package consumers against the current host. Source packages and test results
are written under `.cache/guest-languages/`. These are experimental source
packages; no registry publication or supported release is implied. See
[guest language coverage and limits](../../../docs/development/guest-languages.md).
