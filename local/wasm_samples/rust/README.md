# Rust debuglets

Write a debuglet in Rust as a normal binary crate with `fn main()`, build it for
`wasm32-wasip1`, and the executor streams your stdout back to the user. See the
[shared model](../README.md) for the execution contract.

## Layout

| Directory      | What it is |
|----------------|------------|
| `debuglet/`    | the SDK crate (library) |
| `helloworld/`  | prints a greeting (no SDK needed) |
| `ping/`        | ICMPv4 echo-request latency probe |
| `throughput/`  | TCP throughput sender, reports Mbps |

Each sample's binary target is named `debuglet`, so the build output is
`target/wasm32-wasip1/release/debuglet.wasm` (copied to the sample directory by
`make wasm`).

## The Rust SDK (`debuglet` crate)

Add a path dependency and use the safe wrapper instead of writing
`extern "C"` blocks against the `env` module:

```toml
# Cargo.toml
[dependencies]
debuglet = { path = "../debuglet" }
```

```rust
fn main() {
    let conn = debuglet::connect_tcp("example.com:80").unwrap();
    conn.send(b"GET / HTTP/1.0\r\n\r\n");
    let mut buf = [0u8; 4096];
    let n = conn.receive(&mut buf);
    print!("{}", String::from_utf8_lossy(&buf[..n]));
    // conn closes on drop
}
```

API surface:

- `connect_tcp(addr)`, `connect_tls(addr)`, `connect_icmp4(addr)`, `accept_tcp()`
  → `Result<Conn, ConnectError>`
- `Conn::send(&self, &[u8])`
- `Conn::receive(&self, &mut [u8]) -> usize`
- the host socket is closed automatically when the `Conn` is dropped

## Reading arguments

WASI argv has no program name, so the user's flags come straight out of
`std::env::args()` (index 0 is the first real argument). The samples include a
tiny `flag_str` helper rather than pulling in a CLI crate.

## Prerequisites

```sh
rustup target add wasm32-wasip1
```

## Build & run

```sh
make wasm SAMPLE_DIR=local/wasm_samples/rust/ping
go run ./cmd/user -wasm local/wasm_samples/rust/ping/debuglet.wasm -- -addr 1.1.1.1 -iter 5
```
