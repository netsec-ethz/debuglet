# WASM debuglet samples

Example debuglets that exercise the host API exported by the executor engine
(`internal/executor/debuglet/wasm/host_functions.go`). They are grouped by source
language:

| Directory | Language | Notes |
|-----------|----------|-------|
| `helloworld/`, `ping/`, `send_tcp/` | Go (`wasip1`) | reference implementations |
| `c/`                                | C (`wasm32-wasi`) | share `c/common/debuglet_api.h` |
| `rust/`                             | Rust (`wasm32-wasip1`) | one crate per sample |

## The host API

The engine runs each sample as a standard **WASI command module**:

- **Entrypoint** is `main()` (`_start`). There is no `run_debuglet()` export.
- **Output** is whatever the sample writes to stdout/stderr — it is streamed back
  to the user. Use `printf` / `println!` / `fmt.Println`.
- **Arguments** are passed verbatim as WASI argv (everything the user types after
  `--`). The program name is *not* prepended, so the first real argument is
  `argv[0]`. The samples read their target from `-addr <host:port>`.
- **Addresses and buffers** are passed by `(pointer, length)`. A guest writes the
  bytes into its own linear memory and hands the host a 32-bit offset plus a
  length, e.g. `connect_tcp(addr, addr_len)` and
  `send_tcp_data(sock, buf, len)`.
- **Timing** uses WASI clocks. The C header wraps `clock_gettime` / `nanosleep`
  as `get_timestamp()` / `sleep_ns()`.

Host functions currently registered: `connect_tcp`, `connect_tls`, `accept_tcp`,
`receive_tcp_data`, `send_tcp_data`, `close_tcp`, `connect_icmp4`, `accept_icmp4`,
`receive_icmp4_data`, `send_icmp4_data`, `close_icmp4`, and the SCION-UDP family.

## Building

```sh
# Go
make wasm SAMPLE_DIR=local/wasm_samples/ping
# C   (requires a wasm32-wasi clang, e.g. wasi-sdk: CLANG=/opt/wasi-sdk/bin/clang)
make wasm SAMPLE_DIR=local/wasm_samples/c/fidelity_ping
# Rust (requires: rustup target add wasm32-wasip1)
make wasm SAMPLE_DIR=local/wasm_samples/rust/helloworld
```

Each build writes `debuglet.wasm` into the sample directory. Run it with, e.g.:

```sh
go run ./cmd/user -wasm local/wasm_samples/c/fidelity_ping/debuglet.wasm -- -addr 1.1.1.1
```

## C samples

| Sample | Transport | Role |
|--------|-----------|------|
| `helloworld`           | —    | prints a greeting |
| `fidelity_ping`        | ICMP | latency probe (prints `RTT_SAMPLE` + `Result:` lines) |
| `latency_icmp`         | ICMP | average ICMP RTT |
| `latency_tcp`          | TCP  | average TCP echo RTT (client) |
| `latency_tcp_server`   | TCP  | echo server for `latency_tcp` |
| `iperf_tcp_client`     | TCP  | throughput sender |
| `iperf_tcp_server`     | TCP  | throughput sink |
| `iperf3_tcp_client`    | TCP  | iperf3-wire-compatible sender |
| `fidelity_iperf_client`| TCP  | 30 s throughput sender |
| `fidelity_iperf_server`| TCP  | throughput sink for the above |

The `*_server` samples call `accept_tcp()`, which depends on the host's TCP
listener. That listener is currently a placeholder in `startServers`
(`internal/executor/debuglet/debuglet.go`); the samples are included for API
completeness and will work once the listener is enabled.

## UDP samples (not ported)

The original `feat/measure-fidelity` branch also shipped UDP samples
(`latency_udp`, `latency_udp_server`, `iperf_udp_client`, `iperf_udp_server`,
`iperf3_udp_client`). They relied on host functions that the refactored engine no
longer exports (`connect_udp`, `send_udp_packet`, `receive_udp_packet`,
`answer_udp_packet`) and on the `udp_send_buffer` / `udp_receive_buffer` globals.
They were left out until UDP support is added back to the host API.
