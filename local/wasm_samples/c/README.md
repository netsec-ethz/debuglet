# C debuglets

Write a debuglet in C as a normal `int main(int argc, char **argv)`, build it for
the `wasm32-wasi` target, and the executor streams your stdout back to the user.
See the [shared model](../README.md) for the execution contract.

## Starter samples

| Sample        | Transport | What it does |
|---------------|-----------|--------------|
| `helloworld`  | —         | prints a greeting |
| `ping`        | ICMPv4    | echo-request latency probe |
| `throughput`  | TCP       | sends for N seconds, reports Mbps |

## Advanced / benchmark samples

| Sample | Transport | Role |
|--------|-----------|------|
| `fidelity_ping`         | ICMP | latency probe (`RTT_SAMPLE` + `Result:` lines) |
| `latency_icmp`          | ICMP | average ICMP RTT |
| `latency_tcp`           | TCP  | average TCP echo RTT (client) |
| `latency_tcp_server`    | TCP  | echo server for `latency_tcp` |
| `iperf_tcp_client`      | TCP  | throughput sender |
| `iperf_tcp_server`      | TCP  | throughput sink |
| `iperf3_tcp_client`     | TCP  | iperf3-wire-compatible sender |
| `fidelity_iperf_client` | TCP  | 30 s throughput sender |
| `fidelity_iperf_server` | TCP  | throughput sink for the above |

The `*_server` samples call `accept_tcp()`, which depends on the host's TCP
listener — currently a placeholder in `startServers`
(`internal/executor/debuglet/debuglet.go`). They are included for API
completeness and will work once the listener is enabled.

## The C bindings (`common/debuglet_api.h`)

All samples include the shared header, which declares the `env` host imports and
provides small helpers:

```c
#include "../common/debuglet_api.h"

int sock = connect_tcp(addr, addr_len);          // -> handle, or -1
send_tcp_data(sock, buf, len);
int n = receive_tcp_data(sock, buf, sizeof buf); // -> bytes read
close_tcp(sock);

long long t  = get_timestamp();   // monotonic nanoseconds (WASI clock)
sleep_ns(1000000000LL);           // sleep 1 s
const char *a = arg_addr(argc, argv, "1.1.1.1");
```

The ICMPv4 family (`connect_icmp4`, `send_icmp4_data`, …) mirrors the TCP one.
Buffers and addresses are passed by pointer and length directly — the WASM
runtime reads them straight out of linear memory.

## Reading arguments

WASI argv has no program name; the first real argument is `argv[0]`. Use the
`arg_addr` helper for `-addr`, and the small `arg_int` helper in the `ping` /
`throughput` samples for integer flags.

## Prerequisites

You need a `wasm32-wasi` clang from the
[wasi-sdk](https://github.com/WebAssembly/wasi-sdk) (Apple/Linux system clang
cannot target `wasm32-wasi`). Download a release, unpack it, then point the
build at it.

## Build & run

```sh
# either set WASI_SDK (CLANG defaults to $WASI_SDK/bin/clang) ...
make wasm SAMPLE_DIR=local/wasm_samples/c/ping WASI_SDK=/opt/wasi-sdk
# ... or pass CLANG directly
make wasm SAMPLE_DIR=local/wasm_samples/c/ping CLANG=/opt/wasi-sdk/bin/clang

go run ./cmd/user -wasm local/wasm_samples/c/ping/debuglet.wasm -- -addr 1.1.1.1 -iter 5
```

`make wasm` compiles `main.c` with `-O2 -lm`.
