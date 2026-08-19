# Writing Debuglets

A **debuglet** is a small WASM program that runs a network measurement on a
Debuglet executor. This directory holds reference samples, grouped by source
language, plus client libraries (SDKs) that hide the low-level host interface.

If you are new here, read this page once for the shared model, then jump to the
guide for your language:

| Language   | Guide                                        | SDK / bindings                                  | Status           |
| ---------- | -------------------------------------------- | ----------------------------------------------- | ---------------- |
| Go         | [go/README.md](go/README.md)                 | `pkg/debuglet` (import `debuglet/pkg/debuglet`) | full             |
| Rust       | [rust/README.md](rust/README.md)             | `debuglet` crate (`rust/debuglet`)              | full             |
| C          | [c/README.md](c/README.md)                   | `c/common/debuglet_api.h`                       | full             |
| JavaScript | [javascript/README.md](javascript/README.md) | — (stdout only, via Javy)                       | hello-world only |
| Python     | [python/README.md](python/README.md)         | — (not currently runnable)                      | unsupported      |

Each language ships the same three starter samples — **helloworld**, **ping**,
and **throughput** — except where the toolchain can't support them (see below).

## The execution model

The executor runs every debuglet as a standard **WASI command module**
(`wasi_snapshot_preview1`) via [wazero](https://github.com/tetratelabs/wazero):

- **Entrypoint** is `main()` / `_start`. There is no special export to define.
- **Output** is whatever you write to stdout/stderr — it is streamed back to the
  user live. Use `fmt.Println` / `println!` / `printf` / `console.log`.
- **Arguments** typed by the user (everything after `--` on the `cmd/user`
  command line) are passed verbatim as WASI argv. The program name is **not**
  prepended, so the first real argument is at index 0 (`os.Args[0]` in Go,
  `std::env::args().next()` in Rust, `argv[0]` in C). The samples read their
  target from `-addr <host:port>`.
- **No filesystem** is mounted, and there is no network syscall layer. All I/O
  beyond stdout goes through the host functions below.

## The host API

Networking is provided by host functions imported from the wazero `env` module.
Every address and buffer is passed by `(pointer, length)`: the guest writes bytes
into its own linear memory and hands the host a 32-bit offset plus a length. The
SDKs do this pointer math for you.

Registered functions (see
`internal/executor/debuglet/debuglet.go` and `.../wasm/host_functions.go`):

| Group   | Functions                                                                                                                                                                               |
| ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP/TLS | `connect_tcp`, `connect_tls`, `accept_tcp`, `send_tcp_data`, `receive_tcp_data`, `close_tcp`                                                                                            |
| ICMPv4  | `connect_icmp4`, `send_icmp4_data`, `receive_icmp4_data`, `close_icmp4`                                                                                                 |
| SCION   | `send_scion_udp_packet`, `receive_scion_server_udp_packet`, `answer_scion_udp_packet`, `scion_available_paths`, `scion_path_length`, `scion_get_interface_details`, `scion_select_path` |

## Building a sample

`make wasm` detects the language from the entrypoint file in `SAMPLE_DIR` and
writes `debuglet.wasm` into that directory:

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/ping
make wasm SAMPLE_DIR=local/wasm_samples/rust/ping
make wasm SAMPLE_DIR=local/wasm_samples/c/ping     CLANG=/opt/wasi-sdk/bin/clang
make wasm SAMPLE_DIR=local/wasm_samples/javascript/helloworld
```

Toolchain requirements per language:

| Language | Needs                                                                       | Override                                   |
| -------- | --------------------------------------------------------------------------- | ------------------------------------------ |
| Go       | Go (built in)                                                               | —                                          |
| Rust     | `rustup target add wasm32-wasip1`                                           | `CARGO=...`                                |
| C        | a `wasm32-wasi` clang ([wasi-sdk](https://github.com/WebAssembly/wasi-sdk)) | `WASI_SDK=/path` or `CLANG=/path/to/clang` |
| JS       | [`javy`](https://github.com/bytecodealliance/javy)                          | `JAVY=/path/to/javy`                       |

## Running a sample

Submit it through the local user client (the executor and dispatcher must be
running — see the [root README](../../README.md)):

```sh
# ping
go run ./cmd/user  -addr 1.1.1.1 -floor 10000 -ceil 10000 -wasm local/wasm_samples/go/ping/debuglet.wasm -- -addr 1.1.1.1 -iter 5
# send TCP
go run ./cmd/user -addr 1.1.1.1 -floor 10000 -ceil 10000 -wasm local/wasm_samples/go/send_tcp/debuglet.wasm -- -addr 1.1.1.1:80
```

Everything after `--` is forwarded to the debuglet as argv. The `-addr` before are the addresses which are sent along in the policy. View the `./cmd/user/main.go` file for more details about the flags that can be passed along for the policy.

## Limitations worth knowing

- **traceroute is not provided.** A classic incrementing-TTL traceroute needs to
  set the IP TTL per probe, but the host API exposes no socket options (only
  connect/send/receive/close). It cannot be implemented with the current ABI.
  The SCION path family (`scion_get_interface_details` etc.) exposes AS-level
  path hops and is the closest available analog.
- **JavaScript is stdout-only.** Javy bundles QuickJS but provides no way to
  import the custom `env` host functions, so JS debuglets cannot do networking.
- **Python is not currently runnable.** See [python/README.md](python/README.md)
  for the details (no pure-WASI-preview-1, filesystem-free CPython path that
  wazero can run).

## Other samples

Beyond the three starters, the Go and C directories contain extra reference
debuglets (raw-import TCP clients, fidelity/iperf benchmarks, echo servers).
The `*_server` C samples depend on the host TCP listener, which is currently a
placeholder in `startServers`; they are included for API completeness.
