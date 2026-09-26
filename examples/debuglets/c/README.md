# C measurements

**Experimental. Not a supported quickstart.** Nothing in this repository builds,
executes or checks these samples, and no C toolchain is part of the pinned
build. The header below is not covered by the guest ABI compatibility suite. Use
the [Go samples](../go/README.md) for supported measurements.

The C samples use a normal `int main(int argc, char **argv)` and compile for
`wasm32-wasi`. The executor records stdout and stderr as job output. See the
[shared guide](../README.md) and the [guest guide](../../../docs/GUESTS.md) for
the imports the header declares.

## Samples and bindings

`helloworld`, `ping`, and `throughput` demonstrate output, ICMPv4, and TCP. Additional latency and iperf-related examples are available for specialized setups; they are not exercised by the installed Go demo.

The header [`common/debuglet_api.h`](common/debuglet_api.h) declares the custom `env` imports:

```c
#include "../common/debuglet_api.h"

int sock = connect_tcp(addr, addr_len);
if (sock >= 0) {
    send_tcp_data(sock, buf, len);
    int n = receive_tcp_data(sock, buf, sizeof buf);
    close_tcp(sock);
}
```

Addresses and buffers use pointers and lengths into guest memory, and one call
transfers at most 8192 bytes: `send_tcp_data` of a larger buffer sends only the
first 8192, and `receive_tcp_data` fills a larger buffer only that far, so both
belong in a loop. A connect that is refused or disallowed by the job's policy
ends the job inside the call rather than returning `-1`.

The header also provides WASI clock helpers and basic argument parsing. The first actual argument is `argv[0]`; no program name is inserted.

Server samples that call `accept_tcp()` require a job requesting a listener and configured executor public-host/port resources. They cannot assume an arbitrary host port is available.

## Build and submit

Use [wasi-sdk](https://github.com/WebAssembly/wasi-sdk), then run from the repository root:

```sh
make wasm SAMPLE_DIR=examples/debuglets/c/helloworld WASI_SDK=/path/to/wasi-sdk
dbl run --wasm examples/debuglets/c/helloworld/debuglet.wasm \
  --executor EXECUTOR_ID --wait
```

Alternatively set `CLANG=/path/to/wasi-sdk/bin/clang`. Replace the executor ID with a node from `dbl nodes`. Network examples additionally need an allowed target and appropriate executor capabilities; compilation alone does not validate those conditions.
