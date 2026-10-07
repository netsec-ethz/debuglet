# C debuglets

These examples and the header are experimental. They are maintained with the repository as experimental; there is no separate release or version promise. The `guest-languages` CI job rebuilds them and tests fresh source-package consumers. Use the [Go examples](../go/README.md) for supported development; the Go SDK in [`pkg/debuglet`](../../../pkg/debuglet) is the complete reference for the host interface.

The examples use [`common/debuglet_api.h`](common/debuglet_api.h) to call the executor's WebAssembly imports. Its declarations are part of guest ABI `debuglet-go-wasi-imports-v1` and use exactly the signatures that ABI freezes.

## What is checked

A C guest built on the header is retained in [`pkg/debuglet/testdata/guest_c`](../../../pkg/debuglet/testdata/guest_c), and `TestForeignGuestsOnCurrentHost` runs it on the executor's engine: a TCP read until end of stream, a listener that echoes one message, and a refused connection. The retained module and its source-hash record are deliberately updated when the header changes; CI checks the rebuild.

Tested toolchain: wasi-sdk 25 (`ghcr.io/webassembly/wasi-sdk:wasi-sdk-25` container), target `wasm32-wasip1`.

## Host semantics

- One call transfers at most 8192 bytes (`DEBUGLET_MAX_IO_BYTES`). `receive_*` fills at most that much and `send_*` sends at most that much; `debuglet_send_tcp_all` loops for a longer stream payload.
- `receive_tcp_data` returns the byte count, and 0 at a clean end of stream. No import returns a negative value.
- Errors are not returned as values. A refused, unreachable or disallowed destination, a read or write error, an invalid handle and a buffer outside the module's memory abort the guest inside the host call. The job ends with what the guest printed before.
- `accept_tcp` needs the job's TCP listener capability. The executor reports the listener's address to the submitter.

Not provided by the header: UDP sockets, the address getters (`get_tcp_addr`, `get_udp_addr`, `get_remote_addr`), `drain_connection`, and the recoverable sockets of the optional `debuglet_io_v1` module.

## Build an example

Build with [wasi-sdk](https://github.com/WebAssembly/wasi-sdk):

```sh
make wasm SAMPLE_DIR=examples/debuglets/c/helloworld WASI_SDK=/path/to/wasi-sdk
dbl run --wasm examples/debuglets/c/helloworld/debuglet.wasm --wait
```

Network examples also need an allowed destination and the corresponding executor capability.

## Use the header in your own project

Installation is copying the single header; nothing else is needed. Checked from an empty directory:

```sh
mkdir hello && cd hello
cp /path/to/debuglet/examples/debuglets/c/common/debuglet_api.h .
# main.c: #include "debuglet_api.h"
/path/to/wasi-sdk/bin/clang --target=wasm32-wasip1 -O2 -o debuglet.wasm main.c
```

The header is licensed under the Apache License 2.0, like the rest of the repository.

### Rebuild and consumer validation

From the repository root on Linux amd64, run
`bash scripts/ci-guest-languages.sh`. CI uses the same digest-pinned compilers
to rebuild the retained fixtures, check source/binary hashes and run fresh
package consumers against the current host. Source packages and test results
are written under `.cache/guest-languages/`. These are experimental source
packages; no registry publication or supported release is implied. See
[guest language coverage and limits](../../../docs/development/guest-languages.md).
