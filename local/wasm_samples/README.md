# WASM measurements

A debuglet is a WASI preview1 command module that runs on an executor. These
samples show how to produce output and use the executor's network API.

| Language | Guide | Support in this repository |
| --- | --- | --- |
| Go | [Go samples](go/README.md) | Supported: the guest SDK, and the examples the compatibility and example suites build and run |
| Rust | [Rust samples](rust/README.md) | Experimental: bindings and samples, not built or run by this repository's checks |
| C | [C samples](c/README.md) | Experimental: host bindings and samples, not built or run by this repository's checks |
| JavaScript | [JavaScript sample](javascript/README.md) | Experimental: output only, no network bindings |
| Python | [Python note](python/README.md) | Unsupported: no build path produces a runnable guest |

Only the Go set is a quickstart. An experimental sample may compile and still
behave differently from what its README describes, because nothing in this
repository executes it. The guest ABI, the compatibility matrix and the
supported example list are in the [guest guide](../../docs/GUESTS.md).

## Execution model

The executor uses wazero to run `wasi_snapshot_preview1` modules. Write an
ordinary `main`/`_start` entrypoint. Stdout and stderr become job output; the
client reads the stored output through `dbl logs`.

Arguments after `--` in `dbl run` become WASI argv directly, with **no program
name** prepended. The first argument is `os.Args[0]` in Go, the first item from
`std::env::args()` in Rust, or `argv[0]` in C. Many samples take
`-addr HOST:PORT`.

No guest filesystem is mounted. Networking uses custom imports from the `env`
module; the language bindings pass addresses and buffers through WASM linear
memory. Use the guest SDK rather than ordinary operating-system socket calls.
One host call transfers at most 8192 bytes, so guests that call the imports
directly must send and receive in a loop.

## Build

Run these from the repository root:

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/helloworld
make wasm SAMPLE_DIR=local/wasm_samples/rust/helloworld
make wasm SAMPLE_DIR=local/wasm_samples/c/helloworld WASI_SDK=/path/to/wasi-sdk
make wasm SAMPLE_DIR=local/wasm_samples/javascript/helloworld JAVY=/path/to/javy
```

Each command writes `debuglet.wasm` into the sample directory. Go uses the
pinned repository toolchain. Rust requires the `wasm32-wasip1` target; C
requires wasi-sdk; JavaScript requires Javy. Compilation of an experimental
sample does not establish runtime compatibility.

## Submit

Use a dispatcher and executor you already configured, then choose an executor ID
from `dbl nodes`:

```sh
dbl --endpoint http://127.0.0.1:9000 nodes
dbl --endpoint http://127.0.0.1:9000 run \
  --wasm local/wasm_samples/go/helloworld/debuglet.wasm \
  --executor EXECUTOR_ID --wait
```

Replace `EXECUTOR_ID` with the chosen node. For a network guest, add the
destination to `--allow` and provide its target argument after `--`. A
destination that is missing from `--allow` ends the job at the connect call.
ICMP, public listeners, and SCION need additional executor configuration. Only
use targets you are authorized to measure.

For an automatic local walkthrough, use `dbl demo` from the complete installed
package. See the [main README](../../README.md) and [CLI guide](../../docs/CLI.md).

## Limits

The Go SDK supports short TCP reads and normal EOF. Output delivery is not
durable acknowledgement of the guest's entire output. A refused or disallowed
destination ends the job rather than returning an error the guest can handle.
JavaScript networking and Python execution are not provided. The host API does
not expose per-packet TTL controls for a conventional traceroute.
