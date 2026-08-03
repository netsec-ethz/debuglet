# JavaScript debuglets

JavaScript debuglets are compiled to WASM with
[Javy](https://github.com/bytecodealliance/javy), which bundles the QuickJS
engine into a self-contained WASI command module. `console.log` is streamed back
to the user as stdout. See the [shared model](../README.md) for the execution
contract.

## Important limitation

Javy guests run **pure JavaScript over QuickJS** and have **no mechanism to
import the executor's custom `env` host functions** (`connect_tcp`,
`connect_icmp4`, …). That means JavaScript debuglets are limited to computation
and stdout — the `ping` and `throughput` measurements are **not available** in
JS. Use Go, Rust, or C for anything that touches the network.

Only `helloworld` ships here for that reason.

## The sample

| Sample       | What it does |
|--------------|--------------|
| `helloworld` | `console.log` a greeting |

## Prerequisites

Install the `javy` CLI (binary releases at
<https://github.com/bytecodealliance/javy/releases>), then make sure `make` can
find it (it's on `PATH`, or pass `JAVY=/path/to/javy`).

## Build & run

```sh
make wasm SAMPLE_DIR=local/wasm_samples/javascript/helloworld JAVY=/path/to/javy
go run ./cmd/user -wasm local/wasm_samples/javascript/helloworld/debuglet.wasm --
```
