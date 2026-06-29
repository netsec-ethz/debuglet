# Go debuglets

Write a debuglet in Go as a normal `package main` with a `func main()`, build it
for `GOOS=wasip1 GOARCH=wasm`, and the executor streams your stdout back to the
user. See the [shared model](../README.md) for the execution contract.

## Samples

| Sample        | Transport | What it does |
|---------------|-----------|--------------|
| `helloworld`  | —         | prints a greeting |
| `ping`        | ICMPv4    | echo-request latency probe |
| `throughput`  | TCP       | sends for N seconds, reports Mbps |

Extra reference samples (`download`, `send_tcp`) show the raw `//go:wasmimport`
interface without the SDK.

## The Go SDK (`pkg/debuglet`)

Import `debuglet/pkg/debuglet` instead of hand-writing `//go:wasmimport`
declarations and `unsafe` pointer math:

```go
package main

import (
	"fmt"
	"debuglet/pkg/debuglet"
)

func main() {
	conn, err := debuglet.ConnectTCP("example.com:80")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	conn.Send([]byte("GET / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 4096)
	n, _ := conn.Receive(buf)
	fmt.Print(string(buf[:n]))
}
```

API surface:

- `ConnectTCP(addr)`, `ConnectTLS(addr)`, `ConnectICMP4(addr)`, `AcceptTCP()`
  → `(*Conn, error)`
- `(*Conn).Send([]byte) error`
- `(*Conn).Receive([]byte) (int, error)`
- `(*Conn).Close() error`

The package builds to a panicking stub off-target so the rest of the module
still compiles and tests on the host; the real host imports are only linked when
you build with `GOOS=wasip1`.

## Reading arguments

WASI argv has no program name, so parse `os.Args` directly:

```go
flag.CommandLine.Parse(os.Args)
```

## Build & run

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/ping
go run ./cmd/user -wasm local/wasm_samples/go/ping/debuglet.wasm -- -addr 1.1.1.1 -iter 5
```
