# Go measurements

Build a normal Go `package main` for `GOOS=wasip1 GOARCH=wasm`. Use the
[guest SDK](../../../pkg/debuglet) for network I/O and standard output for
results. That package is the guest side; the native HTTP client in
[`pkg/client`](../../../pkg/client) is the submitter's side.

The guest ABI these samples are built against, its memory and unit rules, and
the compatibility matrix are in the [guest guide](../../../docs/GUESTS.md).

## Supported examples

Each of these compiles with the pinned toolchain and is executed against a
loopback peer by the example suite in `pkg/debuglet`. "Policy" is what the
job's allowed-destination list must contain.

| Directory | Measures | Policy | Typical arguments |
| --- | --- | --- | --- |
| `helloworld` | nothing; output only | none | none |
| `hello-local` | nothing; echoes its arguments | none | anything |
| `demo` | the `dbl demo` nonce exchange | the target | `HOST:PORT NONCE` |
| `latency` | TCP round-trip time | the target | `-addr HOST:PORT -count 3` |
| `http_get` | one plaintext HTTP response | the server | `-addr HOST:PORT -path /` |
| `dns` | a DNS A lookup over UDP | the resolver | `-addr HOST:53 -name example.org` |
| `throughput` | TCP bytes delivered in a fixed time | the sink | `-addr HOST:PORT -secs 5 -chunk 4096` |
| `listen_tcp` | inbound TCP, echoing one chunk per client | none inbound | `-count 1` |
| `listen_udp` | inbound UDP datagrams and their senders | none inbound | `-count 1` |
| `send_udp` | UDP output only, no reply | the destination | `-addr HOST:PORT -count 5` |
| `loop` | nothing; runs until the execution budget ends it | none | `-print -every 1000000` |

`ping` (ICMPv4 latency), `send_tcp` and `download` are reference samples: they
keep compiling, but they need raw-socket privileges or a destination outside a
local setup, so they are not quickstarts. Each says so in its own header.

## Guest SDK

```go
package main

import (
    "fmt"
    "io"

    "github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func main() {
    conn, err := debuglet.ConnectTCP("127.0.0.1:8080")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer conn.Close()
    if err := conn.Write([]byte("hello\n")); err != nil {
        fmt.Println(err)
        return
    }
    reply, err := io.ReadAll(conn)
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Print(string(reply))
}
```

This expects a local TCP peer that reads the request, replies and closes the
connection, and a submitted policy whose address list contains `127.0.0.1`.

`ConnectTCP`, `ConnectTLS`, `ConnectICMP4`, `ConnectUDP` and `AcceptTCP` return
`*Conn`. `Read` follows `io.Reader`: a short read is normal and a clean TCP or
TLS end of stream is `io.EOF`. `Write([]byte) error` has one return value and is
**not** an `io.Writer`. `Close() error` releases the guest's socket. Listener
operations need the executor's public-host and port configuration and a job
policy that requests a listener.

Native builds compile against stubs that panic, so SDK calls only work inside a
guest.

### What the SDK does not turn into an error

Only a clean end of stream reaches the guest as an error. A refused connection,
a destination outside the job's policy, a failed TLS handshake and a socket
error all end the job inside the host call: the guest stops there and the job
keeps the output it had already printed. The samples print what they are about
to do before they do it, so their output shows how far they got.

One host call transfers at most 8192 bytes. `Read` fills a larger buffer only
that far, which is an ordinary short read. `Write` splits a longer stream
payload across calls, and refuses a longer datagram with `ErrTooLarge` rather
than sending a truncated one.

## Arguments

The executor does not prepend a program name, so guest flags are parsed from
`os.Args` as they are:

```go
flag.CommandLine.Parse(os.Args)
```

## Build and submit

From the repository root:

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/latency
dbl run --wasm local/wasm_samples/go/latency/debuglet.wasm \
  --executor EXECUTOR_ID --allow 127.0.0.1 --wait -- -addr 127.0.0.1:8080 -count 3
```

Replace `EXECUTOR_ID` with an ID from `dbl nodes`, and supply `--endpoint`
before the command when the dispatcher is not on the default local port. A
destination that is missing from `--allow` ends the job at the connect call.

Only measure targets you are authorized to measure. Every example defaults to a
loopback address except `dns` (`1.1.1.1:53`) and `ping` (`1.1.1.1`), whose
subject is a public resolver. A default reaches nothing on its own: a guest only
connects to a destination the submitted policy allows, so those two need an
explicit `--allow 1.1.1.1` from someone entitled to probe it.

See the [shared guide](../README.md) for the execution model, the
[throughput guide](throughput/README.md) for a local network walkthrough and the
[guest guide](../../../docs/GUESTS.md) for the ABI and the compatibility matrix.
