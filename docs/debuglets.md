# Write a debuglet

A **debuglet** is the small WebAssembly program an executor runs for one measurement. Debuglets are WASI Preview 1 command modules. Their output becomes the measurement output that a client reads with `dbl logs` or the API.

## Start from an example

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/hello-local
dbl run --wasm examples/debuglets/go/hello-local/debuglet.wasm --wait
```

The [examples](../examples/debuglets) show supported patterns. Build Go debuglets for `GOOS=wasip1 GOARCH=wasm` and import `github.com/netsec-ethz/debuglet/pkg/debuglet` when you need Debuglet network operations.

## Runtime model

A debuglet has no host filesystem or ordinary host sockets. The executor provides the network operations allowed by the submitted and operator policies. It enforces the job's time and bandwidth budgets. Legacy `Connect*` calls end the debuglet on host failures. The recoverable socket API below lets a diagnostic handle transport failures and continue within the same budgets.

The stable host ABI is `debuglet-go-wasi-imports-v1`. The Go package hides its low-level imports behind familiar connection types. Use the package API and examples rather than binding the ABI directly.

## Handle network failures

Use `Dial` or `DialTimeout` when the diagnostic needs to recover from a timeout,
reset or refused connection. They return a `Socket` implementing
`io.ReadWriteCloser`; its `Write` returns `(n, err)`. Existing `Connect*` functions
return the original `Conn` and keep their existing behavior.

```go
s, err := debuglet.DialTimeout("tcp", "example.com:80", time.Second)
if err != nil {
    fmt.Println("connect:", err)
    return
}
defer s.Close()
if err := s.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
    fmt.Println("deadline:", err)
    return
}
n, err := s.Read(buf)
consume(buf[:n]) // Always process bytes before the accompanying error.
switch {
case errors.Is(err, debuglet.ErrTimeout):
    fmt.Println("no response before the deadline")
case errors.Is(err, debuglet.ErrReset):
    fmt.Println("peer reset the connection")
case err != nil && !errors.Is(err, io.EOF):
    fmt.Println("read:", err)
}
```

Networks are `tcp`, `tls`, `udp` and `ip4:icmp`, subject to the same destination,
transport and bandwidth policies as the legacy calls. `ErrTimeout`, `ErrReset`,
`ErrClosed`, `ErrRefused` and `ErrDenied` are distinguishable with `errors.Is`.
No arbitrary host error text or filesystem paths cross this interface.

Reads can return bytes **and** an error together, including `io.EOF`. Empty UDP
or ICMP datagrams return `(0, nil)`. Writes retain their partial count on failure
and never retry automatically; oversized datagrams return `ErrTooLarge` without
sending. A zero deadline clears that socket deadline, without extending the
run's lifetime. Invalid guest memory and never-issued handles still trap.

## Compatibility

Build and test debuglets against the Debuglet release you plan to use. The executor records the debuglet ABI in its installation manifest. A debuglet must target an ABI the executor supports.

Recoverable sockets require the optional `debuglet_io_v1` host module. A host
without it rejects the guest at linking, naming the missing module. Existing
ABI-v1 guests remain supported without recompilation. The baseline ABI label
alone does not advertise this extension; use a release that includes it. The
[extension contract](development/guest-io.md) records its wire signatures.

Coordinated guests using `Ready` require the optional
`debuglet_experiment_v1.ready` extension on the executor and matching dispatcher
support. See [coordinated measurements](measurements.md#coordinate-a-batch-of-debuglets)
and its five-executor example. Existing guests do not acquire this requirement.

### Other languages

Any WebAssembly module that targets `wasm32-wasip1` and imports only the
functions of the ABI runs on the executor; the Go SDK is the only supported way
to produce one. The Rust bindings (`examples/debuglets/rust/debuglet`) and the
C header (`examples/debuglets/c/common/debuglet_api.h`) are experimental. They
declare the TCP, TLS, listener and ICMPv4 imports with the frozen signatures,
but not UDP, the address getters, `drain_connection` or `debuglet_io_v1`. One
retained guest per language runs on the engine in the test suite. Python and
JavaScript guests are not currently supported (their samples were removed in
0.2.0); [Guest languages](development/guest-languages.md) records what was
measured and why.
