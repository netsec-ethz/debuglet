# Recoverable socket extension

`debuglet_io_v1` is an optional host module alongside the unchanged `env`
imports of `debuglet-go-wasi-imports-v1`. The Go guest SDK's `Dial`,
`DialTimeout` and `Socket` use this module. The legacy `Conn` API and compiled
guests retain their original signatures and failure behavior. An older host
cannot link a guest that imports this module.

Every result is an `i64`: the low 32 bits hold a byte count or handle and the
high 32 bits hold a status. A status never invalidates a positive I/O count.
Pointers and buffer lengths are unsigned `i32`; handles are nonnegative `i32`.

| Import | Parameters | Low result |
| --- | --- | --- |
| `dial` | transport, address pointer, address bytes: `i32`; timeout nanoseconds: `i64` | handle on success; ignored on error |
| `read` | handle, buffer pointer, buffer bytes: `i32` | bytes read |
| `write` | handle, buffer pointer, buffer bytes: `i32` | bytes written |
| `close` | handle: `i32` | zero |
| `deadline` | handle, direction: `i32`; Unix nanoseconds: `i64` | zero |

Transports are TCP=0, TLS=1, ICMPv4=2 and UDP=3. Zero dial timeout uses the run's
remaining lifetime; negative means expired. Deadline direction is read=0 or
write=1, with timestamp zero clearing that deadline. The host retains ownership
of each handle through its existing socket registry; closing does not reuse it.

Statuses are success=0, EOF=1, timeout=2, reset/broken-pipe=3, closed=4,
connection-refused=5, policy-denied=6, other-I/O=7, no-progress=8,
short-write=9, canceled=10 and unsupported-operation=11. EOF is meaningful only
for TCP/TLS reads; unexpected datagram EOF is other-I/O. The SDK exposes the
standard `io.EOF`, `io.ErrNoProgress` and `io.ErrShortWrite` values, and typed
`debuglet.IOError` values for other failures. Errors carry no host-provided text.

Each call transfers at most 8192 bytes. A stream read of `(0, nil)` into a
nonempty buffer reports no-progress. A short write without an underlying error
reports short-write. Datagram writes exceeding the bound trap at the raw host
boundary; the SDK rejects them as `ErrTooLarge` before a call. It never splits a
datagram. The SDK processes long stream writes in bounded calls, stopping at
the first error and preserving the aggregate count.

Out-of-bounds guest memory, never-issued handles and invalid transport or
deadline selectors trap. A previously valid closed handle reports closed.
Destination admission, packet attribution, resource accounting and run shutdown
remain in the existing host path. Per-socket deadlines cannot extend a run.
