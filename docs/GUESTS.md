# Guest ABI and Go examples

A debuglet is the WebAssembly program an executor runs for one job. It is an
ordinary WASI preview1 command module: a normal `main` built for
`GOOS=wasip1 GOARCH=wasm`. Standard output and standard error become the job's
output, which the client reads with `dbl logs`.

Networking is not the operating system's. A guest has no sockets and no
filesystem; it calls a small set of host imports that the executor provides,
subject to the job's destination policy and bandwidth limits. The
[guest SDK](../pkg/debuglet) wraps those imports so that guests work with a
`Conn` instead of memory offsets.

This document is the contract between a compiled guest and the host that runs
it, and the list of Go examples that are supported against it.

## Execution model

- Guest arguments are the job's arguments verbatim, with **no program name**
  inserted. In Go, `os.Args[0]` is the first argument the submitter supplied, so
  guests parse flags with `flag.CommandLine.Parse(os.Args)`.
- Output is streamed while the guest runs and stored by the dispatcher. Stored
  output is what the client reads back; it is not an acknowledgement that the
  guest's entire output was captured.
- A job carries an execution budget. When it expires the executor closes the
  runtime, which ends the guest wherever it is, including inside a host call.
- There is no guest filesystem, no environment, and no host clock import. WASI
  supplies monotonic time, wall time and sleep, so `time.Now`, `time.Since` and
  `time.Sleep` behave normally.

## Guest ABI

The guest ABI is the frozen interface between a compiled guest and a host. Its
identifier is recorded in every installation as `guest_abi` in
`share/debuglet/manifest.json`, and the same identifier is compiled into the
installed binaries as part of their build identity.

**Current identifier: `debuglet-go-wasi-imports-v1`.**

A guest compiled against this ABI runs on any host that records this
identifier. A change to any import name, signature, ownership rule or unit
below produces a different identifier, because guests built for the new
interface cannot run on hosts that implement this one.

### Imports

Every import is exported by the host module `env`. All parameters and results
are 32-bit integers. `p`/`len` pairs are an offset into the guest's linear
memory and a length in **bytes**. `sock` is a socket handle.

| Import | Signature | Meaning |
| --- | --- | --- |
| `connect_tcp` | `(addrp, addrLen) -> handle` | Dial TCP to a `host:port` address |
| `connect_tls` | `(addrp, addrLen) -> handle` | Dial TCP and complete a TLS handshake; reads and writes carry plaintext |
| `connect_udp` | `(addrp, addrLen) -> handle` | Open a connected UDP socket to a `host:port` address |
| `connect_icmp4` | `(addrp, addrLen) -> handle` | Open a raw ICMPv4 socket to an IPv4 address without a port |
| `accept_tcp` | `() -> handle` | Accept one inbound connection on the job's TCP listener |
| `get_tcp_addr` | `(bufp, bufLen) -> n` | Write the job's public TCP listener address, or `-1` |
| `get_udp_addr` | `(bufp, bufLen) -> n` | Write the job's public UDP listener address, or `-1` |
| `get_remote_addr` | `(sock, bufp, bufLen) -> n` | Write the peer's `host:port`, or `-1` |
| `receive_tcp_data` | `(sock, bufp, bufLen) -> n` | Read once from a TCP or TLS socket |
| `receive_udp_data` | `(sock, bufp, bufLen) -> n` | Read one datagram from a connected UDP socket |
| `receive_icmp4_data` | `(sock, bufp, bufLen) -> n` | Read one packet from an ICMPv4 socket |
| `receive_udp_from` | `(recvp, recvLen, senderp, senderLen, addrLenp) -> n` | Read one datagram from the job's UDP listener and write the sender's address |
| `send_tcp_data` | `(sock, bufp, bufLen)` | Write to a TCP or TLS socket |
| `send_udp_data` | `(sock, bufp, bufLen)` | Send one datagram on a connected UDP socket |
| `send_icmp4_data` | `(sock, bufp, bufLen)` | Send one ICMPv4 packet |
| `drain_connection` | `(sock)` | Currently a no-op for the accounting-wrapped sockets used by the runtime; does not guarantee delivery |
| `close_tcp` | `(sock)` | Close a TCP, TLS or UDP socket |
| `close_icmp4` | `(sock)` | Close an ICMPv4 socket |

### Memory, handles and units

- **Memory belongs to the guest.** Every pointer is an offset into the guest's
  own linear memory. The host reads or writes it only while the call runs and
  keeps no reference afterwards. The guest must pass a non-empty buffer that
  stays alive for the duration of the call.
- **Handles belong to the host.** A handle is a non-negative index the host
  assigns, starting at 0 and increasing per job. Handles are not reused, and a
  closed handle is invalid. The guest passes handles back unchanged.
- **One call transfers at most 8192 bytes**, whatever the buffer's length is. A
  read into a larger buffer is an ordinary short read. A send of a larger
  buffer transfers only the first 8192 bytes, so guests using the raw imports
  must send in a loop; the SDK's `Conn.Write` does that for streams and refuses
  an oversized datagram with `ErrTooLarge` rather than truncating it.
- **Lengths and counts are bytes.** There are no other units on this interface:
  no import takes or returns a duration, a rate or a timestamp.
- **Addresses are text**, in Go's `host:port` form. The host writes an address
  only when it fits and returns `-1` otherwise, so addresses are never
  truncated. 512 bytes is enough for the addresses the executor produces.
  `receive_udp_from` additionally stores the sender's length as a
  little-endian `uint32` at `addrLenp`.
- **No host call has a deadline.** A read blocks until data arrives, the peer
  closes, or the job's execution budget ends the guest.

### What a guest can reach

Every host import that moves traffic is checked against one network policy
before the packet exists. The policy has two halves and both must admit the
traffic: the **operator policy** the executor is configured with, and the
**job policy** the submitter declared as the run's destination list. Neither
half can widen the other.

The operator half denies, on every transport and whatever the job declared:
this host, private, carrier-grade, link-local, unique-local, multicast and
reserved address ranges, including the addresses that carry an IPv4 address
inside an IPv6 one; loopback, unless the operator configured the local profile, which a deployment that writes no policy has not;
anything the operator listed as denied, by address, range or name; and any
destination port outside the permitted ranges. A destination written as a name
is resolved first and the check is made on the addresses it resolves to, so an
alias reaches exactly what the name it resolves to reaches, and a destination
that moves out of the job's policy stops being reachable with it.

A destination with several addresses keeps all of the admitted ones: the host
tries them in the order the resolver returned them, so a destination whose
first address does not answer is still reached, and every attempt is an address
the policy admitted.

The job half is the declared destination list, resolved again on every call.
Resolutions are reused for a couple of seconds, so a destination that moves
stops being reachable within that window rather than instantly.
Traffic is accounted against the declared destination that admitted it, so a
job that declares a name keeps one bandwidth account for it however the guest
spells it.

Which transports exist at all is the operator's decision:

| Transport | Imports | Supported | Notes |
| --- | --- | --- | --- |
| TCP | `connect_tcp`, `send_tcp_data`, `receive_tcp_data`, `close_tcp` | yes | connect happens only to the checked address |
| TLS | `connect_tls` and the TCP data imports | yes | the certificate is verified against the name the guest asked for; a refused destination is never handshaken with |
| UDP | `connect_udp`, `send_udp_data`, `receive_udp_data` | yes | |
| ICMPv4 | `connect_icmp4`, `send_icmp4_data`, `receive_icmp4_data`, `close_icmp4` | only where permitted | needs the job to request ICMP and the executor process to hold the raw-socket privilege; otherwise the connect call ends the job |
| Inbound TCP | `accept_tcp`, `get_tcp_addr` | yes, with a listener | a peer outside the policy is closed without reaching the guest and `accept_tcp` waits for the next one |
| Inbound UDP | `receive_udp_from`, `get_udp_addr` | yes, with a listener | a datagram from a sender outside the policy is dropped and never written into the guest's buffer |
| SCION | the SCION-UDP imports | no | off in the supported profile; the imports stay registered and end the job when called |

Outbound, a refused destination receives nothing: the refusal happens before
the socket is connected, so there is no connection, no TLS handshake and no
datagram. The refusal reaches the guest as a trap, like any other host-call
failure.

Inbound is the other way round: the peer reached the executor on its own. A
refused TCP peer has already completed the handshake with the host, and is
closed immediately without the guest ever seeing it; a refused datagram has
already arrived, and is dropped without being written into the guest's buffer.
Neither ends the job: `accept_tcp` goes on waiting for a peer the policy
admits, and `receive_udp_from` goes on waiting for a datagram from one.

### How failures reach the guest

There are three outcomes, and only the first two are values:

1. **End of stream.** `receive_tcp_data` returns `0` for a TCP or TLS socket
   whose peer closed cleanly. The SDK turns this into `io.EOF`, so `io.ReadAll`
   and similar helpers terminate. `0` from a UDP or ICMP read is an empty
   datagram, never an end of stream.
2. **`-1`.** The listener and peer address imports return `-1` when no address
   is available or the buffer is too small.
3. **A trap, which ends the job.** Everything else - a refused connection, a
   destination outside the job's policy, a failed TLS handshake, a socket error
   other than a clean end of stream, an invalid handle, an invalid buffer -
   aborts the guest inside the host call. The job fails and keeps the output
   the guest had already produced, which is why the examples print what they
   are about to do before they do it.

A guest cannot catch the third kind. Recovering from a refused destination in
the guest is not possible; submit the job with a policy that permits the
destinations it needs.

## Compatibility matrix

| Item | Supported value |
| --- | --- |
| Guest ABI identifier | `debuglet-go-wasi-imports-v1` |
| Guest toolchain | Go 1.25.11, the version this repository pins, with `CGO_ENABLED=0` |
| Guest target | `GOOS=wasip1 GOARCH=wasm`: a `wasi_snapshot_preview1` core module with a `_start` export |
| Host runtime | wazero, `wasi_snapshot_preview1`, one module instance per job |
| Guest imports | exactly the 18 functions above, from the module `env`. A host may export more, and this ABI's guests import none of them |
| Supported hosts | every installation whose `share/debuglet/manifest.json` records `guest_abi` equal to the identifier the guest was built against |
| Transfer bound | 8192 bytes per host call |
| Guest languages | Go, through `pkg/debuglet`. The Rust and C bindings target the same imports but are experimental and not covered by the gate below |

Because an installation records its identifier, the ABI of a host can be read
from `share/debuglet/manifest.json` without running anything. `dbl` verifies the
installation it belongs to and rejects a manifest whose recorded identifier is
not the one the binary was built with.

## The compatibility gate

`pkg/debuglet` carries a frozen guest for each published ABI. It declares the
imports itself instead of calling the SDK, so it keeps importing exactly what
guests published under that ABI import, whatever the SDK does later. The suite:

- compares the frozen guest's imports, and the current SDK's imports, against
  the frozen table for this ABI, so an added, removed, renamed or retyped
  import fails and needs a new identifier;
- executes the frozen guest on the current engine and its real host imports,
  against loopback peers the test owns, covering connect, send, receive, end of
  stream, a blocked read ended by the execution budget, connected UDP, the TCP
  and UDP listeners, a destination outside the policy, a refused connection, a
  failed TLS handshake, and the transfer bound;
- checks the guests shipped in an installation against the same table.

`scripts/ci-compatibility.sh` runs the gate against the candidate installation
it has just verified, so a candidate that changes the ABI without changing its
identifier does not pass.

## Supported Go examples

The examples live in [`examples/debuglets/go`](../examples/debuglets/go). Build
one with `make wasm SAMPLE_DIR=examples/debuglets/go/<name>`, which writes
`debuglet.wasm` next to its source.

Each supported example compiles with the pinned toolchain and is executed
against a loopback peer by the example suite in `pkg/debuglet`. "Policy" is what
the job's allowed-destination list must contain.

| Example | Measures | Policy | Output |
| --- | --- | --- | --- |
| `helloworld` | nothing; output only | none | `Hello from Debuglet! (Go)` |
| `hello-local` | nothing; echoes its arguments | none | the greeting, then one line per argument |
| `demo` | the `dbl demo` nonce exchange over TCP | the target's address | `DEBUGLET_DEMO_OK <nonce>` |
| `latency` | TCP round-trip time, one connection per sample | the target's address | `rtt seq=… bytes=… ms=…` per sample, then `summary samples=…` |
| `http_get` | one plaintext HTTP response | the server's address | `status=…`, `header_bytes=… body_bytes=…`, `elapsed_ms=…` |
| `dns` | a DNS A lookup over UDP | the resolver's address | `answer a=… ttl=…` per record, then `answers=…` |
| `throughput` | how much a TCP sender delivers in a fixed time | the sink's address | `[+] sent … in … (…/s)` |
| `listen_tcp` | inbound TCP; echoes one chunk per client | the peers it accepts | `listening on host:port`, then `received seq=… bytes=…` |
| `listen_udp` | inbound UDP; reports datagrams and senders | the senders it accepts | `listening on host:port`, then `received seq=… bytes=… from=…` |
| `send_udp` | UDP output only, no reply | the destination's address | `sent=… bytes=… to=…` |
| `loop` | nothing; occupies the processor until the budget ends it | none | nothing unless `-print` is given |

Notes and limits:

- `latency` measures connect, send and first reply together, over the executor's
  socket path. It is application-level timing, not a kernel or link measurement.
- `throughput` reports what the guest handed to the host in the time it ran. It
  is not an iperf client and it does not establish link capacity or verify
  bandwidth enforcement.
- `dns` builds and parses the message itself and reads A records only. A UDP
  read has no deadline, so a lost reply keeps the guest waiting until the job's
  budget ends it.
- `http_get` speaks enough HTTP/1.0 to read one response with
  `Connection: close`. For HTTPS, `ConnectTLS` needs a target whose certificate
  the executor's system roots trust; a failed handshake ends the job.
- `listen_tcp` and `listen_udp` need a job that requests a listener and an
  executor configured with a public host and port range. Their job policy is
  what admits the peers: a connection or datagram from anywhere else never
  reaches the guest. `listen_udp` only reports what it receives; it sends
  nothing back. `dbl run` does not
  expose that request: submit them with the Go client SDK (`client.Policy`'s
  `ListenTCP` or `ListenUDP`) or through the dispatcher API.
- `loop` is the readable demonstration of the execution budget: the job ends
  with a timeout and keeps whatever the guest had printed.
- A destination the job's policy does not allow, and one that refuses the
  connection, both end the job inside the connect call. `latency` shows it: the
  output stops after its `target=…` line, with no `rtt` line and no summary.
  The example suite covers both, along with the end of stream that `http_get`,
  `demo` and `latency` depend on.

## Reference examples

These are published for reading rather than as quickstarts. They compile with
the pinned toolchain, and the suite keeps them compiling, but they need
privileges or a destination the tests cannot own, so they have no execution
test:

- `ping` measures ICMPv4 echo latency. It needs a job that requests ICMP and an
  executor process that can open raw sockets; elsewhere the connect call ends
  the job.
- `send_tcp` and `download` call the host imports directly instead of using the
  SDK. They show the pointer-and-length convention this document describes.
  `download` additionally needs an HTTP target to download from.

## Other languages

Go is the supported guest language. The [Rust](../examples/debuglets/rust) and
[C](../examples/debuglets/c) directories are experimental: they are not built or
executed by this repository's gate, their bindings are not covered by the
compatibility suite, and a successful build of one of them establishes nothing
about its behaviour on an executor.

## Limits

- One ABI identifier is published: `debuglet-go-wasi-imports-v1`. There is no
  translation layer between identifiers; a host runs the guests of its own ABI.
- The gate proves that a guest built against the frozen interface still runs on
  the current host. It does not prove that any particular older installation is
  still available for a side-by-side run.
- SCION imports exist in the executor but are not part of this ABI, are not
  wrapped by the Go SDK, and are not covered here.
- ICMP, TLS to a public target, and listeners all depend on executor
  configuration and privileges that a plain local installation does not have.
- The four ICMPv4 imports are frozen by the table and by the guests' import
  surface, but the gate does not execute them: raw sockets are unavailable where
  it runs. `connect_tls` is executed only on its failure path, against a
  plaintext peer, because a local target with a certificate the executor trusts
  is not part of the gate.
- `Conn.Write` used to hand a buffer larger than the transfer bound to a single
  host call, which delivered its first 8192 bytes and dropped the rest. It now
  transmits all of it. A guest that wrote such buffers therefore sends more
  bytes than before, through the job's rate limiter, and a job whose budget was
  sized around the truncated behaviour can now reach that budget instead.
