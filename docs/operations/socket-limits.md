# Guest socket limits

The executor applies these finite admission limits in the trusted pilot profile:

| Scope | Limit |
| --- | --- |
| Live connected or accepted sockets per run | 64 |
| Listeners per run | 3, with at most one per transport |
| Connection attempts per run over its lifetime | 4,096 |
| Guest descriptor reservations shared by one executor node | 1,024 |
| Cached or pending SCION destinations per run | 16 |

These are construction defaults, including in local TEST mode. Connections,
listeners and accepted peers reserve capacity before the host creates or accepts
the resource. A successful TCP/TLS reservation costs one descriptor slot;
UDP/ICMP costs two to cover the connected socket and the userspace tagger's raw
socket. The two slots remain reserved even if tagging falls back to an untagged
connection. Listeners cost one slot. Concurrent reservations are counted too.

A failed dial or rejected accepted peer returns its live reservation after
cleanup, but consumes one lifetime attempt. Closing a connection returns live
and node capacity after its close has completed. Repeated close does not return
capacity twice. Handles are never recycled during a run: old handles remain
closed, and the lifetime budget bounds the retained handle table. A run that
has spent its lifetime attempt budget must finish; it cannot reset that budget.
Other runs have independent per-run counters and share only the node limit.
Node reservations belong to the daemon and survive control-session replacement.

Exhaustion fails immediately with the public failure `guest socket quota
exceeded`. Legacy socket imports trap and fail the run; the recoverable
`debuglet_io_v1` dial returns `Denied` with no usable handle. The public terminal
classification uses the quota error identity and does not expose the runtime's
stack trace or connection details. Already-open sockets and control/cleanup
operations remain available. The ordinary execution timeout and cancellation
close blocked I/O through the existing joined cleanup path.

This is accounting for guest socket operations, not a kernel-enforced bound on
all process descriptors, CPU or memory. DNS, control connections, databases and
runtime internals also use descriptors. Operators must provision the process
file limit with headroom beyond these guest reservations and monitor host
capacity. A single run cannot consume all 1,024 guest slots, but many runs can
exhaust the shared guest budget. No capacity guarantee is made for unrelated
processes on the same host.

SCION remains disabled by the supported default network policy. Its registry
now enforces its 16-destination capacity, including pending dials; this does not
establish a descriptor bound for the external SCION stack. Enabling SCION is
outside the supported shared-pilot socket accounting profile. The optional
[shared runtime profile](guest-isolation.md) separately contains compiler and
WASI processes; these socket counters still do not impose kernel limits on the
parent's networking code.
