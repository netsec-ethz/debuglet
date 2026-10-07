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

## Destinations denied at runtime

The dispatcher can mark a destination `denied` in the bandwidth snapshot it
sends to an executor. The executor then refuses new connections, datagram
sends and accepted peers for that destination, by the name the dispatcher
gives and by every address a run resolved that name to, with the public
failure `destination refused: denied by the operator network policy`
(`Denied` for a recoverable `debuglet_io_v1` dial). It also closes, for every
run, the connected and accepted sockets whose peer is such an address. A
guest using the recoverable `debuglet_io_v1` imports observes a closed socket
(`Closed`), as for a lost connection, and continues with its other sockets. A
guest blocked in a legacy socket import fails as it does when a connection is
lost, with the generic public failure. The executor logs one `Destination
revoked: active sockets closed` line per affected run with the run ID and the
number of sockets closed. A connection that was being made while the denial
arrived is checked again when it is registered and is closed instead of being
handed to the guest (a recoverable dial reports `Closed`; an accepted peer is
skipped).

A version-2 acknowledgement confirms that admission is refused and the
active sockets have closed. If delivery fails or the executor cannot confirm
revocation, the dispatcher retires that exact control session within the
five-second delivery deadline. It cannot renew its lease through successful
health probes. Remote cleanup may take the remaining negotiated lease
duration; retirement itself is not a remote acknowledgement.
Connections closed this way do not resume when a later snapshot allows the
destination again; the guest has to connect anew. Traffic sent or received
before the close is not charged back. Limits of this mechanism: SCION
connections and the run's listeners themselves are not closed (an inbound
peer of a denied destination is refused per connection and per datagram); a
denied name is matched to the addresses the run itself resolved it to; and an
executor denial set belongs to its control session. The dispatcher retains
the policy durably, refuses new denied work after reconnect, and includes
denials in every full allocation snapshot.

SCION remains disabled by the supported default network policy. Its registry
now enforces its 16-destination capacity, including pending dials; this does not
establish a descriptor bound for the external SCION stack. Enabling SCION is
outside the supported shared-pilot socket accounting profile. The optional
[shared runtime profile](guest-isolation.md) separately contains compiler and
WASI processes; these socket counters still do not impose kernel limits on the
parent's networking code.
