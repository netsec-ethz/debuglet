# Threat model and supported scope

Debuglet is an alpha for trusted Linux amd64 environments. The local TEST
profile and deliberately configured trusted deployments are supported; this is
not a general-purpose sandbox for hostile guests or a production payment
system. This reference describes the current code. See [SECURITY.md](../SECURITY.md)
for private vulnerability reporting and the
[operator security guide](https://github.com/netsec-ethz/debuglet/wiki/Security-and-supported-scope)
for operational guidance.

## Actors, assets and data flows

| Actor | Authority and exposure |
| --- | --- |
| Submitter | Uses the HTTP API, CLI or console to submit a module, arguments and policy and to read or cancel their runs. A module's author need not be its submitter. |
| Dispatcher operator | Controls API and control listeners, authentication configuration, enrollment authority and the database containing accounts, ownership, results and TEST bookkeeping. |
| Executor operator | Controls the executor identity and credentials, network policy, listener addresses, SQLite state and the host from which traffic originates. |
| Destination controller | Controls a measured endpoint. A submitted destination does not establish their consent. |
| Observer | May see traffic and public executor and TESLA information. Public identifiers do not grant access to another account's results. |

The submitter sends a module and measurement policy to the dispatcher over HTTP.
The dispatcher assigns it to an executor over a bound control session; executor
host functions mediate guest traffic. State, output and terminal reports return
to the dispatcher. The [architecture](architecture.md) describes the control
paths; [stored state](operations/configuration.md#stored-state) lists retained
assets and their lifetimes. Dispatcher and executor operators can inspect the
plaintext state on their hosts, including credentials and workload data.

## Trust boundaries

### HTTP clients and account ownership

Managed deployments use server-issued sessions, including the configured GitHub
OAuth login. Protected routes require a valid session and enforce object
ownership or an operator role. Cookie-authenticated changes require CSRF proof.
A user UUID alone is not a credential. The [API reference](api.md)
and [OpenAPI contract](../api/openapi.yaml) define the route-level decisions.

The explicit local-development profile allows credential-free local TEST
operations only with its required loopback, TLS-disabled and payment-disabled
configuration. It is not enabled merely because a reverse proxy terminates TLS.
Keep it off in a managed deployment. Authentication does not provide a general
registration, login or workload abuse prevention service; restrict exposure to
the intended users.

### Dispatcher and executor control

Both control paths use the negotiated binding, secret session token and a live
lease. Old bindings cannot acquire a replacement session's authority. Protocol
version `3` describes message and lease semantics; it is not an identity check.
Where `tls.require_client_cert` is enabled, enrollment binds an executor ID to
the presented client certificate, and both paths must establish that identity.
Without that configuration, an ID is self-reported. Networked operators must
configure authenticated TLS on both paths and protect the enrollment authority;
see [connection topology](operations/remote-deployment.md#required-topology).

Account-owned enrollment allows a signed-in account to create and manage its own
executor identities when the dispatcher enables that feature. Setup tokens are
short-lived, single-use secrets; host administrative enrollment remains an
operator action. Enrollment establishes possession of credentials, not trust in
an executor's implementation, reported capabilities, measurements or location.

A dispatcher with a live authorized session chooses the modules and policies
sent to an executor. Executor network policy remains a separate operator limit.
Cancellation and recovery inspection cannot prove that a remote process has
stopped or that a destination no longer receives traffic.

### Guest code and the executor host

WASI guests receive no host filesystem, inherited environment or ordinary
socket access. Host functions mediate network operations through both the
operator policy and the run's policy, checking resolved addresses before
connection and accepting inbound peers.

The trusted profile runs guests inside the executor process. The explicit Linux
shared profile runs compilation and execution in supervised child processes with
cgroup memory, CPU, process and time budgets. The parent retains networking and
durable output; guest-directed copies and socket counts are bounded, but parent
TLS, DNS and other library allocations are outside the child's memory limit.
The [resource-limit reference](operations/guest-isolation.md) describes required
delegation, cleanup and platform constraints. These controls do not establish
containment of a runtime escape or of every parent host-call cost.

### Executor traffic and destination control

The operator's network policy denies disallowed address ranges and ports and
can add addresses or prefixes to `denied_destinations`. `local_targets` is an
explicit exception used by the local fixture. Bandwidth accounting depends on
the selected supported counter mode; kernel attachment and in-process fallback
have different observation limits. Neither a resource reservation nor a traffic
counter proves destination consent.

An operator can change a dispatcher destination limit, but this does not
represent an authenticated opt-out by the destination. To honour an opt-out
request, an operator denies the destination with `PATCH /destination`
(`denied`, `reason`) and checks its delivery with `GET /destinations`; see
[destination limits and opt-outs](operations/configuration.md#destination-limits-and-opt-outs).
Limits, policy changes
and cancellation each have different delivery and persistence guarantees. Follow
the [operator security guide](https://github.com/netsec-ethz/debuglet/wiki/Security-and-supported-scope)
and verify the reported outcome before claiming that traffic has stopped.

### Packet attribution and payment authority

The [tag specification](tag-spec.md) defines `debuglet-tag-v1`, the fields it
covers and the limits of its 16-bit tag. Attribution needs a working tagger, retained evidence and the appropriate
disclosed key. Kernel mode tags marked IPv4 TCP/TLS, UDP and ICMP traffic.
Userspace mode can tag IPv4 UDP/ICMP datagrams when its raw socket is available;
TCP/TLS remains untagged in that mode. Neither mode tags IPv6 or SCION, and
kernel-tagged runs refuse IPv6 destinations. Check the reported tagging mode
and transport rather than treating fallback accounting as attribution. Dispatcher
schema 14 retains announced chains, verified disclosed keys and run intervals
across dispatcher restarts, subject to the configured attribution retention
period. Lookups report the coverage cutoff; missing history is not evidence that
no run existed. Restarting the executor still discards
undisclosed keys; [key-schedule configuration](operations/configuration.md#executor-tesla-key-schedule)
explains the disclosure window. A valid tag does not establish destination
consent, a human identity or non-repudiation.

TEST bookkeeping transfers no money. Blockchain payment authority and settlement
are outside the supported profile. Keep chain payments disabled, including after
restoring or upgrading state with historical paid rows.

## What identifiers and observations do not prove

| Value | What it does not prove |
| --- | --- |
| Session token | The human's identity beyond the login/credential flow, or that the token has not been copied. Protect it as a credential. |
| User UUID, run UUID or displayed version | Authentication, permission to access the object, or peer compatibility. |
| Enrolled executor ID | Physical machine identity, exclusive possession of the key, accurate location or honest execution. |
| Control lease | That a guest is running, has stopped, or has sent or received any packet. |
| Cancellation acknowledgement | Remote termination or reversal of effects already produced. |
| Retained or restored row | That interrupted work completed. Previous bindings are retained for inspection and are not automatically replayed. |
| Result provenance | A record of admitted inputs and reported metadata; not independent proof of execution or network conditions. |

## Conditions before supporting untrusted use

A wider support claim needs evidence for each condition below; current CI and
trusted local demonstrations do not establish it:

- Authentication, ownership, enrollment and TLS configured and tested on every
  exposed boundary, with an explicit abuse and credential-revocation procedure.
- Per-guest resource isolation and control capacity verified for the selected
  deployment, including parent host-call costs outside the shared worker budget.
- Traffic policy enforced across all supported transports, with a durable,
  authenticated destination opt-out and an observed response to abuse reports.
- Versioned attribution with retained verification history and accurately stated
  timing, clock and cryptographic limits.
- Payments disabled, or a separately validated and audited payment authority and
  recovery procedure.
- Supported upgrade/restore combinations exercised with populated state and
  documented limits; the threat model, installation guide and release notes
  updated together before extending the support claim.
