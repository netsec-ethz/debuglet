# SCION experiments

The visual builder can discover SCION paths, select a path by its stable ID,
exchange a UDP payload, and receive or reply on a SCION listener. Path discovery
runs on the selected executor. A bounded QUIC echo measurement adds reliable,
TLS-authenticated exchange on a selected path. Existing TCP, HTTP and TLS
inspection blocks still use IP; coordinated experiments still use their
existing TCP control channel.

## Prepare a dedicated executor

Use an executor reserved for trusted experiment authors. SCION is not supported
by the shared isolation profile or by dispatcher aggregate egress grants. Do not
disable those protections on a public executor to make a SCION experiment run.
Use a dedicated deployment whose operators have accepted this profile instead.

After normal [executor onboarding](executor-onboarding.md), the relevant executor
configuration is:

```toml
[isolation]
profile = "trusted"

[network.policy]
scion = true
inbound = true # Needed for SCION receive/reply blocks.
```

The host must already have a functioning SCION daemon and local SCION network
configuration. Make `SCION_DAEMON_ADDRESS` available to the executor service,
using an IP and port such as `127.0.0.1:30255`. The executor loads its SCION
environment unless `network.disable_scion_environment` is enabled. Check the
daemon address visible to the service, not only to an interactive shell.

The dedicated dispatcher's `[egress] enabled` setting must be `false` (its
default). A dispatcher with aggregate grants enabled refuses SCION listeners;
the executor refuses SCION on any run carrying an aggregate grant. Existing
grants must retire before changing that dispatcher setting; see
[aggregate egress](aggregate-egress.md).

Trusted isolation does not provide the shared profile's hard process CPU/memory
boundary. SCION traffic is not TESLA-tagged, and an `ebpf` enforcement label does
not establish SCION packet coverage. Normal destination restrictions and
application-payload accounting still apply. See [guest isolation](guest-isolation.md)
and [socket limits](socket-limits.md) before choosing this deployment profile.

## Build and check a measurement

1. Select updated executors that report SCION support and the required host
   functions. A positive report means the local daemon and local address were
   available; it does not prove reachability to another AS.
2. For a paired experiment, have the receiver publish its SCION listener address
   over the experiment's TCP channel. The builder adds the selected peers' SCION
   host IPs to the run destination policy. Keep TCP listener connectivity working
   on both participants for coordination.
3. Discover paths to that address, choose an ID from the returned paths, then
   perform an exchange using that exact ID. Give the receiver a bounded receive
   operation followed by a reply. Discovery alone sends no measurement payload
   to the peer and is not an echo test.
4. Report path ID, hop/interface metadata, response and elapsed time. An empty
   path list, expiry, timeout or unavailable selected path is a measurement
   outcome; do not turn it into zero latency or silently choose another path.

Addresses use `ISD-AS,IP:port`, for example `1-ff00:0:110,192.0.2.4:4000` or
`1-ff00:0:110,[2001:db8::4]:4000`. These are documentation addresses; replace them
with the receiver's actual address. The destination policy is host-IP scoped,
not ISD-AS scoped, and the operator's port and reserved-address rules still
apply. The sender and receiver must each permit the other's SCION host IP.

For the first deployment check, use two controlled SCION-connected executors,
verify a successful reply on the chosen path, and retain the path metadata with
the results. Then repeat with a different discovered path if one exists. A local
daemon test or an executor version check alone is not end-to-end validation.

## Measure a reliable exchange

Use **Start SCION QUIC echo** on the receiving executor. Read its endpoint and
certificate SHA-256 fingerprint from that run's output in your authenticated
console session. Give the responder enough run time to remain available while
you build and start the client; stop it with **Stop SCION QUIC echo**, or let the
run finish. Starting echo claims the run's SCION listener exclusively. Raw
SCION receive/reply operations cannot use it afterward, and it cannot be
restarted in that run.

On the client, discover paths to the endpoint, choose a path ID, and use
**SCION QUIC exchange** with that ID and the expected certificate fingerprint.
The reply must match the request. Report handshake time separately from total
exchange time, and keep failures visible. Each exchange creates a fresh QUIC
connection, so total time includes connection setup; it is not steady-state
throughput or one-way delay.

The fingerprint must come from a trusted source. Copying it from the
authenticated console is one option; accepting an arbitrary fingerprint sent
over the experiment's plaintext TCP channel does not authenticate the peer.
Private keys remain in the executor and are not stored in workflow documents.

This is a small echo protocol over QUIC/TLS, with requests and replies limited
to 4096 bytes. It does not implement TCP or HTTP/3, and it cannot exchange data
with an arbitrary QUIC server. The selected path applies to outbound traffic;
the return path may differ. QUIC handshake packets, acknowledgments and
retransmissions are included in its SCION UDP payload accounting. The dedicated
executor and attribution limitations above still apply.
