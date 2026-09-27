# Configuration reference

This page is the reference for running a dispatcher or executor from a configuration file: the daemon configuration keys, transport security and what each daemon stores. Managed services are described in [Managed services](services.md), deployments in [deploy/README.md](../deploy/README.md), and the installed-package checker in [Local environment checks](environments.md).

## Daemon configuration

`dbl demo`, `dbl up`, `dbl dispatcher up` and `dbl executor up` write the daemon
configuration themselves. This section applies when a dispatcher or executor is
started directly with `--config FILE`.

Each daemon reads one TOML file and checks it completely before it opens a
database, binds a listener or acquires a packet counter. A key the daemon does
not support is an error that names the key, so a misspelled setting fails
instead of silently doing nothing. An omitted key keeps its documented default:
`logging.log_level` is `info`, `server.version` is `unknown`,
`scheduler.executor_timeout` is 60 seconds and `resources.max_debuglets` is 100.
An explicit value is always checked, so `max_debuglets = 0` is an error rather
than a request for the default.

A key that takes a DNS name (`server.bind_host`, the host of `dispatcher.addr`
and `dispatcher.yamux_addr`, `tls.server_name` and `network.public_host`)
follows the RFC 1123 host-name rules: dot-separated labels of 1 to 63 ASCII
letters, digits and hyphens, none starting or ending with a hyphen, at most 253
bytes in total, with one optional trailing dot. An underscore is refused,
because it names DNS records such as SRV owners rather than hosts. The check is
syntax only and performs no lookup; [`dbl validate`](CLI.md) applies the same
rule to its `--allow` entries.

The dispatcher requires `database.path`; `server.bind_host` empty, an IP address
or a DNS name; `server.http_port` and `server.grpc_port` between 0 and 65535 and
different from each other unless both are 0, which asks the operating system for
an unused port; a supported `logging.log_level`; `scheduler.executor_timeout`
between 1 and 300 seconds; a `scheduler.scheduler_granularity_ms` that is not
negative and still converts to a duration; and every entry of
`cors.allowed_origins` written as `scheme://host[:port]` without a path. A `*`
entry is rejected: a wildcard cannot carry cookie credentials, and an empty list
already leaves credential-free wildcard CORS in place. Unless `tls.disable` is
true, `tls.cert_file` and `tls.key_file` must be set, `tls.require_client_cert`
needs `tls.ca_file`, and the dispatcher loads all of them as it starts, before
it opens the database or binds a listener. See [transport
security](#transport-security).

Two `[server]` keys decide how the HTTP API treats credentials.
`server.local_development` asks for the local development profile, in which a
request that presents no credential at all is served as this dispatcher's own
operator. It is an explicit opt-in that the dispatcher checks twice: the
configuration reader refuses it unless `tls.disable` and `sui.disabled` are true
and `server.bind_host` is set to a loopback address, and the daemon refuses to
start if the listeners it actually bound are not on loopback. A dispatcher that
does serve the profile logs a warning naming it at startup. Leave the key out of
any configuration a machine other than its operator can reach; the generated
deployment examples do not set it, and the configuration `dbl demo`, `dbl up`
and `dbl dispatcher up` write for their own loopback environment does.
`server.behind_tls_terminator` states that a TLS terminator such as the bundled
nginx stands in front of the dispatcher, so the session cookie is marked
`Secure` although the daemon itself serves cleartext. It is configuration rather
than a header check because `X-Forwarded-Proto` and its relatives are set by
whoever sent the request.

The operator role is granted on the dispatcher host and nowhere else. With the
daemon stopped, or from the same host while it runs:

```sh
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml -grant-operator <account UUID>
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml -revoke-operator <account UUID>
```

Each opens the configured database through the same schema checks the daemon
applies before serving, changes the role of one existing account, prints what it
changed and exits. An identifier that names no account is reported rather than
created. The change takes effect on that account's next request, so revoking
does not wait for a session to expire. Operator accounts reach the
dispatcher-wide operations (`PATCH /destination`, `GET /user-ids`) and no other
account's runs; see [the access matrix](API.md).

Executor identities are enrolled on the dispatcher host too, and only there:

```sh
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml -enroll-executor <executor ID>
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml -revoke-executor <executor ID>
```

Enrolling prints a token once, valid for 24 hours and usable once; only its
digest is stored, so a lost token is replaced rather than recovered. Write it
into the executor's `credentials.enrollment_token` and start the executor: its
first `Hello` spends the token, and the dispatcher records the SHA-256
fingerprint of the certificate that connection presented. From then on that ID
is admitted only over that certificate, on both control channels, and the key
can be removed from the configuration. Rotation is a new token for the same ID,
presented by the replacement certificate: the old one is refused from then on
and a session still open on it loses its lease at the next renewal. Revoking
deletes the binding with the same effect. Neither ends a session at once: a
node that is already connected keeps the authority of the lease it holds until
that lease expires, which is up to `scheduler.executor_timeout` seconds, and
loses it at the renewal after the change. Revoking an executor that has not
connected yet drops the token it was given, which is reported as such.

Enrollment is enforced only where the dispatcher verifies client certificates
itself — `tls.require_client_cert` with `tls.ca_file` — because there is
otherwise no credential to bind an ID to. Without it the dispatcher logs at
startup that executor identities are unverified, which is the local development
profile. Behind a TLS terminator the dispatcher sees the terminator's
connection and no client certificate, so enrollment belongs in front, with the
requirement itself.

The executor requires `identity.executor_id` and `database.path`; a positive
`resources.capacity`; `dispatcher.addr` and `dispatcher.yamux_addr` written as
`host:port` with a port from 1 to 65535, where `yamux_addr` defaults to `addr`;
`network.packet_counter` omitted or set to `auto` or `fallback`, where omitted
and `auto` both keep interface discovery; a `network.public_host` that is an IP
address or a DNS name and a `network.public_ports` list of ports and ranges; and
TESLA epochs that still convert to a schedule, with `tesla.chain_length` between
0 and 604800 epochs, where 0 derives the length from `tesla.delay`. Unless
`tls.disable` is true, `credentials.client_cert` and `credentials.client_key`
must be set; the executor reads them while it builds its resources, before it
acquires any of them. `tls.disable = true` is accepted only when both dispatcher
endpoints are literal loopback addresses. The default network
interface is discovered only after the rest of the file is accepted.

## Transport security

The dispatcher serves two listeners. `server.http_port` carries the HTTP API and
the executors' reverse control stream behind one protocol multiplexer;
`server.grpc_port` carries the executors' direct gRPC calls. Both present the
same certificate and trust the same authority, so an executor verifies one name
and one root for both of its channels.

### Dispatcher keys

With `tls.disable = false` the dispatcher terminates TLS itself:

- `tls.cert_file` and `tls.key_file` are the server identity. The certificate
  has to carry every name a peer dials — the deployment's DNS name, or
  `127.0.0.1` for a local one — as a subject alternative name.
- `tls.ca_file` is the authority that verifies executor certificates. When it is
  set, a certificate a peer offers must chain to it; a peer that offers none is
  still admitted unless the next key says otherwise.
- `tls.require_client_cert` makes an executor present such a certificate on both
  channels. The direct gRPC listener refuses the handshake without one. The
  reverse control stream is refused after protocol matching instead, because the
  HTTP API shares that port with submitters who hold no certificate and keeps
  answering them.

The shared port is terminated in front of the multiplexer and offers HTTP/1.1
only: the multiplexer routes cleartext framing and cannot hand an HTTP/2
connection negotiated through ALPN to a protocol-aware server. The direct gRPC
listener offers h2, which gRPC requires. Submitters reach the API over ordinary
HTTPS; [`pkg/client`](SDK.md) verifies the chain and follows no redirect.

Startup refuses a certificate or key file it cannot read, a key that does not
match its certificate, a certificate that is expired or not yet valid, an
authority file that holds no PEM certificate, and `require_client_cert` without
`ca_file`. Each failure names the key to correct and the daemon does not start;
nothing falls back to a plaintext or unverified listener.

### Executor keys

With `tls.disable = false` the executor verifies the dispatcher on both channels:

- `credentials.client_cert` and `credentials.client_key` are the identity it
  presents. Both are required whether or not the dispatcher asks for one.
- `credentials.ca_cert` is the authority that verifies the dispatcher. An
  omitted value keeps the host's trust store, which is what a certificate from a
  public authority needs; a named file replaces it, which is what pinning a
  deployment's own authority means.
- `tls.server_name` is the name verified in the dispatcher's certificate. Empty
  verifies the host part of `dispatcher.addr` and `dispatcher.yamux_addr`; set it
  when the executor dials something else, such as a literal address or the name
  of a terminator standing in front.

Unusable material fails node construction naming the key that holds it, before
the executor acquires a packet counter or connects anywhere.

### Plaintext

`tls.disable = true` keeps the cleartext transport of the trusted local profile,
where dispatcher, executor and client run on one machine that one administrator
trusts. The executor accepts it only when `dispatcher.addr` and
`dispatcher.yamux_addr` are literal loopback addresses such as `127.0.0.1` or
`[::1]`; a name is refused even when it would resolve to one, because the
configuration is checked before the daemon looks at the host and what a name
resolves to is a property of the machine rather than of the file. This is the
line [`pkg/client`](SDK.md) already draws for its own cleartext endpoints.
Anywhere else the configuration is refused rather than downgraded, because the
cleartext control transport carries the session token, every uploaded module and
every guest output. A dispatcher with `tls.disable = true` starts on any address
but logs, at startup, which of its listeners are exposed off loopback and what
has to stand in front of them.

### Provisioning

Use one authority for a deployment and keep its key off both daemon hosts. Issue
the dispatcher a server certificate carrying the names its peers dial, and each
executor a client certificate whose extended key usage is client authentication;
a certificate issued for serving is refused as an executor identity. The
executor certificate's name is not the executor ID; what binds the two is the
enrollment above. Install the files where only the daemon's user can read them: the private
keys are as sensitive as the database.

Neither daemon builds a chain it was not given. When the leaf is not signed
directly by the configured root, `tls.cert_file` and `credentials.client_cert`
must hold the leaf followed by every intermediate up to that root, in that
order; `tls.ca_file` and `credentials.ca_cert` hold roots only, and may hold
several, which is what an authority rotation needs. A root outside its own
validity window is refused at startup naming the key that holds it, since no
chain could be built on it.

`deploy/docker/nginx/certs` and the `certs_dir` the Ansible roles copy from hold
this material for those rigs. `make deploy-certs` issues and installs it for a
deployment; see [transport security](../deploy/README.md#transport-security) in
the deployment guide. `make generate-certs` is the separate local-development
target: it writes two self-signed keypairs into `configs/`, a dispatcher server
certificate and an executor client certificate, each carrying `DNS:localhost`
and `IP:127.0.0.1`. The configurations in `configs/` run with TLS disabled and
do not read them.

### Rotation and renewal

Both daemons read their certificate files once, at startup. Replacing a file on
disk changes nothing until the process restarts, so a renewal is: write the new
pair, put it in place, restart the daemon. An executor retries the dispatcher
addresses it was started with, `dispatcher.addr` and `dispatcher.yamux_addr` of
its configuration (the generated `service.toml` for `dbl executor up` and a
managed executor), with a jittered backoff that doubles up to 30 seconds. A
dispatcher renewed on the same addresses is therefore rejoined without any
action and shows up as a reconnect. A dispatcher that comes back on other
addresses is not: the executor has to be brought up again with `dbl executor up
--dispatcher` against the new endpoint, or installed again against it and
restarted.

The control session uses the yamux defaults at both ends, a keepalive every 30
seconds with a 10-second write deadline, and a session that fails its keepalive
ends. These defaults normally detect a partition in roughly 40 seconds; that
is not a strict upper bound. An executor can lose eligibility earlier when its
current lease expires (`scheduler.executor_timeout`, 60 seconds by default,
measured from its last renewal). It rejoins on a new control session at its
first reconnection attempt after the partition heals; the backoff starts each
attempt at most 30 seconds after the previous one ended.

Renew before expiry. A dispatcher whose certificate has expired refuses to start
and reports the validity window; an executor whose dispatcher serves an expired
certificate refuses the connection and keeps retrying, which looks like an
unreachable dispatcher rather than a certificate problem, so the dispatcher's own
startup report is where a rotation is verified.

Rotating the authority needs an overlap, because `tls.ca_file` and
`credentials.ca_cert` accept a bundle: append the new root to every peer's file
and restart, then reissue the leaf certificates against the new root, then
remove the old root from the bundles. Reversing that order refuses every peer
that has not been reissued yet.

### Reverse-proxy termination

The supported alternative is a terminator in front of the dispatcher, with the
dispatcher's own listeners plaintext on a network only the terminator can reach.
`deploy/docker` does this with nginx, which terminates the gRPC port as HTTP/2
and the shared port as a byte stream. A terminator has to:

- present a certificate for the name executors dial, on both ports;
- negotiate `h2` on the port that proxies `server.grpc_port`, since gRPC
  requires it;
- proxy the port that carries `server.http_port` as a byte stream, not as an
  HTTP proxy: the same connection carries the HTTP API and the executors'
  multiplexed control stream;
- verify executor certificates itself when the deployment requires them; the
  dispatcher behind it sees the terminator's connection and no client
  certificate, so `tls.require_client_cert` belongs in front, not behind;
- be the only reachable path to the dispatcher's ports, which is what makes the
  cleartext hop behind it acceptable.

An executor still pins the deployment's authority in `credentials.ca_cert` and
verifies the terminator's name, so the boundary the executor authenticates is
the terminator, not the dispatcher process behind it.

`TestControlTLSReverseProxyBoundary` in `internal/dispatcher/transport/rpc`
exercises that boundary locally with certificates issued in the test: a
terminator in front of both plaintext listeners, an executor that pins the
authority and verifies the terminator's name, and a peer pinning another
authority that is refused. Its terminator splices the two connections byte for
byte, which is what a stream proxy does on the control port. It is not a gRPC
proxy re-originating HTTP/2, so what a terminator does to a proxied gRPC
connection's own framing — and anything a deployment's proxy adds, such as
verifying client certificates itself — is not covered by that test.

`[network.policy]` is the operator's traffic policy for guests. It is checked
together with the destination list a submitter declares for a run: both must
admit a destination, and neither can widen the other. Every key is optional and
keeps its documented default.

`tcp`, `tls`, `udp`, `icmp` and `inbound` switch a transport on or off and
default to true; `scion` defaults to false, because a SCION connection cannot
be held to the policy contract in this profile, and its imports end a job that
calls them. `icmp` is a permission, not a promise: the transport also needs the
job to have requested ICMP and the executor process to hold the raw-socket
privilege, which is what the executor now advertises to the dispatcher instead
of its packet-counter type. `inbound` covers accepted TCP connections and the
datagrams a job's UDP listener receives.

`local_targets` keeps loopback destinations reachable and is false unless the
file says otherwise, so an executor that writes no policy reaches no service
behind its own loopback interface. The local, wallet-free environment does
measure against this machine and sets it: `dbl demo`, `dbl up` and the role
commands write it into the configuration they generate, and
[configs/executor/executor.toml](../configs/executor/executor.toml)
sets it for a daemon started directly with `--config`. The other reserved and
internal ranges — this host, private, carrier-grade, link-local, unique-local,
multicast, the documentation and benchmarking ranges, the 6to4 relay prefix and
reserved space, including their IPv6 spellings — are denied whatever it says.

`denied_destinations` adds operator denials as a comma-separated list of CIDR
blocks, IP addresses and DNS names. A name is matched exactly — `example.org`
does not deny `www.example.org` — and denies both the name itself and the
addresses it currently resolves to; a denied name that stops resolving keeps
denying the name but no longer denies any address, so a destination that must
stay unreachable regardless is better written as an address or a range.
`permitted_ports` limits the destination ports a guest may reach, written as
the same comma-separated ports and ranges as `public_ports`; empty permits
every port. Names are resolved before the check, and the connection is then
made to an address that was checked, so a refused destination receives no
connection, no TLS handshake and no datagram. A name with several addresses
keeps all the admitted ones and they are tried in turn. Resolutions are reused
for a couple of seconds, which bounds what a peer can make the executor ask its
resolver.

Note that `network.public_host` is the address the executor advertises for its
own listeners, not a destination: the policy never applies to it, and the
documentation address the local environment advertises there stays as it is.

An executor that writes no `[network.policy]` table therefore denies the
reserved and internal ranges including loopback, permits every port, and offers
every transport but SCION.

## Stored state

A dispatcher keeps what it records in its database until the operator deletes
the state directory that holds it: run records with their declared
destinations, stored guest output, accounts and their credentials, and payment
rows. The one exception is a session, which is deleted the next time any
session is issued once it has been expired for longer than its 12-hour
lifetime. An executor keeps a run's module bytes, arguments and policy only
while the run is outstanding and deletes them when it ends; a terminal result
stays until the dispatcher acknowledges it, a result the dispatcher refused for
good stays as evidence, and the rows of interrupted work stay until the
directory is deleted, as
[Draining a managed role](services.md#draining-a-managed-role) describes. The state
directory of `dbl up` is `$XDG_STATE_HOME/debuglet` when that variable holds an
absolute path and `~/.local/state/debuglet` otherwise, and the role commands use
`dispatchers/NAME` and `executors/NAME` below it unless `--state-dir` names
another ([CLI.md](CLI.md)). A managed service keeps
`/var/lib/debuglet/<role>s/<name>`, which `dbl service uninstall --purge`
deletes and a plain `uninstall` keeps. The Ansible deployment keeps
`/var/lib/debuglet/dispatcher/dispatcher.db` and
`/var/lib/debuglet/executor-<env>/executor.db` under its default `state_dir`
([deploy/README.md](../deploy/README.md)), and a daemon installed by hand keeps
the database its configuration names in `database.path`. `dbl demo` removes its
temporary state after successful cleanup. If a child cannot finish cleanup, it
retains the directory and reports its path. The product has no retention period,
no export and no route or command that deletes a run, its output or an account; automated
retention is deferred until a deployment with a policy owner exists.

Each daemon serves one SQLite database. This build states which schema versions
it supports and checks the supplied database against them before it serves
requests or restores queued work. A database is refused when it does not exist,
cannot be read, is not a Debuglet database, belongs to the other daemon, records
a schema newer than this build supports, records one older than it supports, or
records a version whose tables and columns are not all present, which is what an
interrupted migration leaves. The report names the file and the action to take:
a database of the wrong daemon asks for a corrected `database.path` rather than
for an upgrade, and an absent one has to be created by applying the packaged
migrations (`make upgrade`) or by starting a local service, which creates its
own state directory.

The check opens the database read-only and leaves its bytes unchanged, so
refused state can still be inspected or restored. A symbolic link is followed,
as SQLite follows it too, and reading a database in WAL mode can still create
the usual `-wal` and `-shm` companions next to it.

Startup never migrates a database. An outdated database is upgraded only by an
explicit step, with its daemon stopped and the file and its `-wal` and `-shm`
companions backed up first: `debuglet-dispatcher -config FILE -upgrade-database`
or `debuglet-executor -config FILE -upgrade-database` applies the packaged
migrations to the configured `database.path`, checks the result as a start
does, prints the schema version it now records and exits. It takes no backup
itself, and it refuses without writing a database that does not exist, cannot be
read, is not a Debuglet database, belongs to the other daemon or records a newer
schema. A deployment runs `deploy/ansible/upgrade-database.yml`, which also takes
the backup; see [deployment setup](../deploy/README.md#upgrading-a-database).
Each migration commits on its own, so a failed one leaves the database at the
last version that completed; a start refuses it as outdated, and running the
upgrade again continues from there. A dispatcher database below schema version
3 and an executor database at version 1 lose their runs and logs when upgraded,
because the third dispatcher migration and the second executor migration
recreate those tables. A dispatcher database at version 1 that holds
transactions cannot be upgraded, because its second migration adds required
columns without a default; the upgrade then stops at version 1. The alternative
to an upgrade is to keep using the version that created a database, or to start
from a new state directory.

The supported upgrade path is wallet-free TEST use. Schema migration 4 preserves
existing earnings balances but gives those rows an empty payout wallet. Executor
re-registration does not fill it in, and both existing and later earnings in the
same row remain unpayable. A successful schema check does not establish that
financial state is usable. For a database with paid activity, preserve the
database and its backup with chain payments disabled. Before enabling payments,
the operator must reconcile the balances, orders and transactions against their
records and verify ownership of each payout wallet; the product supplies no
automatic recovery for this state. Do not replace paid state with an empty
database or infer a historical payout address from a new registration.

Local services create their database on first start and keep it across restarts.

The executor database also records every TESLA chain the executor started: its
generation, anchor, epoch base, epoch length and chain length. The chain is
recorded before the node starts, and a start whose anchor is already recorded
is refused. A configured `tesla.seed` yields a new chain for every start, derived
from the seed and the generation. An upgrade from executor schema 4 keeps its
rows and creates the chain table empty; the next start records its first chain.
