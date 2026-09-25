# Local environment checks

The compatibility checker runs an installed Debuglet package on Linux with a temporary dispatcher, executor, loopback TCP target, and `/api` proxy. It verifies the package identity, one TEST submission, guest output, terminal state, and cleanup. It has no remote-deployment mode.

## Manifest

Start with [local/configs/canary.json](../local/configs/canary.json). Set a canonical nonzero lowercase executor UUID and an operator label of 1–64 ASCII letters, digits, spaces, underscores, dots, or hyphens, beginning with a letter or digit.

Every illustrated key is required. Leave the API/control addresses and deployment record empty: the checker allocates its own listeners and reads daemon readiness records. The environment is `local`, target host is `127.0.0.1`, and control protection is `owned-loopback`.

The manifest must be a regular file of at most 64 KiB. Symlinks and nonregular files are rejected, as are duplicate, unknown, aliased, null, or missing fields, trailing JSON, and invalid UTF-8. Durations are integer milliseconds: execution is 1–15,000; the attempt is at most 180,000 and exceeds execution by at least 20,000. Ceiling bandwidth is 64,000–1,000,000 bits per second. Manifest fields do not accept credentials or daemon arguments.

## Run the checker

Install a checksum-verified package first; see [installation](../README-install.md). From the matching source checkout:

```sh
mkdir -p .ci .cache
go build -mod=readonly -o .ci/local-compatibility ./internal/acceptance/canary
.ci/local-compatibility \
  -manifest local/configs/canary.json \
  -installed-root "$HOME/.local/lib/debuglet/VERSION" \
  -archive-sha256 ARCHIVE_SHA256 \
  -evidence-dir "$PWD/.cache/local-check-result" \
  -dry-run
```

Replace `VERSION` and `ARCHIVE_SHA256` with the version and lowercase SHA-256 from the matching verified archive. The archive digest cannot be reconstructed from installed files. The checker separately verifies the installed payload hashes and metadata. The evidence directory must not already exist; its parent must exist.

Dry-run validates local inputs and prints JSON without starting services or creating evidence/state directories. After reviewing it, omit `-dry-run` to perform the local check. Use a new evidence directory for each run.

The checker writes `result.json` as a mode 0600 file in its private mode 0700 directory after execution and cleanup, and emits the same JSON. It never overwrites a result. Unobserved facts remain null; an uncertain submission is not retried. Recorded registry ineligibility after shutdown can result from disconnection and does not by itself prove lease expiration.

Exit codes: 0 for valid dry-run or complete success, 2 for invalid input, 1 for operational failure, 124 for deadline, and 130 for interruption.

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
this material for those rigs; `make deploy-certs` and `make generate-certs`, described
under [Deployment](#deployment), issue it.

### Rotation and renewal

Both daemons read their certificate files once, at startup. Replacing a file on
disk changes nothing until the process restarts, so a renewal is: write the new
pair, put it in place, restart the daemon. An executor reconnects on its own
after the dispatcher restarts, with the backoff it already applies to a lost
control session, so a dispatcher renewal shows up as a reconnect rather than as
an outage that needs a fleet action.

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
[local/configs/executor/executor.toml](../local/configs/executor/executor.toml)
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

Startup never migrates a database. Automatic upgrades are not supported: keep
using the version that created a database, or start from a new state directory.
Local services create their database on first start and keep it across restarts.

## Managed services

`dbl service install --role dispatcher|executor` installs one verified role as a
service the host's service manager supervises. It is opt-in and sits beside the
unprivileged foreground commands, which are unchanged. It needs administrator
privileges and an existing unprivileged account; it never creates, changes or
removes one. The reference units are in [deploy/systemd](../deploy/systemd), and
the generator produces them byte for byte.

| | |
| --- | --- |
| Unit | `debuglet-dispatcher-<name>.service`, `debuglet-executor-<name>.service` |
| Account | `debuglet:debuglet` by default, existing, unprivileged |
| Payload | `<prefix>/lib/debuglet/<version>/bin/debuglet-{dispatcher,executor}`, system prefix |
| Persistent state | `/var/lib/debuglet/<role>s/<name>`, mode 0700, owned by the account |
| Administration | `/etc/debuglet/services/<role>-<name>.json` and `.maintenance`, mode 0644, owned by root |
| Runtime state | `/run/debuglet/<role>s/<name>`, created and removed by the manager |
| Readiness signal | `/run/debuglet/<role>s/<name>/ready.json`, written by the daemon |
| Shutdown budget | `TimeoutStopSec=45`, SIGTERM to the daemon alone |

The persistent directory holds only what the daemon itself serves: the role's
SQLite database, its `role-state.json` identity and the generated `service.toml`.
The installing administrator creates the directory, bootstraps the database and
hands the whole tree to the service account as the last step, so the bootstrap
never runs in a directory another account can already write to. Files are mode
0600 and the directory is mode 0700. Ownership is applied to each entry itself,
never through a symbolic link, and an installation refuses to take ownership of
anything in that directory that is not a regular file or a directory.

What is *not* in the persistent directory is the record of the installation and
a dispatcher's maintenance switch. Both live in `/etc/debuglet/services`, where
only an administrator can write them and every account can read them. That
separation is the point: the service account owns its state directory and can
therefore replace anything inside it, so nothing there may tell a later
privileged command where to act. Every path a later `start`, `stop`, `status`,
`drain` or `uninstall` uses is derived from the root, the role and the name the
operator named, and the record is used at all only when it agrees with those
derived paths; a record that names a different directory, unit or database is
refused and nothing is done. A dispatcher likewise reads its maintenance switch
and cannot remove or rewrite it, so it cannot take itself out of maintenance. The unit adds no privileges, grants
no capabilities, sees no home directory and can write only to that directory.
A package installed under `$HOME/.local`, the default of the package installer,
can therefore not be run as a managed service, and installing one is refused
with that reason; install the package under a system prefix such as
`/usr/local` instead. Because the service is confined to its state directory,
the generated configuration uses userspace packet accounting and disables
wallet and SCION integration. A managed dispatcher is a boot-time service that
every account on its host can reach, so its generated configuration also leaves
`server.local_development` off explicitly rather than inheriting whatever the
shared generator writes for a foreground environment: it authenticates every
request that is not public, and a client obtains a session for it with
`dbl login --register NAME`. A managed executor also denies loopback and the
internal ranges to the debuglets it runs: it serves submitters it does not
trust, on a host that has other services on it, so the local profile's
`network.policy.local_targets` is switched off for it. Transport security is disabled in this profile,
so a managed executor accepts only a literal-loopback dispatcher address on the
same host.

A restart keeps the directory, so it keeps the databases, the stored results and
a managed executor's identity. Installing is repeatable and changes nothing the
second time; installing a different package version over an existing state
directory is refused, because startup never migrates a database. A reinstall
never restarts a running daemon: it reports that a restart is required and leaves
that decision to the operator.

`Type=exec` means the manager reports a unit started once the daemon has been
executed, which is process creation and not readiness. The daemon publishes its
readiness record when it has actually reached its ready point, and `dbl service
install`, `start` and `status` report ready only after reading that record and
finding that it names the unit's main process and, for an executor, its retained
identity. Stopping sends SIGTERM to the daemon alone (`KillMode=mixed`), which
leaves the teardown of anything it started to the daemon, and gives it the full
45-second budget. A stop is waited for rather longer than that budget, so a
daemon that uses all of it is not reported as a failure. The restart policy is the
deployment's and differs by role: a dispatcher is restarted after a failure
(`Restart=on-failure`), an executor after any exit at all (`Restart=always`),
because an executor that ends for any reason should come back. Neither undoes a
stop an operator asked for, which is what a drain relies on; a dropped control
stream needs no restart either, because the executor reconnects by itself.

The readiness record proves nothing about a stop: it lives in the unit's runtime
directory, which the manager removes whenever the unit stops, whether the daemon
finished or was killed. What proves that local ownership was released is how the
daemon left. An inactive unit whose recorded result is success and whose exit
status is zero is a daemon that ran its whole shutdown path: it revoked
admission, joined its own work and closed its database before exiting, and a
failure in any of those steps is a nonzero exit instead. A unit that was killed
at its stop timeout, or that exited nonzero, is `failed` with a result that says
which, and its state may still be owned by a process that never finished. Such a
unit stays failed until it is started and stopped again.

`dbl service uninstall` stops and removes the unit and keeps every byte of state;
removing a unit and disabling it touch no state, so they are allowed even after a
daemon ended badly. `--purge` also deletes the database, the identity, all
retained results and the installation record, and it is refused unless the last
shutdown actually finished. A refused purge undoes nothing at all, so the
instance stays installed and inspectable.

## Draining a managed role

`dbl drain --role executor` stops one managed executor and disables its unit. The
stop is the drain: it is what revokes the executor's control eligibility, signals
its running work and joins its own local cleanup, and this workflow adds no
second lifecycle controller beside it. Other executors are untouched and keep
serving. The wait-versus-cancel policy is the daemon's own: queued work is
waited for only in the sense that admission is closed and nothing new starts,
running work is signaled and joined inside the stop budget, and nothing beyond
that is cancelled.

Once the join is proven, the command reports the disposition of what the node
still holds, read from its database read-only:

- **Queued.** Rows that were accepted and persisted but never started stay in the
  database. Nothing replays them; this build quarantines every stored control
  binding on the next start, so they stay inspectable instead of being re-run.
- **Started.** Rows that carry a start marker are never re-run either: a
  restarted executor refuses work it already started.
- **Quarantined.** Every retained row, for the reason above.
- **Terminal results.** Successfully persisted results whose acknowledgement
  this executor never observed stay retained, including those it never managed
  to send and those the dispatcher refused permanently. A storage write failure
  can leave no retained result; this build does not guarantee recovery from
  that failure. A retained result is evidence that this node selected an
  outcome; it is not evidence about what the dispatcher recorded.

Rows and results are counted exactly, however many there are. The one bounded
part of the report is the number of distinct control sessions the retained rows
came from: at most a thousand are distinguished, and a node holding work from
more says so, so that number is a lower bound and every other number is not.

A drain that does not join inside its budget is reported as incomplete. That report
authorizes nothing: no deletion, no upgrade and no database closure, because the
process may still own the database. `dbl drain --resume` enables and starts the
executor again; it replays nothing, and the retained rows stay quarantined.

`dbl drain --role dispatcher` does not stop the dispatcher. It publishes a
maintenance switch, a mode-0644 file in `/etc/debuglet/services` that the
generated unit names in `DEBUGLET_MAINTENANCE_FILE`, and the dispatcher refuses
new submissions while it is there. A refused submission is answered `503` with
the operator's reason, and nothing is admitted, scheduled or inserted. The
payment intent route is refused the same way, so no new order is priced while
a dispatcher is paused; an order that was already paid before the pause is
refunded by the refusal itself, which spends it: the same batch is refused from
then on, so no batch is ever run for a payment that has been given back. The
refund itself is at least once against the chain, not exactly once. The order
rows and the transaction move together in one database transaction, but the
transfer is not part of it: a transfer that was executed and then reported an
error, or one followed by a commit that failed, leaves the transaction paid and
is attempted again on the next submission. When the refund cannot be performed
at all the answer says the order is still paid and the batch can be submitted
again once admission resumes. It adds no route, needs no credential
and survives a restart, so maintenance is not undone by the restart it was
declared for; it is read for each submission, so `--resume` takes effect at once
without a restart. It stops exactly one thing: accepted debuglets keep their
persistence and schedule, executors keep their control sessions, and results and
queries are unaffected. A switch file that exists but cannot be read or
understood also stops admission; an operator removes the file to serve again.

## CI

`make ci-compatibility` installs and checks the package produced by `make ci-package`. It retains test output and result files under `.cache/ci/`. `make ci-local` additionally checks the installed combined environment and independent dispatcher/executor/client roles, including URL connection, executor selection, the SDK example and same-package restart with retained results. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full build/test sequence.

A pass covers the installed package and local API-prefix traversal. It does not establish remote topology, SCION operation, authenticated nodes, or production readiness. Traffic-policy enforcement is covered by the package tests under `internal/executor` and `pkg/debuglet`, not by the installed checks. ETH testbed compatibility and deployment remain unconfirmed.

## Deployment

Deployment inputs live in [deploy/](../deploy): the two container images, the Ansible roles that install the daemons as systemd services, and the scripts around them. See [deploy/README.md](../deploy/README.md).

The examples there belong to one of two profiles, and neither is derived from the other. The **local TEST** profile is the compose rig in [docker-compose.yml](../docker-compose.yml) with the configuration in `deploy/docker/configs`: two daemons on one machine with TEST payments, no wallet, no certificates, no packet counter and no external network, publishing its API on a loopback address only. Its executor shares the dispatcher's network namespace and reaches it over loopback, which is the one shape a control channel without transport security is supported in. The **authenticated deployment** profile is the Ansible roles, which render their configuration from templates and need an inventory, pinned SSH host identities, a dispatcher address, an API origin and one UUID per executor. The API enforces authentication, so a client obtains a session with `dbl login --register`; the one credential-free profile is `server.local_development`, which `dbl up` and `dbl demo` use and which the daemon refuses on anything but a loopback listener. Installing those same two daemons by hand on separate hosts, with a private authority and authentication on, is written out step by step in the [cross-host quickstart](quickstart-remote.md).

Both images and the binaries the Ansible roles install come from the same release payload as the package, built with the pinned toolchain from a clean committed checkout, so a deployed daemon reports the same version and source revision as an installed one. `deploy/docker/smoke-test.sh` builds both images, checks that identity against the checkout, and starts each image on a loopback-only network with a temporary configuration. `deploy/docker/compose-smoke.sh` checks the local TEST rig end to end: it seeds the databases with the packaged migrations, waits for a ready executor on the published loopback API, runs one TEST sample, restarts both services and reads the same run back.

A deployment installs the same verified package an operator installs by hand, and runs from a provisioner built only from pinned inputs. `deploy/scripts/build-linux.sh` copies the release archive, its checksums and its own installer out of the payload stage and records the version, source revision, toolchain and digests; the Ansible payload role checks those digests on the managed host before the package's own installer runs, and nothing is compiled or bootstrapped there. `deploy/provisioner.env` pins the provisioner's base image by digest, the Ansible version, the collections and the digest of each dependency manifest, and `deploy/ansible/preflight-provisioner.yml` stops a deployment before it changes a host when the running provisioner differs from them. Each managed host carries `/etc/debuglet/deployment-<environment>.json`, which records the application and the provisioner separately for `prod` or `dev`. `deploy/test/provisioner-check.sh` builds the provisioner and checks all of that in a throwaway container.

Select deployment targets explicitly: `./deploy/debuglet-deploy dev` builds, deploys and verifies development, while `prod` selects production. There is no production default. The command selects the environment's inventory, variables and pinned SSH host-key file. The environments use separate package prefixes (`/opt/debuglet/dev` and `/opt/debuglet/prod`), staging directories, deployment records and executor users, configurations, state and systemd units. See [deployment setup](../deploy/README.md) before using any command that changes hosts.

Existing nonempty legacy databases are preserved. Discovering legacy state while a new environment-specific database is absent stops deployment; an operator must establish schema compatibility and prepare the intended state before proceeding. Moving a database is not a schema upgrade, and the playbooks do not perform one.

`deploy/test/ansible-render.sh` applies the deployment roles to a temporary directory tree over the local connection. It checks that the preflight refuses a missing dispatcher address, a missing API origin, a wildcard credentialed origin, colliding listener ports and a non-UUID executor identity; that the rendered configurations name the configured listener addresses and keep each database in the writable state directory rather than the read-only configuration directory; that the installed daemons accept both rendered configurations through their own validator; and that repeating the same variables changes nothing. Nothing is deployed anywhere.

Certificate material is issued by two targets, both writing outside the repository's tracked files. `make deploy-certs INVENTORY=hosts.dev.yml DEPLOY_ENV=dev DISPATCHER_SANS="DNS:dispatcher.example.com,IP:203.0.113.10"` runs `deploy/scripts/generate-certs.sh` for every executor in the inventory and installs the result: it writes a private CA to `deploy/certs/`, a dispatcher server certificate carrying exactly those subjectAltName entries with `serverAuth` extended key usage, and one client certificate per executor UUID with `clientAuth`, then `deploy/ansible/deploy-certs.yml` installs the server keypair and the CA on the dispatcher and the CA plus that host's client certificate on each executor. The subjectAltName list has no default and is required, because an executor verifies the dispatcher against the name it dialled and a common name alone is not accepted. The deployment preflight refuses missing material, an expired root, a leaf that does not chain to it and a leaf without the extended key usage for its side, before it touches a host; every certificate the generator issues comes straight from that CA, so a leaf file is a complete chain, while material from another authority has to carry the leaf followed by its intermediates, with authority files holding roots only. `make deploy` installs no certificates, so `make deploy-certs` comes first with the same inventory and environment. `make generate-certs` is the separate local-development target: it writes two self-signed keypairs into `local/configs/`, a dispatcher server certificate and an executor client certificate, each carrying `DNS:localhost` and `IP:127.0.0.1`; the `local/` configurations run with TLS disabled and do not read them.

Managed hosts are authenticated against a provisioned known-hosts file: an unknown or changed SSH host key ends the connection before a deployment changes anything, and no command trusts a key it merely scanned. `deploy/test/host-key-verification.sh` checks that against a throwaway loopback SSH server. The host-key provisioning and rotation procedure is in [deploy/README.md](../deploy/README.md).

Neither that check nor the CI pipeline deploys anywhere. Nothing here establishes remote topology, SCION operation, authenticated nodes or traffic-policy enforcement.
