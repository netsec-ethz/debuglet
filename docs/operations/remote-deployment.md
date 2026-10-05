# Run Debuglet across hosts

A networked deployment has one dispatcher and one or more executors on Linux amd64 hosts. Every role runs the same Debuglet release. Use TLS, authenticate users, and keep the local-development profile disabled. Running a second dispatcher, against the same database or a separate one, is unsupported, and the dispatcher does not detect one at startup. To recover from a dispatcher outage, restart the dispatcher as described in [dispatcher outage](dispatcher-outage.md); [backup and restore](backup-restore.md) covers generated local TEST state.

Use the full release bundle for the bundled samples. The native daemons accept
operator-supplied configuration; `dbl up`, `dbl executor up`, and `dbl service
install` generate local loopback profiles and do not provision this deployment.

## Required topology

- Clients reach the dispatcher HTTP API.
- Executors connect outward to the dispatcher's HTTP and gRPC control listeners.
- Executors need no public inbound control port.
- The dispatcher certificate must match the name or address executors use.

## Native TLS and executor enrollment

The operator supplies a server certificate with the dispatcher's dialled name in
its subject alternative names, and a distinct client certificate and private key
for each executor. Distribute the CA's public certificate to clients and
executors through a trusted channel; keep its private key off daemon hosts.
Protect each executor's key and configuration so only its service account and
the administrator can read them.

In addition to its [database and listener configuration](configuration.md), the
dispatcher needs these keys to verify executor identities:

```toml
[tls]
disable = false
cert_file = "/etc/debuglet/dispatcher/server.crt"
key_file = "/etc/debuglet/dispatcher/server.key"
ca_file = "/etc/debuglet/dispatcher/ca.crt"
require_client_cert = true
```

Keep `server.local_development = false`; for wallet-free TEST submissions set
`sui.disabled = true`. The HTTP API still accepts authenticated users without a
client certificate. Both executor control channels require one. TLS termination
at a proxy alone does not establish this native certificate-to-executor binding.

For each stable executor UUID, the operator runs the installed dispatcher command
against its configured database, as the database owner:

```sh
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml \
  -enroll-executor EXECUTOR_UUID
```

Run this in a private terminal: the command prints a secret token once, valid for
24 hours and usable once.
Transfer it privately to that executor; keep it out of shared logs and version
control. Add it to the executor's protected configuration for its first start:

```toml
[identity]
executor_id = "EXECUTOR_UUID"
[dispatcher]
addr = "dispatcher.example:9001"       # direct gRPC listener
yamux_addr = "dispatcher.example:9000" # reverse control and HTTP API listener
[tls]
disable = false
[credentials]
ca_cert = "/etc/debuglet/executor/ca.crt"
client_cert = "/etc/debuglet/executor/client.crt"
client_key = "/etc/debuglet/executor/client.key"
enrollment_token = "PRIVATE_TOKEN"
```

These are the connection fields, not a complete executor configuration; also
supply the existing database, resource and pricing settings. For the userspace
TEST profile, set `network.packet_counter = "fallback"` and keep
`network.policy.local_targets = false`. Use
`tls.server_name` only when the certificate name differs from the dialled host.
The gRPC and reverse-control addresses must name their respective listeners.

The first successful registration consumes the token and stores the certificate
fingerprint bound to that UUID. Remove `credentials.enrollment_token` afterward.
Restart with the same UUID, keypair and database; no new token is needed. A
replacement certificate needs a new token for the same UUID. The corresponding
`-revoke-executor EXECUTOR_UUID` command removes the binding and prevents new
registration and lease renewal. An existing session retains its current lease
until expiry or an earlier disconnect.

The current Ansible executor template renders the certificate paths but has no
enrollment-token input. It does not perform this initial binding automatically.
An on-host configuration edit is overwritten by the next Ansible deployment;
coordinate initial enrollment and configuration ownership with the operator.
Do not disable client-certificate verification to bypass missing enrollment.

## Client trust and account access

The published v0.2.0 CLI uses account-key login. For this profile with a private
CA on Linux, set `SSL_CERT_FILE` to its public certificate before using `dbl`.
Each participant registers an independent account once and retains the private
account key, recovery code and saved session. This flow does not perform browser
GitHub login; managed deployments may use a different account policy.

```sh
export SSL_CERT_FILE=/path/to/ca.crt
dbl connect https://dispatcher.example:9000 --name research
dbl --dispatcher research login --register alice
dbl --dispatcher research nodes
dbl --dispatcher research run --sample hello --executor OTHER_EXECUTOR_UUID --wait --allow-remote-test
dbl --dispatcher research logs RUN_ID
```

Use the operator's actual API URL, including any proxy path prefix. With multiple
executors, select the intended ready UUID explicitly. TEST moves no funds and
requires `--allow-remote-test` outside a literal loopback endpoint. Results belong
to the submitting account. For a later login, reuse its saved account key as
described in [the CLI reference](../cli.md#return-to-an-existing-account).

## Release-specific commands

- The v0.2.0 full bundle links only `dbl` into `PREFIX/bin`; invoke its daemons
  from `PREFIX/lib/debuglet/v0.2.0/bin`. Current source builds also link the daemon commands.
- v0.2.0 has no `-init-database` flag. Its documented initialization uses the
  local `dbl` roles once, followed by an orderly stop, to create the database
  before starting a native daemon. Current source supports the explicit
  [database initialization command](configuration.md#creating-a-database).
- Preserve each role's database and credentials across restart. Use the explicit
  [upgrade procedure](configuration.md#upgrading-a-database) when changing releases;
  do not run an older daemon against a newer database.

The [Operating a Dispatcher](https://github.com/netsec-ethz/debuglet/wiki/Operating-a-Dispatcher), [Operating an Executor](https://github.com/netsec-ethz/debuglet/wiki/Operating-an-Executor), and [Deployment and Upgrades](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades) Wiki pages contain the operator workflow and recovery guidance.
