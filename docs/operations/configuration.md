# Configuration reference

`dbl demo`, `dbl up`, `dbl dispatcher up`, and `dbl executor up` generate safe loopback configuration. This page applies when an operator starts `debuglet-dispatcher` or `debuglet-executor` with `-config FILE`.

## Dispatcher

A networked dispatcher needs a SQLite database path, reachable HTTP and gRPC listeners, and TLS. Keep `server.local_development = false`; the credential-free profile is only for loopback local development. Configure a trusted certificate authority when enrolling executor client certificates.

## Executor

An executor needs a stable `identity.executor_id`, a private SQLite database, dispatcher control addresses, and TLS credentials for a networked deployment. Use the same release as the dispatcher. Choose `packet_counter = "fallback"` unless the host is deliberately configured for eBPF accounting.

## State and upgrades

Daemons never migrate a database at startup. Back up the dispatcher database, use the release's explicit migration process, and deploy a single reviewed version across the service. An interrupted executor run is not resumed after restart.

The [configuration examples](../../configs) and [Ansible templates](../../deploy/ansible) are the canonical key-level references. Use the [Wiki](https://github.com/netsec-ethz/debuglet/wiki) for deployment, TLS, and operator procedures.
