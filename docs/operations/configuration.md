# Configuration reference

`dbl demo`, `dbl up`, `dbl dispatcher up`, and `dbl executor up` generate safe loopback configuration. This page applies when an operator starts `debuglet-dispatcher` or `debuglet-executor` with `-config FILE`.

## Dispatcher

A networked dispatcher needs a SQLite database path, reachable HTTP and gRPC listeners, and TLS. Keep `server.local_development = false`; the credential-free profile is only for loopback local development. Configure a trusted certificate authority when enrolling executor client certificates.

## Executor

An executor needs a stable `identity.executor_id`, a private SQLite database, dispatcher control addresses, and TLS credentials for a networked deployment. Use the same release as the dispatcher. Choose `packet_counter = "fallback"` unless the host is deliberately configured for eBPF accounting.

## State and upgrades

Daemons never migrate a database at startup. Back up the dispatcher database, use the release's explicit migration process, and deploy a single reviewed version across the service. An interrupted executor run is not resumed after restart.

### Creating a database

A daemon never creates its database either: `database.path` must name an existing file that holds the packaged schema, or the daemon refuses to start. There are three ways to create one.

- A deployment: `make deploy-seed-db` writes schema-only databases to `deploy/dist`, and deploying the host installs the matching one when the host has none yet (see [deploy/README.md](../../deploy/README.md)).
- A hand-installed host: start a fresh local service with the installed `dbl`, stop it once it is ready, and copy its database to `database.path`, owned by the service account. For a dispatcher, `dbl dispatcher up --state-dir DIR --port 0 --grpc-port 0` leaves `DIR/dispatcher.sqlite`; for an executor, `dbl up --state-dir DIR --port 0` leaves `DIR/executor.sqlite`. This is what `deploy/docker/seed-state.sh` does for the local container rig.
- A source checkout: `make upgrade` applies the migrations to `.data/dispatcher.db` and `.data/executor.db` with goose.

### Upgrading a database

`debuglet-dispatcher -config FILE -check-database` (and the same for `debuglet-executor`) reports whether the configured database is supported by this build, then exits. It only reads the database, so it can run while the daemon serves it, as the file's owner. Its exit status is:

| Status | Meaning |
|---|---|
| 0 | The database is current for this build; there is nothing to upgrade. |
| 3 | The database is outdated, and `-upgrade-database` brings it to this build keeping its data. |
| 4 | The database is outdated, and its upgrade drops the recorded runs and their logs; it needs `-accept-data-loss`. |
| 1 | Any other refusal: the database is absent, unreadable, not this role's, newer than this build, or incompletely migrated. |

To upgrade by hand, stop the daemon, back up the database file together with its `-wal` and `-shm` files when present, and run the new release's daemon with `-config FILE -upgrade-database` as the service account. It applies the packaged migrations and checks the result as a start does; on a current database it changes nothing. An upgrade from a dispatcher schema below version 3 or an executor schema below version 2 drops the tables `debuglets` and `debuglet_logs`, so the runs recorded there and their logs are lost; such an upgrade is refused unless `-accept-data-loss` is given as well. A deployment uses `deploy/ansible/upgrade-database.yml`, which runs these steps on every host and is described in [deploy/README.md](../../deploy/README.md).

Both modes act on the `database.path` of the configuration file given with `-config` and print the absolute path of the database they check or upgrade. A copied local-service directory keeps a `service.toml` whose `database.path` still names the original database, so edit that path, or write a separate configuration, before upgrading a copy. The daemons report the configuration's `server.version` (dispatcher) and `identity.version` (executor), which an upgrade does not change: after a hand-run upgrade, update those fields; a deployment re-renders them with the normal deployment command.

Each upgrade leaves its backup in place. Removing old `backup-*` directories is the operator's decision, after the upgraded service has been verified; a backup of a database with paid state is kept until its reconciliation is complete.

The [configuration examples](../../configs) and [Ansible templates](../../deploy/ansible) are the canonical key-level references. Use the [Wiki](https://github.com/netsec-ethz/debuglet/wiki) for deployment, TLS, and operator procedures.
