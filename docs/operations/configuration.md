# Configuration reference

`dbl demo`, `dbl up`, `dbl dispatcher up`, and `dbl executor up` generate safe loopback configuration. This page applies when an operator starts `debuglet-dispatcher` or `debuglet-executor` with `-config FILE`.

## Dispatcher

A networked dispatcher needs a SQLite database path, reachable HTTP and gRPC listeners, and TLS. Keep `server.local_development = false`; the credential-free profile is only for loopback local development. Configure a trusted certificate authority when enrolling executor client certificates.

## Executor

An executor needs a stable `identity.executor_id`, a private SQLite database, dispatcher control addresses, and TLS credentials for a networked deployment. Run exactly one executor daemon process per database; the raw daemon does not take a cross-process ownership lock. Use the same release as the dispatcher. Choose `packet_counter = "fallback"` unless the host is deliberately configured for eBPF accounting.

### Executor output limits

The optional `[output]` section uses the defaults shown in the [executor example](../../configs/executor/executor.toml): 8 MiB and 65,536 frames emitted per run, 64 MiB queued per executor, 65,536 retained run records, and 1 MiB/s per run with a 64 KiB burst. Zero selects the default. Stdout and stderr share one ordered writer, 16 KiB chunks and a 256 KiB accepted queue. Rate limits apply backpressure; a total-byte or storage limit cancels that guest and marks its accepted output prefix as truncated.

The spool budget charges payload plus 64 bytes per frame and 256 bytes per retained run; it is a logical quota, not an upper bound on SQLite file size or WAL space. Acknowledged payload is released, but reconciliation metadata remains bounded by `retained_runs`. No age-based deletion occurs. Existing data above a lowered cap remains readable; new admission can fail until capacity is raised or an explicit retention policy is applied. A storage write failure can make executor output admission unavailable until restart; a failed finality write stays pending.

Durable output requires both peers to negotiate output version 1. Retained output may resume over a new control session only with the same still-enrolled TLS certificate and original run binding. Plaintext local sessions cannot resume output across control bindings. Workloads themselves are never restarted, and output completion remains separate from the guest's exit status.

## State and upgrades

Daemons never migrate a database at startup. Back up the dispatcher database, use the release's explicit migration process, and deploy a single reviewed version across the service. An interrupted executor run is not resumed after restart.

### Creating a database

A normal daemon start requires `database.path` to name an existing, supported database. To create a schema without starting any service, use the installed daemon's explicit initialization command as the service account:

```sh
mkdir -m 700 /path/to/new-state
debuglet-dispatcher -init-database /path/to/new-state/dispatcher.db
# On an executor host, use debuglet-executor with the executor database path.
```

The parent must be a real mode-0700 directory owned by that account. Initialization creates a mode-0600 database exclusively and refuses an existing database or SQLite companion file without changing it. It takes an explicit path, reads no runtime configuration, and cannot be combined with other flags. Set the daemon configuration's `database.path` to that file afterward.

Local `dbl` services and the Docker seed service use the same implementation. For Ansible, run `make deploy-build deploy-seed-db`; seed generation uses the daemons from that verified payload, and the roles install a seed only when the host has no database yet. See [deploy/README.md](../../deploy/README.md).

The former goose CLI `make upgrade` and `make downgrade` targets are removed. Use the daemon commands below for explicit upgrades. Rollback means stopping the service and restoring the pre-upgrade database and its matching executable/configuration; it is not an automatic down migration. Never run an older binary against a newer database unless its schema policy explicitly accepts it.

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
