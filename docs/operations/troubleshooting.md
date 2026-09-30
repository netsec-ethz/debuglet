# Troubleshooting

Use the guide for your installed release. Start with the failure below and keep
existing state while diagnosing it.

## A local port is occupied

An `address already in use` error means another process has the requested port.
For a disposable local pair, choose an available port and fresh state:

```sh
dbl up --port 0 --state-dir "$(mktemp -d)"
```

Connect to the endpoint it prints. Leave unrelated services running; use the
existing instance if it is the one you intended to connect to.

## No executor is ready, or an executor cannot join

Run `dbl nodes` on the selected connection. If it lists no ready executor, start
the intended executor or inspect its daemon log. For a networked deployment,
check its dispatcher HTTP and gRPC addresses, matching release, and TLS client
credentials. A certificate error calls for the operator's public CA and a
dispatcher address matching its certificate, not disabled verification. Follow
the [connection topology](remote-deployment.md#required-topology) if a control
listener is unreachable. Local roles use the endpoint printed by the dispatcher;
see the [local-role commands](../cli.md#run-local-roles-separately).

## OAuth login fails, or a browser session expires

Return to the deployment's sign-in page and start GitHub login again. Complete
the flow in the same browser with cookies enabled. An `invalid GitHub login
state` or `invalid GitHub login verifier` error can follow an expired or missing
login cookie; start a fresh login instead of reusing the callback URL. A missing,
expired or revoked session requires a new provider login, not account-key recovery.

If login is disabled or continues to fail, ask the operator to check the daemon
log and the configured GitHub application, callback URL and HTTPS/cookie setup
against the [OAuth deployment settings](../../deploy/README.md#deployment-variables).
Do not send cookies, authorization codes or application secrets with a report.

## A service runs but is not ready

An active process alone does not establish readiness. For the default
`dbl service` executor instance, inspect both status and recent diagnostics:

```sh
sudo dbl service status --role executor
sudo journalctl -u debuglet-executor-worker.service -n 100 --no-pager
```

Use `--role dispatcher` for its status; its default unit is
`debuglet-dispatcher-local.service`. For a named instance, pass its `--name` and
read the unit reported by status. Ansible deployments use their deployed unit
names. Correct the first reported configuration, permission or connection error
before restarting. Foreground `dbl up` and role commands keep `dispatcher.log`
or `executor.log` in the state directory they report; [log retention](services.md#foreground-daemon-logs)
describes the rotated files. `dbl logs ID` reads measurement output, not daemon logs.

## Database schema or local state version is unsupported

Startup refuses a schema the binary cannot serve, and local state is pinned to
the package that created it. Keep the existing directory. For disposable local
work, select a fresh `--state-dir` as above. For persistent services, stop the
affected role, back up its state and follow the release's explicit
[database upgrade procedure](../../deploy/README.md#upgrading-a-database).
Changing the recorded version or deleting the database is not an upgrade.

## A role was killed while it wrote its database

The daemons keep their SQLite databases in rollback-journal mode. A daemon
killed in the middle of a write (`SIGKILL`, OOM kill, host crash) leaves a
`-journal` file next to the database that holds the committed content of the
pages the unfinished transaction had already overwritten. The next start rolls
that transaction back before the schema check, as SQLite does for any writer
that opens the file, logs once at warn level `Database crash recovery ran` with
the database and journal paths, and then checks and serves the last committed
state. `-upgrade-database` does the same and prints the warning on standard
error. Nothing committed is lost; the interrupted write is, as if it had never
started.

The read-only checks do not recover: `-check-database` refuses such a database
as unreadable with `database needs crash recovery`, naming the journal, and
`dbl doctor --offline` reports the schema `not_checked` with the same reason.
Start the daemon, or run its `-upgrade-database`, and check again. Never delete
the `-journal` file: the database without it may be corrupt. If recovery itself
fails, for example because the service account cannot write the database or
its directory, startup refuses with `SQLite could not roll back its journal`.
Correct the ownership or permissions and start again; if that is not the cause,
stop every process using the database, keep the database and its journal
together, and restore the database from a backup.
