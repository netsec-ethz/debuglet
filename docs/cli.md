# `dbl` command-line client

`dbl` is the fastest way to try Debuglet, manage local roles, submit debuglets, and inspect results. Run `dbl --help` for the complete, version-specific command reference.

## Common workflows

### Try Debuglet

```sh
dbl demo
```

### Run local roles separately

```sh
# terminal 1
dbl dispatcher up

# terminal 2
dbl executor up --dispatcher http://127.0.0.1:9000

# terminal 3
dbl connect http://127.0.0.1:9000 --name local
dbl run --sample hello --wait
dbl logs ID
```

### Use a managed dispatcher

```sh
dbl connect https://dispatcher.example --name research
dbl --dispatcher research login --register researcher
dbl --dispatcher research nodes
dbl --dispatcher research run --sample hello --wait --allow-remote-test
```

### Inspect the saved account

```sh
dbl --dispatcher research --output json whoami
```

`whoami` reports the selected session's account ID, name and role. A missing,
expired or revoked credential exits 1 with a `dbl login` hint. Credentials are
never printed.

### Inspect daemon configuration

```sh
dbl --output json config --role executor --file /etc/debuglet/executor/executor.toml
```

`config` uses the daemon's configuration validation and reports nonsecret settings
with their origins: configured, default, or deferred until startup. It omits
credential fields and URL credentials, queries and fragments. It makes no network
request, opens no database and leaves the configuration unchanged.

### Diagnose an installation

```sh
dbl --output json doctor --role executor --file /etc/debuglet/executor/executor.toml
dbl --dispatcher research --timeout 10s --output json doctor --connection
```

`doctor` reports local prerequisites without starting a daemon or measurement.
Network checks require `--connection` and contact only the selected HTTP
dispatcher's version route. Filesystem and capability checks describe the
invoking process, which may differ from the service account; they do not prove
packet enforcement, clock synchronization or daemon readiness.

After stopping the daemon, add `--offline` to inspect its database schema without
writing database state. Existing journals make that check inconclusive and are
left unchanged. Report statuses are `pass`, `failure`, `unavailable` and
`not_checked`; failures or unavailable checks exit 1. `not_checked` is not a
successful verification.

## Command groups

| Goal | Commands |
| --- | --- |
| Run local roles | `demo`, `up`, `dispatcher up`, `executor up` |
| Manage connections | `connect`, `dispatcher list`, `dispatcher use`, `dispatcher remove` |
| Manage credentials | `login`, `logout`, `whoami` |
| Submit work | `validate`, `run`, `cancel` |
| Read results | `nodes`, `status`, `logs` |
| Manage system services | `service`, `drain` |
| Inspect versions | `version` |
| Inspect local setup | `config`, `doctor` |

Use `--output json` when another program reads command output. `--dispatcher NAME` selects a saved connection; `--endpoint URL` uses a one-off endpoint.

The [Wiki](https://github.com/netsec-ethz/debuglet/wiki) explains managed services, deployment, and recovery. The [HTTP API guide](api.md) is the reference for applications that do not use `dbl`.
