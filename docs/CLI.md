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

## Command groups

| Goal | Commands |
| --- | --- |
| Run local roles | `demo`, `up`, `dispatcher up`, `executor up` |
| Manage connections | `connect`, `dispatcher list`, `dispatcher use`, `dispatcher remove` |
| Manage credentials | `login`, `logout` |
| Submit work | `validate`, `run`, `cancel` |
| Read results | `nodes`, `status`, `logs` |
| Manage system services | `service`, `drain` |
| Inspect versions | `version` |

Use `--output json` when another program reads command output. `--dispatcher NAME` selects a saved connection; `--endpoint URL` uses a one-off endpoint.

The [Wiki](https://github.com/netsec-ethz/debuglet/wiki) explains managed services, deployment, and recovery. The [HTTP API guide](API.md) is the reference for applications that do not use `dbl`.
