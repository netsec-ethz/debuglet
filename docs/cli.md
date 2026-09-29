# `dbl` command-line client

`dbl` is the fastest way to try Debuglet, manage local roles, submit debuglets, and inspect results. Run `dbl --help` for the complete, version-specific command reference.
The local roles, bundled samples and demo require the full package. The CLI-only
package connects to an existing dispatcher and accepts your own `--wasm FILE`.

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

### Use an account-key connection

These CLI login commands apply to local or legacy account-key deployments.
Managed browser deployments use their configured OAuth sign-in flow; `dbl login`
does not perform browser OAuth login.

```sh
dbl connect https://dispatcher.example --name research
dbl --dispatcher research login --register researcher
dbl --dispatcher research nodes
dbl --dispatcher research run --sample hello --wait --allow-remote-test
```

Use [capability filters](operations/executor-discovery.md) on `nodes` and `run` to select a ready executor by protocol, enforcement mode and advertised capacity.

### Return to an existing account

For a local or legacy account-key account, use the workflow below. Renew a
managed browser session by signing in through its OAuth provider again.

A saved session is reused until it expires or is revoked; using it does not
extend its lifetime. Do not register a second account when login expires.
For the `research` connection above, the default Linux credential directory is
`${XDG_CONFIG_HOME:-$HOME/.config}/debuglet`. With `--config FILE`, credentials
live beside that file instead.

```sh
config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/debuglet"
dbl --dispatcher research login --account-key-file "$config_dir/account-key-research.txt"
dbl --dispatcher research nodes
```

Registration prints the locations of the account key and recovery code, not
their contents. Keep private backups of both. `credentials.json` holds the
session and must remain mode `0600`; do not fix a permission error by making
it world-readable. `dbl --dispatcher research logout` revokes the current
session when reachable and forgets it locally. It does not delete the account
or its account-key file.

### Recover a lost account key

The CLI has no recovery command. Use its saved recovery code with
[`POST /auth/recover`](../api/openapi.yaml) or [`pkg/client.Recover`](../pkg/client/client.go).
Recovery replaces both credentials and revokes all existing sessions. If both
the account key and recovery code are lost, neither can be retrieved from the
dispatcher.

This Linux example uses `curl` and `jq`, keeps credentials out of command
arguments and terminal output, and writes the result in a new private directory.
Set the endpoint to the same dispatcher as the saved `research` connection.
For a private CA, also supply `--cacert /path/to/ca.crt` to `curl`.

```sh
(
  set -eu
  umask 077
  config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/debuglet"
  recovery_dir=$(mktemp -d "$config_dir/recovered.XXXXXX")
  jq -n --rawfile code "$config_dir/recovery-research.txt" \
    '{recovery_code: ($code | rtrimstr("\n") | rtrimstr("\r"))}' > "$recovery_dir/request.json"
  curl --proto '=https' --fail --silent --show-error \
    -H 'Content-Type: application/json' --data-binary @"$recovery_dir/request.json" \
    --output "$recovery_dir/response.json" https://dispatcher.example/auth/recover
  jq -er '.account_key | select(type == "string" and length > 0)' \
    "$recovery_dir/response.json" > "$recovery_dir/account-key.txt"
  jq -er '.recovery_code | select(type == "string" and length > 0)' \
    "$recovery_dir/response.json" > "$recovery_dir/recovery.txt"
  dbl --dispatcher research login --account-key-file "$recovery_dir/account-key.txt"
  printf 'Keep the replacement credentials in %s\n' "$recovery_dir"
)
```

Back up the replacement files and use their paths for later login or recovery.
The old key and recovery code no longer work. A lost response can leave recovery
completed without delivering the new credentials: do not blindly retry the
old code; retain the response file, if any, and contact the dispatcher operator.

### Follow stored output

```sh
dbl logs --follow ID
dbl logs --follow --after LAST_CURSOR ID
```

Following succeeds only after draining the declared complete output cursor,
which can arrive before or after the workload exits. A truncated prefix is
printed before exiting 1 with its loss reason. Historical output or an older
server has unknown completeness: following drains a terminal run's available
pages, then exits 1 instead of claiming the stream is complete. Pending output
continues polling after workload exit; use the global `--timeout` to bound the
wait. Plain `dbl logs ID` remains a single successful page read, regardless of
finality. JSON pages include `output`; human progress goes to stderr and guest
bytes remain unchanged on stdout.

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
| Read results | `nodes`, `status`, `logs`, `recovery` |
| Manage system services | `service`, `drain` |
| Inspect versions | `version` |
| Inspect local setup | `config`, `doctor` |

`dbl recovery ID` separates the last stored outcome from control availability and a dated executor observation. See [recovery inspection](operations/recovery-inspection.md); no result authorizes replay.

## Common options

Global options precede the command; command options precede positional arguments.
For example: `dbl --dispatcher research logs --after 10 --limit 100 ID`.

| Option | Default / effect |
| --- | --- |
| `--dispatcher NAME` | Use a saved connection and its endpoint-bound credential. Without it, use the selected connection. |
| `--endpoint URL` | One-off endpoint; does not use a saved connection's credential. Use a saved connection for login. |
| `--config FILE` | Connections file; Linux defaults to `$XDG_CONFIG_HOME/debuglet/config.json` or `$HOME/.config/debuglet/config.json`. |
| `--output human\|json` | `human`; use `json` for scripts. |
| `--timeout DURATION` | Whole-command deadline: normally `30s`, `60s` for `demo`, and `5m` for `service`/`drain`. Foreground `up`, `dispatcher up` and `executor up` have no whole-command deadline unless supplied. |

### Submit and read measurements

| Option | Default / effect |
| --- | --- |
| `run --wasm FILE` or `--sample hello` | Exactly one input; a regular WASM file is limited to 24 MiB. The sample requires the full package. |
| `run --executor ID\|auto` | `auto` selects only when exactly one executor is ready. |
| `run --duration DURATION` | `10s` server run budget, at least `1ms`, in whole milliseconds. |
| `run --floor-bps N`, `--ceil-bps N` | Both `1048576`; ceiling must be at least the floor. |
| `run --allow ADDRESS` | Repeatable destination allowlist; narrows the executor policy. Put a destination's port in the guest arguments. |
| `run --wait` | Poll for the result; a failed workload exits 3. A client timeout does not cancel the run. |
| `run --allow-remote-test` | Required to deliberately use TEST outside a literal loopback endpoint; moves no funds. |
| `run -- ARGS...` | Pass the remaining arguments to the guest. |
| `logs --after N` | `0`; read entries after this cursor. |
| `logs --limit N` | `0` selects server default `100`; explicit page size is `1..1000`. |
| `logs --follow` | Drain the declared final output cursor; complete output succeeds, while truncated or historical unknown output exits 1. Pending output waits until the command timeout. |

Keep the submission's run ID. `status ID` reads the reported outcome and `logs ID`
reads output; `cancel ID` requests cancellation. The server's [API contract](api.md)
defines the outcome, including cases where remote termination is uncertain.

## Troubleshooting

Use the [troubleshooting guide](operations/troubleshooting.md) for occupied
ports, executor connections, OAuth sessions, service logs and state-version errors.

The [operations guides](README.md#operate-a-deployment) explain managed services, deployment, and recovery. The [HTTP API guide](api.md) is the reference for applications that do not use `dbl`.
