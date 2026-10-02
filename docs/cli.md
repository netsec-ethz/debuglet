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
For a managed browser account, use `dbl login` (or `dbl login --no-browser` on a
headless host) to approve the printed device code in the console. See
[browser accounts and CLI access](operations/authentication.md).

```sh
dbl connect https://dispatcher.example --name research
dbl --dispatcher research login --register researcher
dbl --dispatcher research nodes
dbl --dispatcher research run --sample hello --wait --allow-remote-test
```

Use [capability filters](operations/executor-discovery.md) on `nodes` and `run` to select a ready executor by protocol, enforcement mode, advertised capacity and SCION ISD-AS (`--isd-as`). The table also shows the operator's name and location labels, the reported ISD-AS and the packet attribution state (`available`, `unavailable(<reason>)` or `unknown`); `--output json` adds admission state, the operator's network label, the reported listeners and the attribution refresh details.

### Return to an existing account

For a local or legacy account-key account, use the workflow below. Renew a
managed API credential with `dbl login`; approve it through either configured
browser provider.

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
their contents. Keep private backups of both. `credentials.json` holds either
the session or its system-store reference and must remain mode `0600`; do not
fix a permission error by making it world-readable. `dbl --dispatcher research logout` revokes the current
session when reachable and forgets it locally. It does not delete the account
or its account-key file.

### Choose credential storage

`dbl login --credential-store auto` is the default. On Linux desktops with
`secret-tool` and a D-Bus session, it saves the issued credential in Secret
Service (for example, GNOME Keyring). Install your distribution's
`libsecret-tools` package to provide `secret-tool`. A locked or failing keyring
is an error: unlock it and retry, or explicitly choose file storage.

Without that desktop facility, `auto` uses the existing owner-only `0600` file.
The login result always names the selected store; JSON output contains
`credential_store: "system"` or `"file"`. Use `--credential-store system` to
require Secret Service, or choose the headless/container path explicitly:

```sh
dbl --dispatcher research login --no-browser --credential-store file
```

System storage keeps only an opaque reference in `credentials.json`. The
secret is bound to the profile name, config directory, dispatcher URL and
account: moving the profile to another path requires a fresh login. Existing
file-backed logins remain readable. Logging in again with a different store
replaces the selected profile's credential; it does not revoke previously
issued credentials. Use the console **Credentials** page to retire old access.

Before downgrading the CLI, use the current version to log out or log in with
`--credential-store file` for every system-backed profile. Older CLIs reject a
credential file containing system-store references, including its file-backed
profiles; conversion of the last system-backed profile restores the older format.

`dbl logout` revokes the current credential and removes its local entry. If
system cleanup fails, use your desktop keyring manager to remove the affected
**Debuglet CLI** entry and revoke it from the console. A saved system credential
cannot be read on a headless host without its original Secret Service session;
use a fresh browser-approved login with file storage there. Native macOS and
Windows secret stores are not supported; supported native packages remain
Linux amd64.

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
packet enforcement or daemon readiness. The `clock` check reads the kernel's
synchronization state and estimated error on Linux (`adjtimex`, read only) and
passes when the kernel reports a synchronized clock within the executor's
`clock.max_error_ms` (100 ms without an executor file). An unsynchronized
clock or a larger error is `not_checked` with the reason, not a failure: the
executor then reports degraded clock readiness but still admits runs. It
queries no time source, so a pass is the kernel's own estimate, not a verified
time. Other platforms report it `not_checked`.

After stopping the daemon, add `--offline` to inspect its database schema without
writing database state. Existing journals make that check inconclusive and are
left unchanged. Report statuses are `pass`, `failure`, `unavailable` and
`not_checked`; failures or unavailable checks exit 1. `not_checked` is not a
successful verification.

### Verify captured probes

```sh
dbl --dispatcher research verify capture.pcap --evidence evidence.json
dbl verify evidence.json
```

`verify` tells the recipient of probes which Debuglet run, if any, sent them.
It needs no account: it reads the dispatcher's public attribution history,
checks the tags on this machine and never uploads packets. It prints one line
per group of packets (one source address in one 10-second epoch, by default)
and then what each verdict means and what to do next:

```
verified     run 6f1c2b1d…  executor exec-zrh-1  192.0.2.4  2026-09-29T09:02Z  40 packets  via offline
pending      198.51.100.4  2026-09-29T10:20Z  5 packets  until 2026-09-29T10:36Z

2 groups: 1 verified, 1 pending (45 packets, tag spec debuglet-tag-v1, checked offline against the history of https://dispatcher.example).
- verified (offline): packets carry valid tags of run 6f1c2b1d-4c8e-4a6f-9d3b-2e1c4a57aaaa on executor exec-zrh-1.
  Offline verification proves this only if the packets were captured before their keys were disclosed (…). …
- pending: the keys of 1 group are not disclosed yet. Retry after 10:36 UTC (2026-09-29), or keep an evidence bundle now with --evidence.
```

Keys are disclosed about 15 minutes after use, so a fresh capture is
`pending`; run the command again after the time it names. `invalid` means the
packets were not sent by the named address's runs (`no_run`: no run was
active; `tag_mismatch`: no packet's tag matches). A group whose packets
carry tags of different runs, as when one executor runs two measurements
toward the same recipient at once, is split into a `verified` line per run
("3 of 5 packets"); its packets that match no run are `unsupported
(unmatched)`, not `invalid`, since the rest of the group does match.
`missing` means the
dispatcher no longer keeps history for that time and proves nothing either
way; `unsupported` names what cannot be checked (IPv6, fragments, a snap
length below 64 bytes, a legacy executor). `--output json` prints the full
report. `--at TIME` takes TIME as the capture time of every packet.
`--evidence FILE` writes a bundle that `dbl verify FILE` checks again later
without the capture or the dispatcher. `--source ADDRESS[/BITS],…` checks
only the packets from those addresses: every other address costs history
lookups (one per second of its traffic without a run), and one check makes
at most 1024. Exit status: 0 all verified, 1 error (usage errors included:
unlike other commands, `dbl verify` never exits 2 for one), 2 some invalid,
3 otherwise inconclusive, 124 timed out. The default timeout is 5 minutes.
Lookups are paced to the dispatcher's rate limit (10 per second, burst 40);
when the dispatcher still answers `429`, `verify` waits for its
`Retry-After` and retries until the timeout, then says how many groups
remain unchecked.
See [probe verification](verification.md).

## Command groups

| Goal | Commands |
| --- | --- |
| Run local roles | `demo`, `up`, `dispatcher up`, `executor up` |
| Manage connections | `connect`, `dispatcher list`, `dispatcher use`, `dispatcher remove` |
| Manage credentials | `login`, `logout`, `whoami` |
| Submit work | `validate`, `run`, `retry`, `rendezvous`, `cancel` |
| Read results | `nodes`, `status`, `logs`, `recovery` |
| Verify received probes | `verify` |
| Manage system services | `service`, `drain` |
| Inspect versions | `version` |
| Inspect local setup | `config`, `doctor` |

`dbl recovery ID` separates the last stored outcome from control availability and a dated executor observation. See [recovery inspection](operations/recovery-inspection.md); no result authorizes replay.

See [measurement workflows](measurements.md) for a deliberate linked retry and
the installed two-executor echo command. Both preserve run identities when a
submission or cleanup response is uncertain.

## Common options

Global options precede the command; command options precede positional arguments.
For example: `dbl --dispatcher research logs --after 10 --limit 100 ID`.

| Option | Default / effect |
| --- | --- |
| `--dispatcher NAME` | Use a saved connection and its endpoint-bound credential. Without it, use the selected connection. |
| `--endpoint URL` | One-off endpoint; does not use a saved connection's credential. Use a saved connection for login. |
| `--config FILE` | Connections file; Linux defaults to `$XDG_CONFIG_HOME/debuglet/config.json` or `$HOME/.config/debuglet/config.json`. |
| `--output human\|json` | `human`; use `json` for scripts. |
| `--timeout DURATION` | Whole-command deadline: normally `30s`, `60s` for `demo`, and `5m` for `service`/`drain`/`verify`. Foreground `up`, `dispatcher up` and `executor up` have no whole-command deadline unless supplied. |

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

`dbl cancel --status ID` inspects the first recorded cancellation without sending another request. It requires API 1.9 or newer and exits successfully even for an unresolved disposition. JSON includes separate request, delivery-attempt and executor-acknowledgement timestamps plus the stored run result. After a lost response or timeout, inspect this record before deciding whether to repeat `dbl cancel ID`; a missing acknowledgement is not proof that the executor did nothing. On older dispatchers, use `dbl status ID` for the run result; ordinary `dbl cancel ID` remains supported.
