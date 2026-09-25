# `dbl` command-line client

`dbl` starts local dispatcher/executor roles, saves dispatcher connections, lists executors, submits TEST-funded WASM, and reads results through the dispatcher's HTTP API. It is built from `cmd/dbl` on top of [`pkg/client`](SDK.md) and is intended for a trusted local environment. No release package for this alpha is published yet; the existing `v0.1.0` tag predates it.


## Build or install

From a source checkout, build the standalone client with `go build -mod=readonly -o dbl ./cmd/dbl`. It can use an existing dispatcher. The complete Linux amd64 package also includes the assets for `dbl demo`; see the [installation guide](../README-install.md). No release-download URL or published version is assumed.

## Usage

```
dbl [--dispatcher NAME | --endpoint URL] [--config FILE] [--timeout 30s] [--output human|json] COMMAND
dbl demo
dbl up [--state-dir DIR] [--port 9000]
dbl dispatcher up [--name local] [--port 9000] [--grpc-port 9001] [--state-dir DIR]
dbl executor up [--name worker] [--dispatcher NAME|URL] [--state-dir DIR]
dbl service install --role dispatcher|executor [--name NAME] [--user debuglet] \
    [--port 9000] [--grpc-port 9001] [--dispatcher HOST:PORT] [--dispatcher-http HOST:PORT] \
    [--start=false] [--enable=false] [--root DIR]
dbl service start|stop|status --role ROLE [--name NAME]
dbl service uninstall --role ROLE [--name NAME] [--purge]
dbl drain --role ROLE [--name NAME] [--reason TEXT] [--wait DURATION] [--keep-enabled]
dbl drain --role ROLE [--name NAME] --resume
dbl connect URL [--name NAME]
dbl login [--account-key-file FILE] [--register NAME] [--recovery-file FILE]
dbl logout
dbl dispatcher list
dbl dispatcher use NAME
dbl dispatcher remove NAME
dbl executor list
dbl nodes
dbl validate (--wasm FILE | --sample hello) [--executor ID|auto] [--allow ADDRESS ...] \
    [--duration 10s] [--floor-bps 1048576] [--ceil-bps 1048576] [-- guest arguments ...]
dbl run (--wasm FILE | --sample hello) [--executor ID|auto] [--allow ADDRESS ...] \
    [--duration 10s] [--floor-bps 1048576] [--ceil-bps 1048576] \
    [--wait] [--allow-remote-test] [-- guest arguments ...]
dbl status ID
dbl logs [--after N] [--limit N] [--follow] ID
dbl cancel ID
dbl version [--server]
```

Global flags come before the command, command flags before positionals (`connect URL --name NAME` also accepts the name after the URL). Explicit `--endpoint` overrides the saved current connection; explicit `--dispatcher` selects a saved name, and supplying both is an error. Without either, the saved current connection is used; with none saved, the endpoint is `http://127.0.0.1:9000`; the SDK's endpoint rules apply (explicit prefix preserved, plaintext only for literal loopback IPs, no redirects, no insecure mode). Rejected endpoint values are omitted from diagnostics because they may contain credentials. `--timeout` supplies the command context for requests and polling; the default is 30 s, 60 s for `demo`, and 5 minutes for `service` and `drain`, which wait for a service manager and for local work to join rather than for a request. `up`, `dispatcher up` and `executor up` have no lifetime timeout unless you set `--timeout`; startup is bounded separately to 30 seconds. Local file operations are synchronous and cannot guarantee interruption of a stalled filesystem or hostile path replacement. `--output` defaults to `human`; `json` keeps stdout parseable. `--help` exits 0.

## Saved connections and separate roles

`dbl connect URL --name NAME` validates the HTTP server and saves/selects a profile.
The default config path is the OS user config directory plus `debuglet/config.json`
(on Linux, `$XDG_CONFIG_HOME/debuglet/config.json` or `~/.config/debuglet/config.json`).
Global `--config FILE` keeps an independent profile set. Profiles contain names and
addresses, not daemon state, a wallet or a credential.

`dispatcher list` (alias `dispatchers`) lists saved connections without network
probes. `dispatcher use NAME` changes the default. `dispatcher remove NAME` removes
only that saved connection; it neither stops a server nor deletes its database.
`executor list` (aliases `executors` and `nodes`) queries the selected dispatcher.

`dispatcher up` starts only a dispatcher and saves its local connection. It binds
loopback HTTP/yamux and gRPC listeners; port `0` selects an available port. Its
printed URL is enough for `executor up --dispatcher URL`. A saved name also works.
The executor gets control addresses from `GET /connection`; users need not derive
or type the second port. It requires the server's `local-test` metadata and literal
loopback addresses. A client can still save an older HTTP server lacking this
optional metadata, but executor startup needs a dispatcher that supplies it.

Roles create their configuration and fresh SQLite schema automatically, disable
wallet/SCION integration, and use userspace packet counting. Each runs until Ctrl-C
and stops only its owned daemon. State defaults to `dispatchers/NAME` or
`executors/NAME` below the local state directory described for `up`; `--state-dir`
overrides it. Executor UUIDs and stored results survive a clean same-package
restart. Active state directories are locked. These commands provide no automatic
database upgrades and no replay of interrupted work; `dbl service` installs the
same roles as supervised services instead of running them in a terminal.

## Managed services

`dbl service` installs one verified role as a service the host's service manager
supervises, next to the unprivileged foreground commands, which are unchanged. It
needs administrator privileges and an existing unprivileged service account
(`debuglet` by default); it never creates, changes or removes an account. Each
instance owns exactly one unit, `debuglet-<role>-<name>.service`, one persistent
state directory `/var/lib/debuglet/<role>s/<name>` holding its database, role
identity and generated configuration, one administrator-owned record in
`/etc/debuglet/services`, and one runtime directory `/run/debuglet/<role>s/<name>`
holding only its readiness record. Every path an operation uses is derived from
the role and name given on the command line; the record is believed only where it
agrees with them, so nothing the service account can write decides where a
privileged command acts.

`--root DIR` writes the same files below another directory so they can be read
before anything is installed for real. A staged tree is files and nothing else:
the host has exactly one service manager, a unit of the same name there is the
production instance, and a unit's runtime directory is the real `/run` whatever
a staged unit says. A staged tree therefore drives no service manager at all,
and `start`, `stop`, `uninstall`, `drain` and `--start`/`--enable` are refused
together with `--root` rather than pointed at the production instance of that
name.

The unit, the paths, the permissions and the shutdown budget are documented in
[environments](environments.md#managed-services) and mirrored in
[deploy/systemd](../deploy/systemd).

Installing is repeatable: the same payload and options a second time change
nothing and report nothing changed. A running daemon is never restarted as a
side effect; when a reinstall changes the unit or the configuration, the report
says a restart is required and leaves the decision to the operator. Installing a
different package version over an existing state directory is refused, because
this build never upgrades a database in place. A service is reported ready only
after its daemon published its own readiness record and that record names the
unit's main process; `started` alone is process creation and never counts as
ready. `uninstall` stops and removes the unit and keeps every byte of state;
`--purge` additionally deletes the database, the role identity, all retained
results and the record, and is refused unless the daemon's last shutdown
actually finished, which the service manager reports as an inactive unit with a
successful result and a zero exit status. A refused purge undoes nothing.

## Taking a role out of service

`dbl drain` removes one managed role from eligible capacity.

An executor is drained by stopping it: stopping is what revokes its control
eligibility, signals its running work and joins its own local cleanup, and the
drain also disables the unit so a reboot does not undo it (`--keep-enabled`
opts out). Every other executor keeps serving. When the join is proven, which means the
manager reports the unit inactive with a successful result and a zero exit
status, the command reports what the node still holds: rows that were accepted but never
started, rows that were started, the quarantine they all enter on the next start,
and terminal results the dispatcher has not acknowledged. Nothing is replayed and
nothing is deleted. A drain that does not join inside `--wait` is reported as
incomplete and authorizes nothing: no deletion, no upgrade, no database closure.

A dispatcher is not stopped. `dbl drain --role dispatcher` switches off the
admission of new submissions only, so accepted debuglets keep their persistence
and schedule, executors keep their control sessions, and results and queries are
unaffected. The switch is a mode-`0644` file in `/etc/debuglet/services`, which
only an administrator can write and which the dispatcher can neither replace nor
remove, so it survives a restart and a reboot, needs no network route and takes
effect immediately. A dispatcher is never stopped or disabled by a drain and
takes no `--keep-enabled`. While it is paused the payment intent route is
refused the same way, so nothing new is priced; an order that was already paid
is refunded by the refusal, which spends it, so the same batch is refused from
then on; where that refund cannot be performed the answer says the order is
still paid and the batch can be submitted again once admission resumes.
`--resume` reverses either drain; it replays nothing, and work retained from
before an executor drain stays quarantined.

## Credentials

A dispatcher authenticates every request that is not public, so a saved connection
usually needs a credential as well as an endpoint. The two are stored separately:
endpoints live in `config.json`, credentials in `credentials.json` beside it, mode
`0600` in the mode-`0700` configuration directory. Only the session is stored
there: the account key stays in the file its owner keeps, so a copy of the
credential file yields one expiring session rather than permanent access. A credential file any other user
can read is refused with the `chmod` that fixes it, rather than used.

```sh
dbl connect http://127.0.0.1:9000 --name local
dbl --dispatcher local login --register researcher   # creates an account
dbl --dispatcher local run --sample hello --wait
dbl --dispatcher local logout
```

- `login` obtains a session for the selected saved connection and stores it for that
  connection. The account key comes from `--account-key-file FILE`, else from the
  `DEBUGLET_ACCOUNT_KEY` environment variable; neither is a command-line argument, so
  it does not appear in this machine's process list. With neither, a dispatcher
  serving the local development profile issues a credential for its own local
  account, which is how the wallet-free local flow gets one without a browser.
- `login --register NAME` first creates an account on the selected dispatcher. Its
  two credentials are written, **never printed**, to owner-only files that must not
  exist yet: the account key to `--account-key-file FILE` (default
  `account-key-PROFILE.txt` beside the connections file) and the recovery code to
  `--recovery-file FILE` (default `recovery-PROFILE.txt`). Keep both; the dispatcher
  cannot show either again. The account key logs in later, the recovery code
  replaces both if it is lost, and both belong in a password manager.
- `logout` revokes the session at the dispatcher and forgets it locally. It forgets
  the local copy even when the dispatcher could not be reached, so a session that
  cannot be revoked remotely does not stay on this machine.

No credential is ever printed. `login`, `logout`, `run`, `status`, `logs`, `cancel`,
`dispatcher list` and every exported receipt carry endpoints and identifiers only.
A stored credential is presented only to the endpoint it was issued for: selecting
another profile sends that profile's credential or none, and changing a saved
profile's endpoint makes `dbl` refuse the stored credential instead of forwarding it
to the new origin.

A credential belongs to a saved connection and to nothing else. An explicit
`--endpoint URL` selects no saved connection, so it presents no credential and reads
neither `config.json` nor `credentials.json`; commands that name their endpoint,
such as `dbl --endpoint URL version --server`, therefore keep working where there is
no configuration directory to locate at all. Use `--dispatcher NAME`, or the saved
current connection, to send a credential. `login` and `logout` both act on a saved
connection and say so when none is selected.

A session expires after 12 hours and can be revoked at any time. Log in again
with the account-key file created during registration, for example
`dbl --dispatcher PROFILE login --account-key-file ~/.config/debuglet/account-key-PROFILE.txt`.
The CLI does not discover that long-lived credential implicitly. If it is lost,
use the recovery code with `POST /auth/recover` or `pkg/client.Recover`; the CLI
does not yet expose account recovery. A command with an expired session exits 1
and prints the dispatcher's `unauthorized` diagnostic.

## Commands

- `demo` uses the verified installed Linux amd64 payload to start its own wallet-free loopback dispatcher/executor, execute the bundled WASM/TCP measurement, verify the nonce/output/terminal result and clean up. See the [installation guide](../README-install.md). A CLI installed alone through `go install` has no bundled daemon/guest assets and cannot run this command.
- `up` starts an installed local dispatcher and executor and stays in the foreground until Ctrl-C or SIGTERM. It creates configuration and SQLite databases automatically, disables wallet/SCION integration, and listens only on loopback. Default HTTP port is 9000. State defaults to `$XDG_STATE_HOME/debuglet` or `$HOME/.local/state/debuglet`; `--state-dir` selects another directory. Completed results and stored output survive stopping and restarting with the same package. A different package version requires a new state directory. Duplicate use of an active state directory is rejected. JSON mode emits one ready record with `state`, `endpoint`, `executor_id`, and `state_dir`; the same record is written to `environment.json` while running. Ctrl-C stops both child processes and retains the databases. This command does not install a background service or resume interrupted work.
- `service` installs, starts, stops, inspects and removes one managed role instance, as described above. Its JSON report has `operation`, `role`, `name`, `unit`, `version`, `state` (`installed`, `ready`, `started`, `stopped`, `uninstalled`, `not-installed` or `incomplete`), `ready`, `enabled`, `active`, `main_pid`, `state_dir`, `unit_path`, `changed`, and, where they apply, `joined`, `executor_id`, `endpoint`, `restart_required` and `note`. After a stop or an uninstall, `joined` reports a daemon that completed its own shutdown, which is the only thing that permits deleting its state. The report is printed even when the operation failed, because the host's state has to be readable either way.
- `drain` takes one managed role out of service and `--resume` puts it back, as described above. Its JSON report has `operation`, `role`, `name`, `unit`, `outcome` (`drained`, `paused`, `resumed`, `started` or `incomplete`), `joined`, `enabled`, `active`, `state_dir`, `changed`, `note` and, after a joined executor drain, a `disposition` object counting `retained`, `queued`, `started`, `quarantined`, `bindings`, `retained_terminal`, `unsent_terminal` and `rejected_terminal`, plus `truncated` when the retained rows come from more control sessions than were counted, which makes `bindings` alone a lower bound. Only `joined` may be used to decide that state can be deleted, upgraded or rebuilt.
- `nodes` lists executors. JSON is always an array.
- `validate` checks a workload without contacting a dispatcher. It reads the same bundled `hello` sample or regular WASM file accepted by `run`, bounds the read at 24 MiB, parses the module with the executor's WASM parser, and applies the SDK `Prepare` resource and envelope rules. Allowlist entries must be bare, unscoped IP addresses or syntactically valid DNS names; absolute DNS names with one trailing dot are accepted. Ports belong in guest arguments. Validation checks syntax only and performs no DNS lookup. A successful result reports the resolved local inputs and sizes, but does not claim that the module will execute, uses a particular ABI, or is supported by a selected executor. Invalid human output names the field on stderr. JSON output emits one object with `valid` and a `diagnostics` array containing stable `field` and `message` values. Validation creates no intent and sends no request.
- `run` submits one job (order ID 0). Local options are validated before requesting an intent: nonblank executor selection (default `auto`) and exactly one of a file or `--sample hello`, `--duration` at least 1 ms and a whole number of milliseconds, nonnegative floor/ceil with floor ≤ ceil, guest arguments only after `--`. Bandwidth flags use bits per second. `--wasm` requires a regular file, including a symlink resolving to one; FIFOs, devices and directories are rejected before opening. File type/size are checked before and after opening, and reads are limited to 24 MiB. The SDK checks the 32 MiB intent envelope before sending and the actual submission envelope after server metadata is known; that second check may fail after an intent exists. `--allow` is repeatable and only populates the policy's address allowlist; the destination host and port a guest connects to belong in the guest arguments. Omitting `--executor`, or setting `--executor auto`, selects only when exactly one executor is ready; otherwise it fails before requesting an intent. An explicit ID skips discovery. No public destination is added. `--sample hello` reads the hello guest from the verified full installation and requires no compiler; `--wasm` accepts your own compiled guest. `--duration` is the server-side budget; `--timeout` bounds client requests and polling. `--allow-remote-test` is required for TEST submission to a non-loopback endpoint.
- `run --wait` polls the state every 250 ms until `RunStateExited`. An empty error is success (exit 0); a nonempty error is a workload failure (exit 3). Unknown states keep polling. A deadline or Ctrl-C ends the local requests, preserves the known IDs and never sends a cancellation.
- `status ID` prints the reported state; exit 0 also when the state describes a failed job.
- `logs ID` prints one page. Human output writes the exact decoded guest bytes to stdout and cursor/state information to stderr. `--follow` drains pages while more are reported, polls while the job is not terminal, and stops after an observed terminal page has been drained; it covers output visible at that time, not delivery. Cursors must strictly advance; corrupt output or a non-advancing cursor is an explicit failure. JSON follow emits one page per line.
- `cancel ID` retrieves the job's executor and sends the cancellation. Success means the dispatcher acknowledged it; this does not certify remote termination or durable terminal reporting. The current server also acknowledges cancellation of a job that has already finished and never rewrites a recorded terminal result, so `status` afterwards shows the server-reported error (`cancelled via API`, or the earlier exit error) unchanged; `dbl` prints only the acknowledgement and never claims the job stopped. Not-found, refused and other server-reported cancellation errors are failures with exit code 1.
- `login` and `logout` manage the credential of the selected saved connection, as described above. They accept no positional arguments. JSON mode emits `{"dispatcher","endpoint","account","role","expires_at"}` for `login` and `{"dispatcher","endpoint","logged_out"}` for `logout`; neither document carries a credential.
- `version` prints the local build metadata (`module`, `version`, `revision`, `modified`); `--server` adds a `server` object with the dispatcher's separate identities: its configured `version`, the HTTP contract it serves (`api_version`, `api_versions`), the build it came from (`binary_version`, `binary_revision`) and the executor control protocol it speaks (`protocol_version`). A dispatcher written before the contract was versioned fills in `version` only. See the [HTTP API guide](API.md).

## Receipts and JSON shapes

`run` emits exactly one receipt on stdout: `{"id","transaction_id","executor_id","state":"submitted"}`. With `--wait` the receipt is buffered and one final document is emitted instead, adding the observed `state` and `error`; on interruption, deadline or error the latest receipt is emitted once. If the second submission step fails, the receipt carries the known `transaction_id`, no invented `id`, and state `submission_unknown` (the server may have accepted the batch) or `submission_failed` (rejected or failed validation before sending). Unexpected submission 201/202 responses produce `submission_unknown` and exit 1. Before a transaction exists, failures emit no receipt. SDK diagnostics remove recognized credential fields and known auth keys as described in [SDK error handling](SDK.md#reading-results).

`status` prints `{"id","state","error","executor_id"}`, `logs` prints the SDK's log page, `cancel` prints `{"id","acknowledged":true}` (human: `Cancellation acknowledged`), and `nodes` prints the node array.

Role startup JSON is emitted once. Dispatcher fields are `state`, `role`, `name`,
`endpoint`, `grpc_address`, `yamux_address`, and `state_dir`. Executor fields are
`state`, `role`, `name`, `endpoint`, `executor_id`, and `state_dir`. `state` is `ready`;
the same role record lives in its state directory's `ready.json` while active.
`connect` returns a profile with `name`, `endpoint`, `grpc_address`, and
`yamux_address`; `dispatcher list` returns `schema_version`, `current`, and the
`dispatchers` array. Neither carries a credential: credentials live in the separate
`credentials.json`. Stored profiles alone do not establish current reachability, and
a saved profile without a stored credential reaches only the public routes.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command completed: a receipt, an acknowledgement or a query was delivered. Not a statement about workload success. |
| 1 | Transport, API, protocol or local I/O failure |
| 2 | Usage or validation error |
| 3 | `run --wait` observed a terminal workload failure |
| 124 | The client deadline expired |
| 130 | Interrupted by the user |

Diagnostics go to stderr. When a failure happens after a receipt exists, the receipt stays on stdout once and the failure is explained on stderr, so automation does not confuse acknowledged submission with successful execution.
