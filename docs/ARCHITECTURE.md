# Architecture guide

How the running system is put together, where each concern lives, and which check to run after changing it. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first for the toolchain and the build sequence, and [docs/SECURITY.md](SECURITY.md) for what the current profile does and does not enforce.

## Components

| Package | Responsibility |
| --- | --- |
| `cmd/dispatcher`, `cmd/executor` | Daemon entry points: load configuration, open SQLite, bind listeners, own process lifetime and signal handling |
| `cmd/dbl` | The user-facing CLI: saved connections, local roles, submission, results, demo |
| `cmd/user` | A direct exercise tool that drives the HTTP API through `internal/user`; it predates `pkg/client`, sends no credential, and therefore reaches only a dispatcher serving the local development profile |
| `internal/dispatcher` | Executor registry, submission, scheduling decisions, run-state callbacks |
| `internal/dispatcher/transport/api` | HTTP API: routes, handlers, request/response models, session authentication and the per-route authorization decision |
| `internal/dispatcher/transport/rpc` | Dispatcher side of the control plane: gRPC server, yamux acceptor, session ownership, leases, mutation tickets |
| `internal/dispatcher/resource` | Capacity model: bitrates, destination usage, time-range scheduler |
| `internal/dispatcher/database` | Generated SQLite access, migrations, queries |
| `internal/dispatcher/payments` | Payment intents, refunds, payouts; `payments/sui` is the chain backend |
| `internal/dispatcher/tag` | In-memory store of TESLA keys disclosed by executors |
| `internal/executor` | Session and node lifetime, run handling, output pump, control admission |
| `internal/executor/transport/rpc` | Executor side of the control plane: gRPC server served over yamux, direct client, lease renewal |
| `internal/executor/debuglet` | One run: wazero runtime, host module, listeners |
| `internal/executor/debuglet/wasm` | Host function implementations and the guest-visible environment |
| `internal/executor/debuglet/socket` | Socket registry, port manager, connection types |
| `internal/executor/scheduler` | Admission, queueing and persistence of runs (`scheduler/memory`, `scheduler/sqlite`) |
| `internal/executor/ratelimit` | Per-run and per-destination accounting: `ebpf` counter, `fallback` token buckets, `app` limiter |
| `internal/executor/tagger` | IPv4 IPID packet tagging and the `tesla` key schedule |
| `internal/controlsession` | Shared control-session vocabulary: binding, protocol version, lease timing, end causes |
| `internal/controlrpc` | The control-session credential on the wire: metadata keys, constant-time match, token redaction |
| `internal/avl` | Shared AVL tree used by dispatcher fair-share allocation and executor rate limiting |
| `internal/artifact`, `internal/packaging` | Installation manifest, payload hashes, package build and install |
| `internal/acceptance` | Installed-package checks used by `make ci-compatibility` and `make ci-local` |
| `pkg/client` | Native Go HTTP client SDK for the dispatcher API |
| `pkg/debuglet` | Guest-side WASI SDK wrapping the host imports |
| `protocol` | Protobuf definitions and generated gRPC stubs for both services |

## Processes and listeners

A dispatcher binds two TCP listeners in `bindDispatcherListeners` (`cmd/dispatcher/main.go`): the HTTP port (default 9000) and the gRPC port (default 9001). The HTTP port is demultiplexed with `cmux`: HTTP/1.1 and HTTP/2 go to the Echo server that serves `internal/dispatcher/transport/api`, and everything else goes to `BidiServer.ServeYamux`. The gRPC port serves `DispatcherService` through `BidiServer.ServeGRPCListener`. An executor binds no public control port at all; it dials out.

## The two control paths

`protocol/protocol.proto` defines two services, and each travels its own way.

**Direct gRPC — executor calls the dispatcher.** The executor holds a `grpc.ClientConn` to `dispatcher.addr` and calls `DispatcherService`: `BindSession`, `RenewLease`, `Heartbeat`, `Resources`, `DebugletState`, `DebugletAllocate`, `DebugletExit` and the `DebugletStream` bidirectional stream.

```
executor                                           dispatcher :9001
  BidiClient.client ──────── gRPC/TCP ───────────► transport/rpc.server
  (bound_client.go adds control metadata           admitted(), then
   and checks its own lease first)                 DispatcherState callbacks
```

**Reverse yamux — dispatcher calls the executor.** The executor dials `dispatcher.yamux_addr`, becomes the yamux *client* and serves its own gRPC server on that session (`grpcServer.Serve(session)` in `BidiClient.ConnectAndServe`). The dispatcher accepts the connection as the yamux *server* and builds a `grpc.ClientConn` whose dialer opens streams on it (`createExecutorClient`), so it is the gRPC client of `ExecutorService`: `Hello`, `Upload`, `Abort`, `Bandwidth`, `ProbeSession`.

```
dispatcher :9000 (cmux → yamux)                    executor
  BidiServer.handleSession                           BidiClient.ConnectAndServe
  yamux.Server(conn) ──── streams ────────────────►  yamux.Client(conn)
  grpc.NewClient(dialer = session.Open) ──────────►  ExecutorService server
```

Both directions share one identity. `registerExecutor` mints a `controlsession.Binding` (dispatcher incarnation plus session ID) and a 32-byte token, sends them in `Hello` over the reverse stream, and adopts the executor ID the peer returns. The executor stores those credentials and confirms them with `BindSession` on the direct path; the dispatcher activates the session only after that confirmation. Afterwards every call in either direction carries the same four metadata keys, checked by `controlrpc.Read` and `controlrpc.Credentials.Matches` in `internal/controlrpc`, which both transport packages use. `RenewLease` on the direct path makes the dispatcher issue a `ProbeSession` on the reverse path before extending the lease, so a lease is only renewed while both directions work. `Mutation` tickets (`internal/dispatcher/transport/rpc/mutation.go`) keep an admitted callback alive across session replacement, and `SessionOwner` retirement fences a stale incarnation.

## Life of a run

1. `dbl run` or `pkg/client` prepares a batch, calls `PUT /payment/intent` for a transaction ID and auth key, then `PUT /debuglet` with the batch and that key (`pkg/client/prepare.go`, `pkg/client/submit.go`).
2. `Handler.PutDebuglets` validates the transaction, converts each request to a `models.DebugletSpec` and calls `Dispatcher.SubmitDebuglets`.
3. `SubmitDebuglets` validates each spec against executor and destination capacity (`validateDebugletSpec` and `internal/dispatcher/resource/schedule`), admits a mutation on the target executor's session, inserts the rows in one transaction with the owning binding, and uploads to the executor over the reverse stream.
4. `Executor.OnUpload` re-checks the binding and inserts the spec into the scheduler, which persists it (`scheduler/sqlite`) and starts it at its time.
5. `debugletHandler` (`internal/executor/handle_debuglet.go`) allocates on the dispatcher (`DebugletAllocate`), applies the returned bandwidth limits, registers the run, reports `INITIALIZING`, compiles and instantiates the module, opens the output stream, reports `STARTED`, and runs the guest under the policy timeout.
6. Guest stdout and stderr reach the dispatcher through `DebugletStream`: the first frame identifies the run, later frames are appended to `debuglet_logs` after `ownedDebuglet` confirms the run belongs to the streaming session. A stream failure changes no run state and is returned as the stream's error; the stream itself never ends the run.
7. `reportDebugletExit` sends one bounded `DebugletExit`. The dispatcher writes the terminal row; `UpdateDebugletState` never lets an ordinary state overwrite a terminal one.
8. `DELETE /debuglet` reaches `Dispatcher.AbortDebuglet`, which admits a mutation, confirms ownership, calls `Abort` over the reverse stream, and records one local terminal attempt. When that attempt fails, or its outcome cannot be confirmed, after the executor acknowledged the `Abort`, the route answers 500 `internal_error` instead of 204, so a client never takes an unrecorded cancellation for a recorded one. `Executor.OnAbort` cancels through `scheduler.CancelBound`, which rejects a run bound to another session.

## Configuration and state

Both daemons read one TOML file (`-config`), parsed by `internal/dispatcher/config` and `internal/executor/config`; `local/configs/` holds working examples and `deploy/docker/configs/` the container variants. `dbl up`, `dbl dispatcher up` and `dbl executor up` generate configuration and state under the state directory instead (`cmd/dbl/up.go`, `cmd/dbl/role_up.go`). Each daemon owns a SQLite file opened with `SetMaxOpenConns(1)`. Migrations live under `internal/{dispatcher,executor}/database/migrations` and are embedded by `migrations.go`; the daemons do not migrate on startup. `internal/demo/schema.go` applies them with goose for the local roles and the demo, and `make upgrade`/`make downgrade` drive the goose CLI against a source checkout's `.data/` databases. Both daemons can publish a readiness record (`-ready-file`, `internal/readiness`), and a loopback TEST dispatcher also serves `/connection` with its actual listener addresses.

## Guest ABI

A guest is a WASI command module. `Debuglet.registerHostFunctions` registers the `env` host module whose export names are the ABI; `internal/executor/debuglet/wasm/host_functions.go` implements them, and `pkg/debuglet/debuglet_wasip1.go` declares the matching `//go:wasmimport` bindings with a non-WASI stub in `debuglet_stub.go`. `internal/artifact.GuestABI` names the version recorded in an installation manifest. Adding or renaming an import means changing all four places; existing modules link against the export names, so keep them stable.

## Client surfaces

`pkg/client` is the only supported HTTP client; the exception is `cmd/user`, which drives the API with `net/http` through `internal/user`. `cmd/dbl` builds on `pkg/client` and adds saved connections (`internal/connections`), local role supervision and output formatting. `cmd/dbl/commands.go` maps a command name to its implementation and defines the shared exit codes; `cmd/dbl/cli.go` parses global options and holds the usage text. Documented behaviour lives in [docs/CLI.md](CLI.md) and [docs/SDK.md](SDK.md).

## Where to change what

| Change | Files | Check |
| --- | --- | --- |
| An HTTP handler or route | `internal/dispatcher/transport/api/handlers_*.go`, `routes.go`, `api_models.go`, and the route's authorization decision through `auth.go`'s `require*` helpers; mirror the wire shape in `pkg/client` and update [docs/SDK.md](SDK.md) and the access matrix in [docs/API.md](API.md) | `go test ./internal/dispatcher/... ./pkg/client/...`, then `make ci-compatibility` for the installed API path |
| A database query or schema | `internal/{dispatcher,executor}/database/queries/*.sql` and `migrations/`; regenerate with `sqlc generate` and commit the generated `*.sql.go` | `go test ./internal/dispatcher/database/... ./internal/executor/database/...`, then `make ci-test` |
| A guest host import | `internal/executor/debuglet/wasm/host_functions.go`, `registerHostFunctions` in `internal/executor/debuglet/debuglet.go`, `pkg/debuglet/debuglet_wasip1.go` and `debuglet_stub.go` | `go test ./internal/executor/debuglet/... ./pkg/debuglet/...`, then `make ci-local` for an installed guest |
| A CLI command | a new file in `cmd/dbl`, its case in `dispatch` (`commands.go`), the usage text in `cli.go`, and `docs/CLI.md` | `go test ./cmd/dbl/...`, then `make ci-local` |
| A protocol message or RPC | `protocol/protocol.proto`, then `make proto`; both `transport/rpc` packages and both handler sets | `go test ./protocol/... ./internal/...`, then `make ci-test` |
| Control-session semantics | `internal/controlsession`, `internal/controlrpc` and both `transport/rpc` packages together; the wire version is `controlsession.ProtocolVersion` | `go test -race ./internal/controlsession/... ./internal/controlrpc/... ./internal/dispatcher/... ./internal/executor/...` |
| Scheduling or capacity | `internal/dispatcher/resource`, `internal/dispatcher/debuglet_service.go`; the fair-share tree itself is the shared `internal/avl` | `go test ./internal/dispatcher/...`, and `./internal/avl/... ./internal/executor/ratelimit/...` as well when the shared tree changes |
| Rate limiting or tagging | `internal/executor/ratelimit`, `internal/executor/tagger`; C sources need regeneration | `go test ./internal/executor/...`, then the hosted `kernel` CI lane |
| Packaging or installation | `internal/packaging`, `internal/artifact`, `scripts/package.sh`, `scripts/install.sh` | `make ci-build && make ci-package && make ci-demo` |

## Focused checks

`make ci-test` runs the command, internal, public-package and protocol tests with structured output; `make ci-vet` vets the same set. A single package is faster during development: `go test -mod=readonly -count=1 ./internal/executor/debuglet/...`. Concurrency changes need `-race`, and the full native run is in [CONTRIBUTING.md](../CONTRIBUTING.md). The installed checks run in order — `make ci-build`, `ci-package`, `ci-demo`, `ci-compatibility`, `ci-local` — but only `ci-package` produces an archive; `ci-demo`, `ci-compatibility` and `ci-local` each install and exercise that same package; `scripts/ci-*.sh` holds their exact steps and `ci-local.sh` also invokes `ci-roles.sh` for separately started roles. `make ci-kernel` runs in an isolated container on a fresh GitHub-hosted `ubuntu-24.04` VM: it regenerates and loads the eBPF objects and rejects skipped kernel tests. All eleven lanes and their aggregate `required` check use GitHub-hosted VMs; the container toolchain is pinned, while the host kernel can change. To build a sample guest, `make wasm SAMPLE_DIR=local/wasm_samples/<lang>/<sample>`.

## Debugging entry points

Both daemons log through zap at `logging.log_level`, with `json_logs` for machine reading. `dbl --output json` makes every command's result parseable, `dbl logs --follow ID` streams stored output, and `dbl status ID` reports state without implying workload success. `dbl dispatcher up`/`dbl executor up` keep the roles in separate terminals so their logs stay apart, and the readiness record plus `/connection` give the actual bound addresses when ports were chosen by the operating system. Installed checks keep evidence and structured test output under `.cache/ci/`.

## What the code establishes

These four are separate properties and the packages keep them separate; do not let a change blur them.

- **Local cleanup** is what `Session.cleanup`, `debugletOperation` and `WasmEnv.Close` do: close the owned runtime, sockets, listeners, limiter entries and database handles, and join the workers that own them, within `scheduler.CleanupTimeout`. A clean join says the executor released its own resources. It does not say a peer stopped, a destination stopped receiving traffic, or a remote record is consistent.
- **Control-session fencing** is what the binding and the 32-byte token do: one dispatcher incarnation and one session own a run, a stale or replaced session is refused, and a live lease means the reverse path answered a probe. It identifies an incarnation, not a machine or a person.
- **Durable recovery** is not implemented. Rows survive a restart and completed results stay readable, but the executor restores with an eligibility function that rejects every prior binding (`internal/executor/node.go`), so earlier runs are quarantined and counted rather than resumed, and the dispatcher's restore only rebuilds the capacity schedule from recent rows.
- **Authentication** is what `AuthMiddleware` and the `require*` helpers in `internal/dispatcher/transport/api/auth.go` do. `RegisterRoutes` installs the middleware on every route; a request presents a server-issued session token, whose verifier is stored only as a SHA-256 digest and compared in constant time against the row its selector names; each protected handler then demands a caller, the account that owns the object, or the operator role. `POST /auth/login`, `/auth/logout` and `/auth/recover` issue, revoke and replace those credentials, and `dbl login` and `pkg/client`'s `Options.Credential` are the clients. It establishes that the caller holds a credential one account was issued, not who is behind that account. The `server.local_development` profile deliberately serves a request that presents no credential at all as the dispatcher's own local operator, and only where `cmd/dispatcher` also recognises the loopback environment that key describes. See [docs/SECURITY.md](SECURITY.md) for the boundary and [docs/API.md](API.md) for the per-route matrix before writing a claim about who may do what.
