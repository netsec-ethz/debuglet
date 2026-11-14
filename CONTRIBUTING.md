# Contributing

Start with a [bug report or proposal](https://github.com/netsec-ethz/debuglet/issues),
then open a focused pull request against `main`. Describe what changes for a
user, any compatibility impact and how to verify it. Use the
[security policy](SECURITY.md) for private vulnerability reports.

## Develop with Debuglet

| Goal | First working example |
| --- | --- |
| Use the CLI | [Install the full package](README-install.md), run `dbl demo`, then [connect to a dispatcher](docs/cli.md#use-an-account-key-connection). Browser accounts use `dbl login`. |
| Write a measurement with the Go SDK | [Build and run the hello example](docs/debuglets.md#start-from-an-example). Use the [Go client](docs/client.md) to submit from an application. |
| Author through MCP | [Build `dbl-studio`](docs/development/workflow-authoring.md#run-the-editor-locally), then [configure your MCP client](docs/development/workflow-authoring.md#connect-an-mcp-client). The MCP tools build and validate; submit through the console or CLI. |

Use matching source and package versions. `dbl-studio` is source-built and is
not included in the runtime package. TEST examples need no crypto wallet; remote
runs still need an eligible executor and sufficient TEST allowance if enforced.

## Find the code

| Change | Start here |
| --- | --- |
| CLI command | `cmd/dbl/` |
| Public Go client | `pkg/client/` |
| Guest SDK and network operations | `pkg/debuglet/` and `internal/executor/` |
| Workflow blocks and compilation | `pkg/workflow/` |
| Editor build service and MCP | `internal/studio/` and `cmd/dbl-studio/` |
| Admission, scheduling, accounts and stored results | `internal/dispatcher/` |
| Dispatcher/executor protocol | `protocol/protocol.proto` |
| Packages, CI and deployment | `scripts/`, `.github/workflows/` and `deploy/` |
| Web console | [Dashboard repository](https://gitlab.inf.ethz.ch/OU-PERRIG/yimin/debuglet/debuglet-dashboard) |

Read the [architecture](docs/architecture.md) for the component boundaries.
For a first extension, follow [adding a workflow block](docs/development/workflows.md#adding-a-built-in-block):
the visual editor and MCP use the same catalog and compiler.

## Develop and test

Use Ubuntu 24.04 amd64 and Go 1.26.11, as pinned in `go.mod` and `mise.toml`.
Install Git and Make, then:

```sh
git clone https://github.com/netsec-ethz/debuglet.git
cd debuglet
go mod download
make test-fast
```

During development, run the tests for the package you change. `make test-fast`
runs native packages in short mode; `make test` also runs their compiler and
integration cases. Before requesting review, run the relevant checks:

```sh
make ci-fmt
make ci-test
make ci-vet
make ci-build
make ci-package
```

Concurrency changes also need `make ci-race`. Changes to privileged networking
need the isolated Linux kernel lane. [CI setup](docs/development/ci.md) describes
the prerequisites and complete matrix; short tests do not replace these checks.

`make coverage` writes statement-coverage reports and package timings to
`.cache/ci/coverage/`. Handwritten code and generated bindings have separate
reports. Coverage identifies gaps; it is not branch coverage or proof of correctness.

## Keep changes reviewable

- Use a focused `feature/`, `fix/`, `docs/` or `chore/` branch.
- Test observable behavior, including meaningful failure cases.
- Update documentation when user-facing behavior changes.
- Keep generated output with its source: use `make proto` for protocol changes
  and `make generate-sql` for queries or migrations. Follow the
  [generation guide](docs/development/generated-code.md) for checks and eBPF artifacts.
- Keep credentials, private keys, local inventory, databases and build output out of Git.
