# Contributing

Start with an issue for a bug or proposal, then open a focused pull request. Describe the observable change, compatibility impact, and how a reviewer can verify it.

## Development

Debuglet development and release checks run on Linux amd64 with Go 1.26.10. The usual checks are:

```sh
make ci-fmt
make ci-test
make ci-vet
make ci-build
make ci-package
```

Run the focused package tests while developing. Run the relevant full checks before requesting review. See [CI setup](docs/development/ci.md) for the complete validation matrix.

`make test-fast` runs the native packages in short mode for the editing loop.
`make test` includes their compiler and integration cases. `make coverage`
collects statement coverage, source/generated reports and package timings under
`.cache/ci/coverage/`; the ordinary CI test lane publishes the same reports.
Short mode is not a substitute for the full or race checks before review.

## Generated code

Keep generated output in the same pull request as its source:

- Protocol changes: edit `protocol/protocol.proto`, then run `make proto`.
- SQL changes: edit queries or migrations, then run `make generate-sql`.
- eBPF changes: regenerate its checked-in artifacts and run the kernel checks when available.

## Pull requests

- Keep changes small enough to review.
- Include meaningful tests for behavior changes.
- Update user-facing documentation when behavior changes.
- Do not commit credentials, private keys, local inventory, databases, or build output.
- Use a focused `feature/`, `fix/`, `docs/`, or `chore/` branch and target `main`.

Read [Architecture](docs/architecture.md) to find the relevant subsystem. Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting.

For a concrete extension path, see [adding a built-in workflow
block](docs/development/workflows.md#adding-a-built-in-block). The editor and MCP
share the catalog and compiler, so ordinary blocks do not need separate
implementations for each interface.
