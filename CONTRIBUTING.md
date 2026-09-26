# Contributing

Use an issue to describe a bug or proposed change, then open a pull request with the implementation, relevant tests, and updated documentation. Keep changes focused enough to review. Explain observable behavior and any compatibility impact; include commands and results that let another developer verify the change.

## Architecture

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) maps the packages to the running system: the dispatcher and executor processes and their listeners, the direct gRPC and reverse yamux control paths, the life of a run, configuration and storage, the guest ABI, and which focused check applies to a given change.

## Development environment

Use Linux amd64 and Go 1.25.11 for package and integration checks. [mise.toml](mise.toml) pins Go and the generation tools. Ordinary Go development does not require SCION, a wallet, or eBPF privileges.

From a checkout with dependencies accessible:

```sh
make ci-fmt
make ci-test
make ci-vet
make ci-race
```

`ci-fmt` reports every tracked Go file that the pinned toolchain's `gofmt` would rewrite, including generated files, and never rewrites the checkout; fix the reported paths with `"$(go env GOROOT)/bin/gofmt" -w` on those files. `ci-test` runs the native command, internal, public-package, and protocol tests without cached results and with a four-minute timeout per package. JSON results are written to `.cache/ci/tests.json`. WASI examples are built for their target rather than treated as native programs. `ci-race` runs the scheduler, session/transport, registry and owned-cleanup packages under the race detector as a separate required lane; [docs/ci.md](docs/ci.md) describes every lane, its budget and what it deliberately leaves out.

For concurrency changes, run the affected packages under the race detector. A full native run is:

```sh
go test -mod=readonly -race -count=1 -timeout=5m \
  ./cmd/... ./internal/... ./pkg/... ./protocol/...
```

Tests that use listeners, subprocesses, callbacks, or databases must own their resources and finish cleanup on failure paths. Use bounded waits and join active work before deleting its state. Preserve meaningful assertions when fixing a regression; report skipped tests and environment requirements.

To capture a bounded heap profile of the dispatcher destination scheduler's
existing insertion benchmark, run `make memory`. It performs one benchmark
iteration with a 30-second test timeout, verifies that the intended benchmark
actually ran, and writes `benchmarks/dispatcher-resource-mem.out` without changing
tracked source or generating code. Inspect that exact file with `make memory-view`;
the viewer fails with an actionable error if the profile has not been generated.
Set `MEMORY_PROFILE=/path/to/profile.out` on both commands to use another output.

## Builds and installed checks

From a clean, committed checkout on Linux amd64:

```sh
make ci-build
make ci-package
make ci-demo
make ci-compatibility
make ci-local
```

`ci-build` writes native binaries and Go WASM guests to `.cache/ci/dist/`. `ci-package` writes and verifies an installable archive in `.cache/ci/packages/`. The demo, compatibility and local checks use that exact package. `ci-local` also needs Python 3; it exercises the installed combined environment, separately started roles, saved client connections, the Go SDK example and retained results after restart. These targets require the pinned Go toolchain and ordinary GNU command-line tools. Output directories used by an installed check must be fresh; use a separate checkout for independent runs.

A successful compile alone does not prove a guest ran. The installed checks exercise real dispatcher/executor processes, SQLite, and a loopback TCP exchange. See [environment checks](docs/environments.md).

## Generated code

Keep source definitions and generated output together in a pull request:

- SQL queries and migrations: `internal/dispatcher/database/` and `internal/executor/database/`; bindings are generated with the pinned `sqlc` using the root `sqlc.yml`.
- Protocol messages: `protocol/protocol.proto`; bindings are generated with the pinned protocol compiler version and Go plugins.
- eBPF programs: C sources and generated Go/object files in the executor's tagger and rate-limit packages.

```sh
make proto
make generate-sql
```

Both targets run the generators pinned in [mise.toml](mise.toml) through the Go toolchain; no protocol compiler binary is required. `bash scripts/ci-generate.sh check` regenerates both sets into a temporary directory and fails on any difference from the committed sources. See [generated sources](docs/generation.md).

Changes to eBPF C sources additionally require their generation and kernel checks in a suitable Linux environment. Ordinary builds use the committed objects. Avoid regenerating unrelated artifacts merely because a local compiler produces different bytes.

## Kernel checks

`make ci-kernel` runs in an isolated container on a fresh GitHub-hosted `ubuntu-24.04` full VM. The launcher builds the pinned tools image and grants the five capabilities described in [CI runners](deploy/ci/README.md); local reproduction needs an equivalent Linux environment. The lane loads and closes both the tagger and packet counter, compares the kernel's tags with the pure-Go tagger's, attaches the legacy tc filter, sends user-space-tagged datagrams, rejects skipped kernel tests, and separately checks C compilation. Ordinary tests may skip privileged loading when those capabilities are unavailable. The container toolchain is pinned, but the hosted kernel is not.

Load/attach checks do not establish packet-policy enforcement, performance, or production isolation. Do not broaden privileges or claim those properties from a normal test pass.

## Review checklist

- Describe the problem, resulting behavior, and relevant compatibility limits.
- Include targeted regression coverage and applicable CI results.
- Keep generated output, configuration examples, and docs consistent.
- Exclude credentials, private keys, local state, and build outputs.
- Preserve license and copyright notices.

## Branches and CI

Open pull requests against `dev` in [netsec-ethz/debuglet](https://github.com/netsec-ethz/debuglet).
Use a focused feature or fix branch and request review from a project maintainer.
Feature work is integrated through `dev`; release pull requests promote reviewed
changes from `dev` to `main`.

The GitHub workflow runs all eleven validation lanes on fresh GitHub-hosted
`ubuntu-24.04` full VMs, including kernel checks. It handles pull requests to
`main` and `dev`, pushes to `main` and `dev`, and manual branch
dispatches, with read-only permissions and no repository secrets. It needs no
self-hosted runner registration or branch-protection prerequisite. Maintainers
should require the aggregate `CI / required` check and code review before merging;
workflow files do not configure those repository settings. See
[docs/ci.md](docs/ci.md) for commands and retained evidence.

Before merging, review the exact candidate and check that every required lane
ran successfully. Pending, cancelled, skipped or missing checks do not establish
a passing candidate. A green workflow covers only the checks it ran; reviewers
still assess compatibility, supported profiles, generated sources and the
[review checklist](#review-checklist).

## Security reports

Follow [SECURITY.md](SECURITY.md) to arrange a private reporting channel before
sharing vulnerability details. [docs/SECURITY.md](docs/SECURITY.md) states the
trust boundaries a change must not silently widen.
