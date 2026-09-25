# Continuous integration

[The GitHub workflow](../.github/workflows/ci.yml) runs eleven lanes on fresh
GitHub-hosted `ubuntu-24.04` full VMs. It handles pull requests to `main` and
`dev`, pushes to `main` and `dev`, and manual branch dispatches.
Each lane reuses the local command below, the pinned Go toolchain from
[mise.toml](../mise.toml), and container images described in [CI images](ci-images.md).
Results are retained under `.cache/ci/`. The aggregate `required` check passes
only when all eleven lanes succeed; skipped or canceled lanes do not count.

The workflow uses read-only permissions, no repository secrets and no persistent
checkout credential. No self-hosted runners or protected refs are needed to run
it. Maintainers should require `CI / required` in branch protection. See
[CI runners](../deploy/ci/README.md) for the container boundary and kernel proof.

| Lane | Command | Result files |
| --- | --- | --- |
| Tests | `make ci-test` | `.cache/ci/tests.json` |
| Vet | `make ci-vet` | — |
| Formatting | `make ci-fmt` | `.cache/ci/gofmt.txt` |
| Generated sources | `bash scripts/ci-generate.sh check` | `.cache/ci/generation/` |
| Race detector | `make ci-race` | `.cache/ci/race-tests.json` |
| Build | `make ci-build` | `.cache/ci/dist/` |
| Package | `make ci-package` | `.cache/ci/packages/` |
| Demo, compatibility, local | `make ci-demo`, `make ci-compatibility`, `make ci-local` | `.cache/ci/*-tests.json`, `.cache/ci/*-evidence/` |
| Kernel | `make ci-kernel` | `.cache/ci/kernel-tests.json` |

The race, local and kernel lanes need Python 3 for their result checks; the
installed lanes additionally need ordinary GNU command-line tools. Nothing here starts a
service beyond the loopback processes the installed checks own themselves.

## Formatting

`make ci-fmt` lists every tracked Go file that the pinned toolchain's `gofmt`
would rewrite, including generated files, and fails when the list is not empty.
It reads the file list from git, so ignored build and cache directories are
never traversed, and it never rewrites the checkout: fix reported files with

```sh
"$(go env GOROOT)/bin/gofmt" -w $(git ls-files "*.go")
```

The reported paths are also written to `.cache/ci/gofmt.txt`. A checkout without
git history, or Go source `gofmt` cannot parse, fails the lane rather than
passing silently.

## Race detector

`make ci-race` runs the concurrency-sensitive packages once under the race
detector and keeps the Go JSON results in `.cache/ci/race-tests.json`. The
selection is the `CI_RACE_PACKAGES` list in the [Makefile](../Makefile): the
dispatcher registry and fair-share scheduling packages, the control session, the
dispatcher and executor transports, the in-memory scheduler, and the executor
packages that own sockets, WASM hosts and their cleanup. They are explicit
native package roots, so WASI samples are never built or run as host tests.

Budget: at most two package binaries run at a time, each with a five-minute
timeout, and the lane reports its own total test time against a 240-second
budget. Bounding the parallelism matters, because these regressions wait on
lifecycles with fixed deadlines and an oversubscribed machine turns those waits
into failures.

Go reports a package with no test files, and a package whose tests all skipped,
as a success. The lane therefore requires every selected package to report at
least one passing test, rejects unrequested packages, failed or unbuildable
packages, and retained race reports, and lists skipped tests as diagnostics.

The lane is not a full race run. `./internal/executor`,
`./internal/executor/scheduler/sqlite` and `./internal/dispatcher/transport/api`
assert fixed deadlines around restore, recovery and peer registration that are
unreliable under the race detector on a shared machine; they run in
`make ci-test`, and under the race detector with the full manual command in
[CONTRIBUTING.md](../CONTRIBUTING.md). A clean lane shows that the selected
packages were race-free in one bounded run, not that the system is free of
races.
