# Install Debuglet

Debuglet releases support Linux amd64. For the full bundle, download the archive, `install.sh`, and `SHA256SUMS` from the [latest release](https://github.com/netsec-ethz/debuglet/releases/latest), then install to your user directory:

```sh
archive=$(printf '%s\n' ./debuglet-v*-linux-amd64.tar.gz)
version=${archive#./debuglet-}
version=${version%-linux-amd64.tar.gz}
sh ./install.sh --archive "$archive" --checksums ./SHA256SUMS \
  --version "$version" --prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
dbl demo
```

The installer verifies the release files before writing them. It requires a POSIX shell, GNU tar, and coreutils. The demo needs no Go compiler, source checkout, service, account, wallet, or root access.

## Supported platforms

| Platform | `dbl` client | Dispatcher and executor | Bundled demo |
| --- | --- | --- | --- |
| Linux amd64 | Validated native package | Validated for trusted deployments | Validated locally |
| macOS, Intel or Apple Silicon | No native package; Linux amd64 container workflow not yet validated end to end | Not supported natively | Not validated |
| Windows or WSL | Not validated | Not validated | Not validated |
| Linux arm64 or other architectures | No released package; not validated | Not validated | Not validated |

On an unsupported host, use a Linux amd64 machine and run `dbl` there to
connect to your dispatcher. Do not run the Linux installer directly on macOS
or Windows. A source build alone does not establish platform support. See
[Versions and compatibility](docs/versions.md) for the support policy
and the limits of those checks. The [Linux client-container guide](docs/operations/client-container.md)
keeps credentials across container restarts; using it on macOS or Windows does
not establish support for Docker Desktop or emulation there.

## Next steps

- Join an existing dispatcher with [executor setup, including SSH and shell-only instructions](docs/operations/executor-onboarding.md). Use its compatible full bundle; v0.2.0 does not include `dbl executor join`.
- Learn the commands in the [CLI reference](docs/cli.md).
- Return to an account with [re-login and recovery](docs/cli.md#return-to-an-existing-account), or start with [troubleshooting](docs/cli.md#troubleshooting).
- Run local roles separately with the [local-role walkthrough](docs/cli.md#run-local-roles-separately).
- Deploy a dispatcher or executor with the [across-host guide](docs/operations/remote-deployment.md).

## Build from source

On Linux amd64 with Go 1.25.11, Git, Make, Bash, GNU tar, and coreutils:

```sh
git clone https://github.com/netsec-ethz/debuglet.git
cd debuglet
make ci-build
make ci-package
```

The full bundle is under `.cache/ci/packages/`. Use it with the same installer command above. The build also produces the component packages below.

## Install one component

Component packages are available from current source builds and are intended for releases after v0.2.0. The v0.2.0 release contains only the full bundle.

| Audience | Component | Source build directory | Installed command |
| --- | --- | --- | --- |
| Client users | `cli` | `.cache/ci/packages/cli/` | `dbl` |
| Executor operators | `executor` | `.cache/ci/packages/executor/` | `debuglet-executor` |
| Dispatcher operators | `dispatcher` | `.cache/ci/packages/dispatcher/` | `debuglet-dispatcher` |

Choose a component, then run this from the source checkout after building:

```sh
component=cli # or executor or dispatcher
cd ".cache/ci/packages/$component"
archive=$(printf '%s\n' ./debuglet-"$component"-v*-linux-amd64.tar.gz)
version=${archive#./debuglet-$component-}
version=${version%-linux-amd64.tar.gz}
sh "./install-$component.sh" --archive "$archive" \
  --checksums "./SHA256SUMS-$component" --version "$version" --prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
```

Each directory contains only its archive, installer and checksums. These filenames are also unique release asset names. Role installations share a prefix safely: upgrading one changes only its own command link. The daemon packages include their SQLite support and embedded migrations; they do not require `goose` or `sqlc` at runtime. Daemons still need configuration and a prepared database; see the operator guide below.

Use the full bundle for `dbl demo`, `dbl up`, `dbl dispatcher up`, `dbl executor up`, and bundled samples. The CLI-only package is for connecting to an existing dispatcher and submitting your own WASM files.

Docker builds use `deploy/docker/debuglet.Dockerfile` targets `cli`, `executor` and `dispatcher` for one component, or `full` for local tools and samples. The local Compose fixture seeds its databases with the full image. With its dispatcher running, client commands use `docker compose run --rm tools --config /state/dbl.toml ...`; the daemon images do not contain `dbl`.

## For operators

For system-wide installation, retention and service management, use [Managed services](docs/operations/services.md). Networked deployments and database upgrades follow the [deployment guide](deploy/README.md).
