# Install Debuglet

Use Linux amd64, a POSIX shell, GNU tar, and coreutils. Choose the operator's
exact **full bundle** for executor enrollment, managed services, or the local
demo. No source checkout or compiler is needed. The published unsigned v0.2.0
package predates `dbl executor join`; the current enrollment flow requires an
operator-supplied candidate until a compatible signed release is published.

## Install a private development candidate

Obtain a trusted standalone `bootstrap.sh`, the exact version and source
revision, and the matching `debuglet-VERSION-linux-amd64.tar.gz`, `install.sh`,
and `SHA256SUMS` through your operator's trusted channel. Keep those three
package files together with their original names. Replace the version
placeholder below with the supplied `v0.0.0-dev.<source-prefix>` and use your
actual local paths. Candidates require a local directory and explicit unsigned
opt-in; they are not public releases. Checksums are verified before the installer
runs, but do not authenticate an unsigned publisher.

```sh
DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR \
DEBUGLET_RELEASE_DIR="$HOME/Downloads/debuglet-candidate" \
DEBUGLET_ALLOW_UNSIGNED=1 \
DEBUGLET_PREFIX="$HOME/.local" \
sh "$HOME/Downloads/bootstrap.sh"
export PATH="$HOME/.local/bin:$PATH"
dbl --output json version
dbl demo
```

Leave component and signature/trust settings unset for this unsigned full
bundle; unsigned mode cannot override configured signature requirements.
Confirm the reported version and source revision. The demo needs no service,
account, wallet, or root access. Installation does not enroll a node, create a
service account, or restart an existing service; follow [executor
setup](docs/operations/executor-onboarding.md) or [managed
services](docs/operations/services.md) next.

## Install a signed release

Once your operator identifies an exact published version with signed assets,
obtain the trusted standalone bootstrap and provision the signer's trust file
independently using [Signed releases and offline
verification](docs/operations/releases.md). Replace the version placeholder
below and leave unsigned, component and local-directory settings unset. This
route also requires curl, Python 3.11 or later, and OpenSSH with `ssh-keygen -Y`.

```sh
DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR \
DEBUGLET_REQUIRE_SIGNATURE=1 \
DEBUGLET_RELEASE_TRUST=/etc/debuglet/release-allowed-signers \
DEBUGLET_RELEASE_SIGNER=releases@debuglet.netsec.ethz.ch \
DEBUGLET_PREFIX="$HOME/.local" \
sh /path/to/trusted/bootstrap.sh
```

Signature verification precedes installer execution and never falls back to
unsigned mode. For offline use, set `DEBUGLET_RELEASE_DIR` to the package
directory including `release.json` and `release.json.sig`.

For the older public v0.2.0 demo only, use `DEBUGLET_VERSION=v0.2.0
DEBUGLET_ALLOW_UNSIGNED=1 sh /path/to/trusted/bootstrap.sh` with component,
local-directory and signature/trust settings unset.

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

On Linux amd64 with Go 1.26.9, Git, Make, Bash, GNU tar, and coreutils:

```sh
git clone https://github.com/netsec-ethz/debuglet.git
cd debuglet
make ci-build
make ci-package
```

The full bundle is under `.cache/ci/packages/`. The build prints its exact
archive name, including the generated `v0.0.0-dev.<source-prefix>` version. Run
the development-candidate command above with that version,
`DEBUGLET_RELEASE_DIR="$PWD/.cache/ci/packages"`, and `sh scripts/bootstrap.sh`.
For another machine, copy the trusted bootstrap and the three package files;
the source checkout stays on the build machine. The build also produces the
component packages below.

The package output includes `compatibility.json` and
`SHA256SUMS-compatibility`. This separate record identifies the core package,
source revision, API version and OpenAPI digest together with the console
repository and commit selected in `configs/release-compatibility.json`. Review
that selection and the matching acceptance results when preparing a release.
The console remains a separate build and deployment.

## Install one component

Component packages are available from current source builds and are intended for releases after v0.2.0. The v0.2.0 release contains only the full bundle.

| Audience | Component | Source build directory | Installed command |
| --- | --- | --- | --- |
| Client users | `cli` | `.cache/ci/packages/cli/` | `dbl` |
| Executor operators | `executor` | `.cache/ci/packages/executor/` | `debuglet-executor` |
| Dispatcher operators | `dispatcher` | `.cache/ci/packages/dispatcher/` | `debuglet-dispatcher` |

Use either bootstrap invocation above with `DEBUGLET_COMPONENT=cli`,
`executor`, or `dispatcher`. For local packages, point `DEBUGLET_RELEASE_DIR`
to that component's directory containing its archive, `install-COMPONENT.sh`,
and `SHA256SUMS-COMPONENT`. Select the same exact version as the full bundle.
Check the installed command with `--help`; the component packages omit the
bundled demo. Role installations share a prefix safely: upgrading one changes
only its own command link. The daemon packages include their SQLite support
and embedded migrations; they do not require
`goose` or `sqlc` at runtime. Daemons still need configuration and a prepared
database; see the operator guide below.

Use the full bundle for `dbl demo`, `dbl up`, `dbl dispatcher up`, `dbl executor up`, and bundled samples. The CLI-only package is for connecting to an existing dispatcher and submitting your own WASM files.

Docker builds use `deploy/docker/debuglet.Dockerfile` targets `cli`, `executor` and `dispatcher` for one component, or `full` for local tools and samples. The local Compose fixture seeds its databases with the full image. With its dispatcher running, client commands use `docker compose run --rm tools --config /state/dbl.toml ...`; the daemon images do not contain `dbl`.

## For operators

For system-wide installation, retention and service management, use [Managed services](docs/operations/services.md). Networked deployments and database upgrades follow the [deployment guide](deploy/README.md).
