# Install Debuglet

Use Linux amd64 and the exact package version recommended by your dispatcher
operator. For executor enrollment, managed services, and the local demo, choose
the **full bundle**. The CLI-only and daemon-only packages do not provide that
complete setup flow.

The current executor setup flow requires a newer package than the published,
unsigned v0.2.0 release. Until a compatible signed release is published, your
operator must supply a private development candidate. A development candidate
is not a public release and has no GitHub release download URL.

## Install a private development candidate

No source checkout or compiler is required. Obtain these files, the exact
candidate version, and its full source revision through your operator's trusted
channel:

- A trusted standalone copy of `bootstrap.sh` from the candidate source.
- `debuglet-VERSION-linux-amd64.tar.gz`, `install.sh`, and `SHA256SUMS`, kept
  together in one local directory with their original filenames.

The bootstrap verifies the archive and installer checksums **before executing
the installer**. The installer then verifies the package contents and installed
files. These checks detect changed bytes; an unsigned candidate does not
authenticate its publisher. Trust in both the bootstrap and the candidate comes
from the channel through which your operator supplies them.

Set the exact values supplied by your operator. `VERSION_PROVIDED_BY_OPERATOR`
below is a placeholder for a version such as `v0.0.0-dev.0123456789ab`; do not
rename an archive or infer its version from an unrelated checkout.

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

Use your actual local paths. Leave `DEBUGLET_COMPONENT` unset for the full
bundle. The command refuses development candidates without a local package
directory and explicit unsigned opt-in. Signature requirements or configured
release trust cannot be overridden by unsigned mode.

Confirm that `dbl version` reports the supplied version and source revision.
The demo needs no service, account, wallet, or root access. Installing the
package does not enroll an executor or create a service account; continue with
[executor setup](docs/operations/executor-onboarding.md), or use
[managed services](docs/operations/services.md) for a system-wide installation.

The installer requires a POSIX shell, GNU tar, and coreutils. Its versioned
files are under `PREFIX/lib/debuglet/VERSION`, and `PREFIX/bin/dbl` selects the
installed bundle. Installing another version does not restart an existing
service; follow the managed-service update procedure.

## Install a signed release

Use this route only after your operator identifies an exact published version
with downloadable signed assets. Obtain the standalone bootstrap and provision
the release signer's trust file independently, as described in
[Signed releases and offline verification](docs/operations/releases.md).
This needs curl, Python 3.11 or later, and OpenSSH with `ssh-keygen -Y` support
in addition to the installer prerequisites.

```sh
DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR \
DEBUGLET_REQUIRE_SIGNATURE=1 \
DEBUGLET_RELEASE_TRUST=/etc/debuglet/release-allowed-signers \
DEBUGLET_RELEASE_SIGNER=releases@debuglet.netsec.ethz.ch \
DEBUGLET_PREFIX="$HOME/.local" \
sh /path/to/trusted/bootstrap.sh
```

Leave `DEBUGLET_RELEASE_DIR` unset for public release downloads. For a signed
offline install, set it to the directory containing the selected package files,
`release.json`, and `release.json.sig`. The bootstrap verifies the signature
before executing the installer and never falls back to unsigned mode.

For the older public demo only, a trusted bootstrap can download the existing
unsigned package with `DEBUGLET_VERSION=v0.2.0 DEBUGLET_ALLOW_UNSIGNED=1 sh
/path/to/trusted/bootstrap.sh`. Leave the component, local-directory and
signature settings unset for that separate legacy invocation. v0.2.0 does not
provide `dbl executor join`.

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

Obtain the selected component's three files and the trusted bootstrap from
your operator, or use the source build directory above. Select the same exact
version as the full bundle:

```sh
DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR \
DEBUGLET_COMPONENT=cli \
DEBUGLET_RELEASE_DIR="$HOME/Downloads/debuglet-candidate/cli" \
DEBUGLET_ALLOW_UNSIGNED=1 \
DEBUGLET_PREFIX="$HOME/.local" \
sh "$HOME/Downloads/bootstrap.sh"
export PATH="$HOME/.local/bin:$PATH"
```

Replace `cli` with `executor` or `dispatcher` and use its matching directory
when needed. Each directory contains its archive, `install-COMPONENT.sh`, and
`SHA256SUMS-COMPONENT`. These filenames are also unique release asset names.
For signed components, use the signed-release command with
`DEBUGLET_COMPONENT` instead of unsigned mode. Role installations share a prefix
safely: upgrading one changes only its own command link. The daemon packages
include their SQLite support and embedded migrations; they do not require
`goose` or `sqlc` at runtime. Daemons still need configuration and a prepared
database; see the operator guide below.

Use the full bundle for `dbl demo`, `dbl up`, `dbl dispatcher up`, `dbl executor up`, and bundled samples. The CLI-only package is for connecting to an existing dispatcher and submitting your own WASM files.

Docker builds use `deploy/docker/debuglet.Dockerfile` targets `cli`, `executor` and `dispatcher` for one component, or `full` for local tools and samples. The local Compose fixture seeds its databases with the full image. With its dispatcher running, client commands use `docker compose run --rm tools --config /state/dbl.toml ...`; the daemon images do not contain `dbl`.

## For operators

For system-wide installation, retention and service management, use [Managed services](docs/operations/services.md). Networked deployments and database upgrades follow the [deployment guide](deploy/README.md).
