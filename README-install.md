# Install Debuglet

To create and run experiments, open the [Debuglet console](https://debuglet.netsec.ethz.ch/console/).
You only need a local installation to host an executor, use the CLI/MCP, or run
the local demo.

**Release availability:** v0.2.0 is the latest published release and predates
`dbl executor join`. The current onboarding flow needs a compatible candidate
from your dispatcher operator until the next signed release is published. The
official public apt channel is not live yet. A version tag alone is not a release.

## Supported platforms

The supported package target is **Ubuntu 24.04, Linux amd64**. Current Linux
fixtures cover the CLI, dispatcher, executor and local demo. There are no
validated native packages for macOS, Windows or Linux arm64. Use a supported
Linux machine to connect to the dispatcher from those platforms.

The [client-container guide](docs/operations/client-container.md) preserves
credentials across Linux container restarts; Docker Desktop and architecture
emulation are not validated. See [compatibility](docs/versions.md) for version
and deployment limits.

## Install with apt on Ubuntu 24.04 amd64

Once your operator supplies a published repository, its independently confirmed
OpenPGP fingerprint and exact Debian version, follow the one-time
[repository setup](docs/operations/apt-repository.md#configure-a-client). Then:

```sh
sudo apt-get update
sudo apt-get install debuglet=DEBIAN_VERSION_PROVIDED_BY_OPERATOR
/usr/bin/dbl --output json version
/usr/bin/dbl demo
```

The full package includes the CLI, executor, dispatcher and samples. Installation
creates the `debuglet` system account and parent state directories when missing;
it does not register an account, enroll an executor or start a service.
`/usr/bin/dbl` avoids picking up an older tar installation on `PATH`.

For an existing service, follow the [upgrade procedure](docs/operations/debian.md)
before activation. Apt stages the new payload and retains payloads referenced by
managed services; it does not drain, migrate or restart them for you.

## Install a signed release

Tar installation needs a POSIX shell, GNU tar, coreutils, Python 3.11+, curl and
OpenSSH with `ssh-keygen -Y`. Obtain the bootstrap from a trusted checkout and
provision the [release signing trust](docs/operations/releases.md#production-signer)
independently. Select an exact published version with signed assets:

```sh
DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR \
DEBUGLET_REQUIRE_SIGNATURE=1 \
DEBUGLET_RELEASE_TRUST=/etc/debuglet/release-allowed-signers \
DEBUGLET_RELEASE_SIGNER=releases@debuglet.netsec.ethz.ch \
DEBUGLET_PREFIX="$HOME/.local" \
sh /path/to/trusted/bootstrap.sh
export PATH="$HOME/.local/bin:$PATH"
dbl --output json version
dbl demo
```

Leave `DEBUGLET_ALLOW_UNSIGNED`, `DEBUGLET_COMPONENT` and `DEBUGLET_RELEASE_DIR`
unset for this full online install. Signature failures stop before installer
execution. [Offline installation and verification](docs/operations/releases.md)
use the same trust checks. Tar installation does not create service accounts or
activate services.

## Install a private development candidate

Ask the operator for the exact version/source, trusted `bootstrap.sh`, and the
matching full archive, `install.sh` and `SHA256SUMS`. Keep the three package files
together with their original names. For a local candidate directory:

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

Leave component and signature/trust settings unset. Check the reported version
and source against the operator's values. Checksums detect changed files but
do not authenticate an unsigned publisher. The demo needs no account, wallet,
root access or existing service.

For a system-wide candidate, use `sudo env` with the same variables and
`DEBUGLET_PREFIX=/usr/local`. Follow [persistent executor setup](docs/operations/executor-onboarding.md#run-persistently-on-linux)
for service-account creation and activation. The older public v0.2.0 demo can be
installed with the [explicit legacy procedure](docs/operations/releases.md#explicit-unsigned-legacy-or-development-install);
it does not provide current enrollment.

## Next steps

| What you want to do | Guide |
| --- | --- |
| Join the network, including from an SSH-only host | [Host an executor](docs/operations/executor-onboarding.md) |
| Submit measurements, use device sign-in or recover access | [CLI reference](docs/cli.md) |
| Run or update persistent services | [Managed services](docs/operations/services.md) |
| Operate a dispatcher | [Deployment guide](deploy/README.md) |

## Build from source

On Linux amd64, install Go 1.26.10, Git, Make, Bash, GNU tar, coreutils, Python
3.11+ and `dpkg-deb` (from `dpkg`), then:

```sh
git clone https://github.com/netsec-ethz/debuglet.git
cd debuglet
make ci-build
make ci-package
```

The build prints the archive name under `.cache/ci/packages/`, including its
`v0.0.0-dev.<source-prefix>` version. Install it using the candidate command
above, `DEBUGLET_RELEASE_DIR="$PWD/.cache/ci/packages"` and
`sh scripts/bootstrap.sh`. Other machines need only the trusted bootstrap and
package files, not a compiler or source checkout.

Debian packages are in `.cache/ci/packages/debian/`. The Debian version drops
`v`, changes the prerelease separator to `~` and adds `-1`: for example,
`v1.0.0-rc.1` becomes `1.0.0~rc.1-1`. The separately built console is pinned in
`configs/release-compatibility.json`; packages record that pairing in
`compatibility.json`. See [release preparation](docs/operations/releases.md#prepare-a-release)
for package acceptance and publication.

## Install one component

Use the full bundle for enrollment, managed-service commands, `dbl demo`,
`dbl up` and bundled samples. Component packages are intended for callers who
only need one role; v0.2.0 contains only the full bundle.

| Component | Installed command | Source-build directory |
| --- | --- | --- |
| `cli` | `dbl` | `.cache/ci/packages/cli/` |
| `executor` | `debuglet-executor` | `.cache/ci/packages/executor/` |
| `dispatcher` | `debuglet-dispatcher` | `.cache/ci/packages/dispatcher/` |

Set `DEBUGLET_COMPONENT` in the appropriate bootstrap command. For offline
packages, point `DEBUGLET_RELEASE_DIR` at the component directory with its
archive, `install-COMPONENT.sh` and `SHA256SUMS-COMPONENT`. Components share a
prefix without replacing each other's command links. Daemons include SQLite
support and migrations, but still need configuration and a prepared database.
Docker targets and local Compose use are documented in [deployment](deploy/README.md).

## For operators

Read [managed services](docs/operations/services.md) for installation and service
ownership, and [deployment](deploy/README.md) for configuration and database
upgrades. Publishing a package does not deploy a console or update an existing
executor automatically.
