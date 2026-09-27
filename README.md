# Debuglet

Debuglet runs small WebAssembly programs for network measurements. A dispatcher
accepts jobs and stores results; executors run the programs with time and bandwidth
budgets. This repository includes the `dbl` CLI, a native Go client SDK, a WASI guest
SDK, and sample measurements.

The local alpha runs on **Linux amd64**. The complete package needs no Go compiler,
wallet, SCION service, root privileges, or hand-written daemon configuration.
The `dbl` client for a remote dispatcher runs on Linux amd64 and, in a container, on
macOS; Windows, WSL and Linux arm64 clients are not supported
([cross-host guide](docs/quickstart-remote.md#clients)).

## Install

Download the current release candidate, verify it and install it under
`$HOME/.local`. This needs only a POSIX shell, curl, GNU tar and coreutils
(`sha256sum`); no Go compiler, Git or source checkout:

```sh
version=v0.2.0-rc.3
base=https://github.com/netsec-ethz/debuglet/releases/download/$version
mkdir debuglet-$version && cd debuglet-$version
for f in debuglet-$version-linux-amd64.tar.gz install.sh SHA256SUMS; do
  curl -fsSLO "$base/$f"
done
sha256sum --check SHA256SUMS
sh ./install.sh --archive ./debuglet-$version-linux-amd64.tar.gz \
  --checksums ./SHA256SUMS --version "$version" --prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
dbl demo
```

`demo` starts a temporary local dispatcher and executor, runs a real WASM/TCP
measurement, checks the result, and cleans up. No existing service is required.
Successful human output begins with `Debuglet VERSION completed locally:` and
ends with `Cleanup: complete`; JSON output also records `RunStateExited`.

The [installation guide](README-install.md) is the reference for everything
after that: offline installation of the same three files, building a package
from source, starting the dispatcher, executor and client separately, and
running the roles as services. Published packages are listed on the
[releases page](https://github.com/netsec-ethz/debuglet/releases); `v0.1.0`
predates this package format.

The [CLI guide](docs/CLI.md) covers multiple roles, state paths, validation,
services and drain operations. The [architecture guide](docs/ARCHITECTURE.md#run-flow)
shows how submission, execution, output and completion travel through the system.

## Credentials

No login is needed for `dbl demo`, `dbl up` or the separately started local roles. The configuration they generate sets
`server.local_development`, the documented profile in which a dispatcher whose
listeners are on loopback, with TLS and payments disabled, serves a request that
presents no credential at all as its own local operator. Every other
configuration — a managed service, and every deployment example — authenticates
each request that is not public and authorizes it against the account that owns
the object. There, register once and obtain a session:

```sh
dbl connect http://127.0.0.1:9000 --name managed
dbl --dispatcher managed login --register researcher
```

The command writes the account key and recovery code to owner-only files beside
the client configuration. A session lasts 12 hours. Log in again with the path
printed during registration, for example:

```sh
dbl --dispatcher managed login \
  --account-key-file ~/.config/debuglet/account-key-managed.txt
```

`dbl logout` revokes the session. If the account key is lost, the recovery code
can replace both credentials through `POST /auth/recover` or `pkg/client.Recover`;
the CLI does not yet expose recovery. The [CLI guide](docs/CLI.md#credentials)
covers credential locations and the [HTTP API guide](docs/API.md)
covers recovery and authorization.

Managed deployments may also expose **Sign in with GitHub** in the browser
console. The dispatcher completes GitHub's authorization-code flow, maps the
GitHub account to a Debuglet account, and issues the same 12-hour session
cookie; GitHub tokens are not retained. Native CLI and SDK clients continue to
use account keys.

## Write a measurement or application

To build a Go measurement, install Go **1.25.11**, clone this repository and run:

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/hello-local
dbl run --wasm examples/debuglets/go/hello-local/debuglet.wasm --wait
```

Replace the sample with your own guest. Go guests compile for
`GOOS=wasip1 GOARCH=wasm` and import `github.com/netsec-ethz/debuglet/pkg/debuglet`
when they need Debuglet's network operations. See the [WASM samples](examples/debuglets/README.md).

For an application that submits measurements and reads results, use the native
[`pkg/client` SDK](docs/SDK.md). With a dispatcher and executor still running, this complete example
submits the guest you just built and prints its output:

```sh
go run -mod=readonly ./examples/client --wasm examples/debuglets/go/hello-local/debuglet.wasm
```

The [CLI guide](docs/CLI.md) covers submission, results, logs, and cancellation.

For a client in another language, the dispatcher publishes its HTTP wire contract as
an OpenAPI document at [`api/openapi.yaml`](api/openapi.yaml), and serves the one it
was built from at `GET /openapi.yaml`. `GET /version` reports the three identities of
a running dispatcher separately: the HTTP contract version it serves, the binary it
was built from, and the executor control protocol it speaks. The
[HTTP API guide](docs/API.md) states how a client selects a contract version and what
may change without a new major version.

## Development

On Linux amd64 with Go **1.25.11**, Git, Make, Bash, GNU tar and coreutils
(plus Python 3 for the test and installed-check targets):

```sh
make ci-test
make ci-vet
make ci-build
make ci-package
make ci-local
```

To build and install a package from a checkout instead of downloading one, see
[Build a package from source](README-install.md#build-a-package-from-source).
Package builds require a clean, committed checkout and use the committed generated
eBPF objects. Output is under `.cache/ci/packages/`. The CI workflow defines checks
for tests, build, packaging, the installed demo, combined and separate local roles,
SDK use, compatibility, and kernel loading. GitHub Actions runs them on fresh
GitHub-hosted Ubuntu 24.04 VMs; see [CI setup](docs/ci.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) for code generation and development details.
The [architecture guide](docs/ARCHITECTURE.md) maps the packages to the running
system, including both control paths and where a given change belongs.

## Current limits

- This alpha uses trusted local Linux processes and TEST payment bookkeeping.
  Wallet and monetary operation are not validated.
- The persistent environment retains stored results; it does not establish durable
  result delivery or recover unknown/interrupted execution outcomes.
- Cancellation acknowledges a request; it does not certify remote termination.
- The HTTP API authenticates a session and authorizes every operation that is not
  public against the owning account or the operator role. What is still open:
  nothing rate-limits account registration or login attempts, registration is
  open to anyone who can reach the port, the operator role can be granted only on
  the dispatcher host, and an executor's identity is bound to an enrolled
  certificate only where `tls.require_client_cert` is set.
- A guest is not isolated from the executor process: it runs under the wazero
  interpreter with no memory ceiling beyond the module's own, no CPU accounting
  and no namespace confinement. A destination that did not ask to be measured is
  protected only by the operator's denial list and the run's declared
  destinations. Keep the alpha in a trusted local environment.
- SCION and remote testbed operation are outside this walkthrough. ETH testbed
  compatibility and deployment are unconfirmed.
- Checksums are not release signatures. A local state directory stays with the
  package version that created it, and moving to another version means a new
  state directory. A deployed daemon's database is upgraded to another package
  version only by the explicit step described in
  [Stored state](docs/configuration.md#stored-state), never automatically.

The [threat model](docs/SECURITY.md) states which actors and trust boundaries the
supported profile assumes, what it promises and what it does not, and why a
session token, a packet tag, a live control lease or completed local cleanup is
not proof of identity, remote completion or non-repudiation.

[SECURITY.md](SECURITY.md) states the supported versions and how to arrange private
vulnerability reporting.

## License

[Apache License 2.0](LICENSE). Existing copyright notices are retained.
