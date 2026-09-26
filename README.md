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

Build the release candidate from the `main` branch on Linux amd64 with **Go 1.25.11**,
Git, Make, Bash, GNU tar and coreutils (`sha256sum`). Use a clean checkout; the
package records its exact source revision and uses committed eBPF objects, so
building it needs no kernel privileges or eBPF compiler.

```sh
git clone --branch main https://github.com/netsec-ethz/debuglet.git
cd debuglet
make ci-build
make ci-package
(
  set -eu
  cd .cache/ci/packages
  sha256sum --check SHA256SUMS
  set -- debuglet-v*-linux-amd64.tar.gz
  [ "$#" -eq 1 ]
  [ -f "$1" ]
  version=${1#debuglet-}; version=${version%-linux-amd64.tar.gz}
  sh ./install.sh --archive "$1" --checksums ./SHA256SUMS \
    --version "$version" --prefix "$HOME/.local"
)
```

The CLI is installed under `$HOME/.local/bin`, with its package under
`$HOME/.local/lib/debuglet`. Copying the three package files to another Linux
amd64 machine supports installation there without Go or a source checkout.
The [installation guide](README-install.md) covers offline installation and
version-pinned release downloads. The `v0.2.0-rc.3` package is the current release
candidate for this workflow; `v0.1.0` predates it.

```sh
export PATH="$HOME/.local/bin:$PATH"
dbl demo
```

`demo` starts a temporary local dispatcher and executor, runs a real WASM/TCP
measurement, checks the result, and cleans up. No existing service is required.
Successful human output begins with `Debuglet VERSION completed locally:` and
ends with `Cleanup: complete`; JSON output also records `RunStateExited`.

## Start roles independently

Start a dispatcher in one terminal:

```sh
dbl dispatcher up
```

It creates its configuration and database and prints a dispatcher URL. In a
second terminal, start an executor using that URL:

```sh
dbl executor up --dispatcher http://127.0.0.1:9000
```

The executor discovers the connection details, registers, and reports when it is
ready. In a third terminal, connect the client and send a job:

```sh
dbl connect http://127.0.0.1:9000 --name local
dbl dispatcher list
dbl executor list
dbl run --sample hello --wait
dbl logs <id-from-the-run-receipt>
```

The client saves the connection. `--sample hello` needs no compiler or wallet.
When exactly one executor is ready, `run` selects it; with several, use
`--executor ID`. Press Ctrl-C to stop a foreground role. Same-package restarts
retain its identity, completed results and output, but do not resume interrupted
measurements.

See the [CLI guide](docs/CLI.md) for multiple roles, state paths, validation,
services and drain operations. The [architecture guide](docs/ARCHITECTURE.md#run-flow)
shows how submission, execution, output and completion travel through the system.

## Credentials

No login is needed for the local roles above. The configuration they generate sets
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
make wasm SAMPLE_DIR=local/wasm_samples/go/hello-local
dbl run --wasm local/wasm_samples/go/hello-local/debuglet.wasm --wait
```

Replace the sample with your own guest. Go guests compile for
`GOOS=wasip1 GOARCH=wasm` and import `github.com/netsec-ethz/debuglet/pkg/debuglet`
when they need Debuglet's network operations. See the [WASM samples](local/wasm_samples/README.md).

For an application that submits measurements and reads results, use the native
[`pkg/client` SDK](docs/SDK.md). With a dispatcher and executor still running, this complete example
submits the guest you just built and prints its output:

```sh
go run -mod=readonly ./examples/client --wasm local/wasm_samples/go/hello-local/debuglet.wasm
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
  [Stored state](docs/environments.md#stored-state), never automatically.

The [threat model](docs/SECURITY.md) states which actors and trust boundaries the
supported profile assumes, what it promises and what it does not, and why a
session token, a packet tag, a live control lease or completed local cleanup is
not proof of identity, remote completion or non-repudiation.

[SECURITY.md](SECURITY.md) states the supported versions and how to arrange private
vulnerability reporting.

## License

[Apache License 2.0](LICENSE). Existing copyright notices are retained.
