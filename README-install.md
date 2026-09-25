# Install Debuglet

Package version: `@VERSION@`

Source revision: `@SOURCE_SHA@`

The markers above are replaced in the copy inside a built package. In a source
checkout, this file is the package documentation template.

This package supports Linux amd64. Installation requires a POSIX shell, GNU tar, coreutils, and `sha256sum`. The installed demo requires no Go compiler, source checkout, wallet, SCION service, root privileges, or existing Debuglet configuration.

## Build a package from source

The alpha is on the `hardening` branch. On Linux amd64, install Go **1.25.11**,
Git, Make, Bash, GNU tar and coreutils, then use a clean checkout:

```sh
git clone --branch hardening https://github.com/netsec-ethz/debuglet.git
cd debuglet
make ci-build
make ci-package
```

The output in `.cache/ci/packages/` contains the three files listed below.
Package creation also verifies an installation of those exact bytes. The
[repository quickstart](https://github.com/netsec-ethz/debuglet/blob/hardening/README.md#install)
shows how to install the result and run the demo. Native builds use committed
eBPF objects and need no privileged kernel access.

## Download a published package

No release package for this alpha is published yet. The existing `v0.1.0` tag
predates it and is not an installation target for these instructions. Use the
source build above until a version with all three assets is available on the
[releases page](https://github.com/netsec-ethz/debuglet/releases).

For a published version, run this from a source checkout, replacing the placeholder
with that release's exact version:

```sh
DEBUGLET_VERSION='<published-version>' sh scripts/bootstrap.sh
```

The bootstrap needs curl in addition to the installer tools. It downloads the
version's archive, installer and checksums from
`https://github.com/netsec-ethz/debuglet/releases/download/VERSION/` over HTTPS, verifies both payloads,
and invokes that installer. No token is needed. Set `DEBUGLET_PREFIX` to change
the default `$HOME/.local` prefix. It does not select a branch, a CI job or a
latest release automatically.

## Offline package installation

Keep these three files from one source package build or one published release together:

- `debuglet-@VERSION@-linux-amd64.tar.gz`
- `install.sh`
- `SHA256SUMS`

In a source checkout this document is a template: replace `@VERSION@` with the version in the archive filename. The copy inside a built archive contains its actual version and source revision. A package built from a branch uses `v0.0.0-dev.<12-character-commit>`; use the filename rather than an unrelated Git tag.

Keep all three files in one directory and verify both downloaded payloads before executing the installer:

```sh
sha256sum --check ./SHA256SUMS
sh ./install.sh --archive ./debuglet-@VERSION@-linux-amd64.tar.gz \
  --checksums ./SHA256SUMS --version @VERSION@ --prefix "$HOME/.local"
"$HOME/.local/bin/dbl" --output json demo
```

## Run the demo

The demo starts a loopback dispatcher and executor, creates fresh private SQLite databases, and runs the bundled WASM guest against a TCP target. It checks the reply, output, and terminal result, then removes its processes and temporary state. It uses userspace traffic accounting.

The CLI link is `$HOME/.local/bin/dbl`; package files live below
`$HOME/.local/lib/debuglet`. Add `$HOME/.local/bin` to `PATH` to use `dbl`
directly. Run `dbl --help` for client commands. The repository contains the
[CLI guide](https://github.com/netsec-ethz/debuglet/blob/hardening/docs/CLI.md)
and [Go client guide](https://github.com/netsec-ethz/debuglet/blob/hardening/docs/SDK.md);
those guides are not additional files in this archive.

## Start a dispatcher, executor and client

After adding the CLI to your path, run the dispatcher in one terminal:

```sh
export PATH="$HOME/.local/bin:$PATH"
dbl dispatcher up
```

In a second terminal, use the URL printed by the dispatcher:

```sh
dbl executor up --dispatcher http://127.0.0.1:9000
```

In a third terminal:

```sh
dbl connect http://127.0.0.1:9000 --name local
dbl dispatcher list
dbl executor list
dbl run --sample hello --wait
dbl logs <id-from-the-run-receipt>
```

No daemon configuration, Go compiler, wallet or credential is needed. The
configuration these commands generate sets `server.local_development`, the
documented profile in which a dispatcher whose listeners are on loopback, with
TLS and payments disabled, serves a request presenting no credential at all as
its own local operator; a credential that is presented is still verified there.
Saved connections live in the user's config directory; `--config FILE` selects
another configuration. A client needs only the dispatcher URL. The executor
obtains both control addresses from that URL and accepts only a local loopback
setup.
Running the dispatcher and executors on separate hosts, with TLS against a
private authority and authentication on, is a different setup: see the
[cross-host quickstart](https://github.com/netsec-ethz/debuglet/blob/hardening/docs/quickstart-remote.md).

Use `executor up --name worker-2 --dispatcher local` for another executor. When
more than one is ready, select one with `run --executor ID`. `dispatcher list`
lists saved profiles; `executor list` lists registrations at the selected
connection. Neither searches for dispatchers elsewhere on the network.

Ctrl-C stops only the role in that terminal. State defaults to
`$XDG_STATE_HOME/debuglet` or `$HOME/.local/state/debuglet`, under
`dispatchers/NAME` and `executors/NAME`; `--state-dir DIR` overrides it. Same-package
restarts retain executor identity, completed results and stored output. A different
package version requires a fresh state directory; interrupted work is not resumed.
These foreground commands install no system service; `dbl service` does that
separately and leaves them unchanged.

`dbl up` still starts a combined dispatcher/executor pair in one terminal. Its
HTTP port defaults to 9000; use `dbl --endpoint http://127.0.0.1:9000 ...` to select
it explicitly. `dbl demo` instead runs a temporary measurement and cleans up.

## Run the roles as services

Managed services cannot execute a package below a home directory because their
systemd units use `ProtectHome=yes`. Install the same verified package under a
system prefix, create the unprivileged service account, and stop any foreground
roles using ports 9000 and 9001 before installing the units:

```sh
sudo sh ./install.sh --archive ./debuglet-@VERSION@-linux-amd64.tar.gz \
  --checksums ./SHA256SUMS --version @VERSION@ --prefix /usr/local
id -u debuglet >/dev/null 2>&1 || \
  sudo useradd --system --home-dir /var/lib/debuglet \
    --shell /usr/sbin/nologin debuglet
sudo /usr/local/bin/dbl service install --role dispatcher
sudo /usr/local/bin/dbl service install --role executor \
  --dispatcher 127.0.0.1:9001
sudo /usr/local/bin/dbl service status --role executor
```

Use the host's equivalent account-management command if it does not provide
`useradd` or `/usr/sbin/nologin`. Each command reports readiness only after the
daemon publishes its own readiness record. Choose other dispatcher ports if an
existing service must keep 9000 or 9001.

`sudo dbl drain --role executor` takes one executor out of service and reports
what it still holds; `sudo dbl drain --role dispatcher` stops the admission of
new submissions without stopping the dispatcher. `sudo dbl drain --resume`
reverses either. The complete profile, paths, permissions, shutdown budget and
drain semantics are in the [environments guide](https://github.com/netsec-ethz/debuglet/blob/hardening/docs/environments.md)
and the [CLI guide](https://github.com/netsec-ethz/debuglet/blob/hardening/docs/CLI.md).

A managed dispatcher is a boot-time service every account on its host can reach,
so its generated configuration leaves `server.local_development` off. It
authenticates every request that is not public, and a client obtains a session
for it once:

```sh
dbl connect http://127.0.0.1:9000 --name managed
dbl --dispatcher managed login --register researcher
```

`login --register` writes the new account's key and recovery code to owner-only
files instead of printing them, and stores only the session, which lasts 12 hours.
After expiry, pass the account-key path printed during registration:

```sh
dbl --dispatcher managed login \
  --account-key-file ~/.config/debuglet/account-key-managed.txt
```

`dbl logout` revokes the session. Account recovery is available through
`POST /auth/recover` and the Go SDK's `Client.Recover`; the CLI does not yet
provide a recovery command.

## Installer behavior

The installer verifies exact package members, permissions, and hashes. It refuses unrelated destination files, symlinks in destination paths, and different bytes at an existing version. Rerunning the same package verifies it and completes an interrupted CLI-link update.

Use trusted shell/coreutils tools and a prefix whose ancestry and contents can be modified only by you, trusted administrators, and cooperating installers. The installer cannot protect directories that another process is allowed to rewrite. Its exclusive `.install.lock` serializes installations. If a forcibly killed installer leaves that lock, first verify that no installer is running, then remove only that stale lock directory before retrying.

Checksums verify identity against the supplied checksum file; obtain that file from the same trusted source as the package. They are not release signatures. The local demo does not establish production isolation, packet-policy enforcement, durable recovery, or payment correctness. Supported upgrades are not provided: a state directory stays with the package version that created it, and moving to another version means a new state directory. The dispatcher does authenticate sessions and authorize every operation against an owning account, but nothing rate-limits registration or login attempts, registration is open to anyone who can reach the port, and the operator role can be granted only on the dispatcher host. Remote testbed compatibility is unconfirmed.
