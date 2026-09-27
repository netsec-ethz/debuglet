# Install Debuglet

Debuglet releases support Linux amd64. Download the archive, `install.sh`, and `SHA256SUMS` from the [latest release](https://github.com/netsec-ethz/debuglet/releases/latest), then install to your user directory:

```sh
archive=$(printf '%s\n' ./debuglet-*-linux-amd64.tar.gz)
version=${archive#./debuglet-}
version=${version%-linux-amd64.tar.gz}
sh ./install.sh --archive "$archive" --checksums ./SHA256SUMS \
  --version "$version" --prefix "$HOME/.local"
export PATH="$HOME/.local/bin:$PATH"
dbl demo
```

The installer verifies the release files before writing them. It requires a POSIX shell, GNU tar, and coreutils. The demo needs no Go compiler, source checkout, service, account, wallet, or root access.

## Next steps

- Learn the commands in the [CLI reference](docs/CLI.md).
- Run local roles separately with the [Getting Started guide](https://github.com/netsec-ethz/debuglet/wiki/Getting-Started).
- Deploy a dispatcher or executor with the [operations guides](https://github.com/netsec-ethz/debuglet/wiki).

## Build from source

On Linux amd64 with Go 1.25.11, Git, Make, Bash, GNU tar, and coreutils:

```sh
git clone https://github.com/netsec-ethz/debuglet.git
cd debuglet
make ci-build
make ci-package
```

The resulting package is under `.cache/ci/packages/`. Use it with the same installer command above.

## For operators

For offline installs, a system-wide installation, package retention, upgrades, or service management, use the [Deployment and Upgrades guide](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades). Those procedures are deliberately kept in the Wiki because they depend on an operator's environment.
