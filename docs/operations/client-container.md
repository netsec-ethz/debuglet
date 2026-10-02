# Run the Linux client in a container

This runs only the client against an existing dispatcher. The full package
also contains daemon binaries and a sample guest, but the commands below do not
start a dispatcher or executor. No privileged container mode or published port
is needed. The supported host is Linux amd64; macOS/Windows Docker Desktop and
Apple Silicon emulation remain unvalidated. See the [platform matrix](../../README-install.md#supported-platforms).

The registration and re-login commands below are for local or legacy account-key
deployments. For a managed browser account, run `dbl login --no-browser` in the
container and approve the printed code using a browser on another machine. See
[browser accounts and CLI access](authentication.md).

## Build the client image

Download the full Linux amd64 archive, `install.sh`, and `SHA256SUMS` for the
same [release](https://github.com/netsec-ethz/debuglet/releases). Put them in an
otherwise empty directory beside this `Dockerfile`:

```dockerfile
FROM debian:bookworm-slim
ARG DEBUGLET_VERSION=v0.2.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl jq
COPY install.sh SHA256SUMS debuglet-${DEBUGLET_VERSION}-linux-amd64.tar.gz /pkg/
RUN sh /pkg/install.sh --archive /pkg/debuglet-${DEBUGLET_VERSION}-linux-amd64.tar.gz --checksums /pkg/SHA256SUMS --version "$DEBUGLET_VERSION" --prefix /opt/debuglet
ENV PATH=/opt/debuglet/bin:$PATH
```

```sh
docker build --platform linux/amd64 --build-arg DEBUGLET_VERSION=v0.2.0 -t debuglet-client .
docker run --rm -it --platform linux/amd64 \
  -v debuglet-client:/root/.config/debuglet debuglet-client sh
```

Use the matching version in the build argument when choosing another package.
`curl` and `jq` are included for the account-recovery procedure below.
For a private dispatcher CA, add these options **before** the image name in
`docker run`: `--mount type=bind,src="$PWD/ca.crt",dst=/run/debuglet-ca.crt,readonly`
and `-e SSL_CERT_FILE=/run/debuglet-ca.crt`. Supply the public CA certificate,
never its private key. The endpoint must match the server certificate.

## Register once, then reuse the volume

Inside the shell, replace the endpoint with your dispatcher's address:

```sh
dbl connect https://dispatcher.example --name research
dbl --dispatcher research login --register researcher
dbl --dispatcher research nodes
dbl --dispatcher research run --sample hello --wait --allow-remote-test
dbl --dispatcher research logs ID
```

Use the run ID printed by `run` in the final command. `--allow-remote-test`
acknowledges TEST bookkeeping on a remote endpoint; it moves no funds.

Exit and repeat the same `docker run` command. `--rm` discarded the container,
but the named volume retained the connection, session, account key and recovery
code. Submit another protected measurement with
`dbl --dispatcher research run --sample hello --wait --allow-remote-test` and read
its logs to verify saved-session access. `nodes` is public and cannot prove this.
After expiry or logout, obtain a new session with:

```sh
dbl --dispatcher research login --account-key-file /root/.config/debuglet/account-key-research.txt
```

Do not repeat registration for the same account. The volume's Linux filesystem
preserves the required `0600` credential-file mode. Protect it and back it up like
the account key; [account recovery](../cli.md#recover-a-lost-account-key) explains
replacement credentials. Before removing the volume, log out to revoke its
session and retain the account key or recovery code elsewhere if still needed.
