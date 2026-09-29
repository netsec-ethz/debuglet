# Add your executor

Use the console's **Operator → My nodes → Add executor** flow to connect a Linux
machine to a dispatcher that supports account-owned enrollment. Your existing
account owns the machine; it does not need dispatcher administrator privileges.

1. Give the machine a name. It appears as **Waiting for setup** until enrollment.
2. Install a Debuglet package that provides `dbl executor join`. Use the package
   recommended by the service operator. The published v0.2.0 package predates
   this command.
3. Copy the setup command from the console and run it on the executor machine:

   ```sh
   dbl executor join --dispatcher https://debuglet.example/api \
     --executor YOUR-EXECUTOR-ID --state-dir ./debuglet-node
   ```

4. Paste the one-time setup token when prompted. The command generates the
   machine's private key locally, obtains its certificate, initializes its
   database, and writes its configuration. The private key stays on the machine.
5. Run the start command printed by `join`. Keep that process running. The
   console updates when the dispatcher observes a ready connection.

For a dispatcher with a private CA, obtain its public CA certificate from the
service operator and add `--ca-file /path/to/dispatcher-ca.crt`. Do not disable
certificate verification. A setup token authorizes one machine identity; it is
not an account key and cannot be used to sign in to the console. For unattended
setup, pass a private file with `--token-file FILE`, then remove that token file.

**Waiting for setup** means no machine certificate has been enrolled.
**Offline** means a certificate is enrolled but no ready connection is observed.
**Connected** means the dispatcher currently considers the machine ready. These
states do not certify its geographic location, measurement results or uptime.

## Run persistently on Linux

For a Linux amd64 machine with systemd, download the full package, `install.sh`
and `SHA256SUMS` recommended by the service operator. Use this sequence for a
**new enrollment**, replacing the package version, dispatcher URL and executor
ID with the supplied values:

```sh
DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR
sudo sh ./install.sh --archive "./debuglet-${DEBUGLET_VERSION}-linux-amd64.tar.gz" \
  --checksums ./SHA256SUMS --version "$DEBUGLET_VERSION" --prefix /usr/local
# Create this account once; omit useradd if debuglet already exists.
sudo useradd --system --user-group --home-dir /var/lib/debuglet --shell /usr/sbin/nologin debuglet
sudo install -d -m 0755 /var/lib/debuglet /var/lib/debuglet/executors
sudo /usr/local/bin/dbl executor join --dispatcher https://debuglet.example/api \
  --executor YOUR-EXECUTOR-ID --state-dir /var/lib/debuglet/executors/worker
# Paste the setup token at the hidden prompt. Do not start a foreground daemon.
sudo /usr/local/bin/dbl service install --role executor --name worker \
  --enrolled-state /var/lib/debuglet/executors/worker
sudo /usr/local/bin/dbl service status --role executor --name worker
sudo journalctl -u debuglet-executor-worker.service -n 50 --no-pager
```

Administrator privileges are needed for these setup commands. The executor
itself runs as `debuglet`, with no capabilities and no new privileges. The parent
directories must remain traversable by that account. Installation enables the
existing managed unit at boot and starts it; readiness is confirmed from the
daemon's own record. The service manager restarts it after an unexpected exit.

The installer adopts only the exact directory for the selected name:
`/var/lib/debuglet/executors/NAME`. It keeps `service.toml`, `executor.sqlite`,
the private key and both certificate files in place. It validates the existing
TLS identity and database without regenerating them or disabling TLS. Reinstall
the same package with the same `--enrolled-state` option; omitting that option
cannot replace an enrolled configuration with a local profile.

Stop any foreground executor before adoption and keep it stopped throughout
installation. The installer refuses an observed executor using the same
identity, configuration or database. This check does not serialize simultaneous
administrator launches. After adoption, use service commands to run this state.
Existing enrollments in another directory remain usable with their printed
foreground command; this installer does not move them or rewrite their paths.

For maintenance, use `sudo dbl drain --role executor --name worker` and
`sudo dbl drain --role executor --name worker --resume`. Normal service uninstall
keeps the identity and database for recovery. See [managed services](services.md)
for stopping, removal and package handling. Back up an enrolled executor by
stopping it cleanly and preserving its entire private state directory; the
foreground TEST backup command does not include enrolled credentials.

## Restart and recovery

Keep the generated state directory. Restarting with the same configuration,
private key, certificate and database preserves the machine identity and does
not need another setup token. A stopped machine remains in My nodes.

Setup tokens expire after 24 hours and are shown only when issued. If setup did
not finish, use **Set up again** to get a new token. Issuing it invalidates any
unused older token but leaves the existing machine connected. Completing setup
with the replacement token replaces its certificate binding: the old machine
can no longer renew its control lease. Stop the old executor before replacement.
An existing connected status alone does not confirm a replacement machine.

If a response was lost or writing the local state failed, obtain a fresh token
and use a new private state directory. `join` refuses to overwrite an existing
identity. Never put a setup token in a command argument, URL or shared log.

## Enable enrollment on a dispatcher

Self-service enrollment is disabled by default. It requires native TLS with
client certificates, an explicitly configured certificate issuer and public
connection addresses. Back up and upgrade an existing dispatcher database using
the release's normal database upgrade procedure before starting the new binary.
Configure the existing `[tls]` section with
`require_client_cert = true`; its `ca_file` must trust the enrollment issuer.
Then add:

```toml
[executor_onboarding]
enabled = true
ca_cert = "/etc/debuglet/executor-ca.crt"
ca_key = "/etc/debuglet/executor-ca.key"
dispatcher_url = "https://debuglet.example/api"
grpc_address = "debuglet.example:9001"
yamux_address = "debuglet.example:9000"
```

Protect the issuer private key so only the dispatcher service can read it.
The dispatcher validates this configuration before starting. Use a dedicated
executor issuer whose certificate chain is trusted by the configured client CA;
do not copy a root CA key or a server private key into the console. The browser
never receives an issuer key or an executor private key.

Enrollment issues client authentication certificates for at most 90 days,
bounded by issuer expiry. Renew a machine with **Set up again** before its
certificate expires; automatic certificate renewal is not provided. Existing
host-administered enrollment remains available.

The new routes require API 1.10. Each account can create at most ten executors;
their names and inventory are scoped to that account. Existing executors enrolled
through host administration are not automatically claimed by console accounts.
This flow does not enable payments, payouts or earnings reporting. The service's
supported workload and containment limits still apply to machines that join it.
