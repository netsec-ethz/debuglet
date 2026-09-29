# Add your executor

Use the console's **Operator → My nodes → Add executor** flow to connect a Linux
machine to a dispatcher that supports account-owned enrollment. Your existing
account owns the machine; it does not need dispatcher administrator privileges.

1. Give the machine a name. It appears as **Awaiting setup** until enrollment.
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

The join command first verifies the HTTPS enrollment API. If that API uses a
publicly trusted certificate, use system trust: do not add the private native
control CA as `--ca-file`. Enrollment supplies the CA for the executor's native
connection. If the **API itself** uses a private CA, obtain its public certificate
from the service operator and add `--ca-file /path/to/api-ca.crt`. This option
replaces the API trust store. Never disable certificate verification.

A setup token authorizes one machine identity; it is not an account key and
cannot sign in to the console. For unattended setup, use a private file with
`--token-file FILE`, then remove that file after successful enrollment.

**Awaiting setup** means no machine certificate has been enrolled.
**Offline** means a certificate is enrolled but no ready connection is observed.
**Ready** means the dispatcher currently considers the machine ready. These
states do not certify its geographic location, measurement results or uptime.

## Set up a machine over SSH

The executor needs no browser or graphical desktop. Open the console on your
laptop, create the executor, then SSH into the Linux machine and install the
compatible full bundle. Run its displayed `dbl executor join` command there and
paste the token at the hidden prompt. For a system service, use the canonical
state directory in [persistent setup](#run-persistently-on-linux) from the start.
For a terminal trial or container, run the printed start command and keep its
process and state directory. A container's supervisor is managed separately.

### Without a browser anywhere

For a dispatcher that allows account-key registration, the existing CLI and
HTTP API support the whole setup. This example needs `dbl`, `curl` and `jq` and
uses a **publicly trusted HTTPS API**, including its `/api` prefix if present.
It creates a new ordinary account and one executor; run it once. The private
setup directory keeps keys, recovery data and API responses out of command
arguments. Do not print these files or include them in shared logs.
The final command enrolls a terminal/container executor; for systemd, stop before
`join` and use the persistent-service alternative immediately below the example.

```sh
set -eu
umask 077
api=https://debuglet.example/api
setup_dir="$HOME/debuglet-operator"
mkdir -m 700 "$setup_dir"  # Fails if it exists; do not overwrite saved credentials.
dbl --config "$setup_dir/connections.toml" connect "$api" --name operator
dbl --config "$setup_dir/connections.toml" --dispatcher operator login \
  --register 'Shell operator' --account-key-file "$setup_dir/account-key.txt" \
  --recovery-file "$setup_dir/recovery.txt"

jq -n --rawfile key "$setup_dir/account-key.txt" \
  '{account_key: ($key | rtrimstr("\n") | rtrimstr("\r"))}' > "$setup_dir/login.json"
curl --proto '=https' --fail --silent --show-error \
  -H 'Content-Type: application/json' --data-binary @"$setup_dir/login.json" \
  "$api/auth/login" --output "$setup_dir/session.json"
jq -er '.token | select(type == "string" and length > 0) | "Authorization: Bearer " + .' \
  "$setup_dir/session.json" > "$setup_dir/auth.header"
curl --proto '=https' --fail --silent --show-error \
  -H @"$setup_dir/auth.header" -H 'Content-Type: application/json' \
  --data '{"name":"My executor"}' "$api/operator/executors" \
  --output "$setup_dir/executor.json"
executor_id=$(jq -er '.executor.id' "$setup_dir/executor.json")
jq -er '.token' "$setup_dir/executor.json" > "$setup_dir/setup-token.txt"
dbl executor join --dispatcher "$api" --executor "$executor_id" \
  --state-dir "$HOME/debuglet-node" --token-file "$setup_dir/setup-token.txt"
rm "$setup_dir/setup-token.txt" "$setup_dir/executor.json" "$setup_dir/login.json"
```

Run the start command printed by `join`, then inspect readiness from a second
SSH terminal. Reuse the same `api` and `setup_dir` values there:

```sh
curl --proto '=https' --fail --silent --show-error \
  -H @"$setup_dir/auth.header" "$api/operator/executors" | jq '.executors'
```

The matching executor reports `ready: true` and `status: "online"` when connected.
To install a system service instead, stop before the example's `join` command
and follow [persistent setup](#run-persistently-on-linux), using this executor ID
and `--token-file "$setup_dir/setup-token.txt"` in its privileged join command.
Do not enroll into the trial directory first; the service installer does not
move identities. Remove the setup token and response after enrollment succeeds.

For an existing account, reuse its private directory and replace registration
with `dbl --config "$setup_dir/connections.toml" --dispatcher operator login
--account-key-file "$setup_dir/account-key.txt"`; skip `mkdir` and `--register`.
Do not create another account to restart an executor. An uncertain executor-create
response should be checked with `GET /operator/executors` before repeating it.
Setup tokens expire after 24 hours and are used once.

Keep private backups of the account key and recovery file. After verification,
revoke the temporary API session and remove its local copies:

```sh
curl --proto '=https' --fail --silent --show-error -X POST \
  -H @"$setup_dir/auth.header" "$api/auth/logout" >/dev/null
rm "$setup_dir/session.json" "$setup_dir/auth.header"
```

The CLI's separately saved session remains available. If the service requires
browser OAuth, use its console on another computer and the SSH flow above;
these commands do not implement headless OAuth. For a privately certified API,
install its CA in the machine's system trust store or obtain service-specific
CLI trust instructions. The `curl --cacert` and `join --ca-file` options must
trust that API certificate. No account session or recovery file is needed by
the running executor; retain its generated identity and database for later starts.

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
This build requires dispatcher schema 13 even if enrollment remains disabled.
A source merge does not migrate the running service. Schedule deployment
separately: preserve the current package, configuration and a consistent database
backup; stop the dispatcher; run the selected package's explicit database upgrade;
then start that same package and verify existing executors and measurements.
Rolling back requires restoring the matching backup and package, not only the
old binary. See the [deployment procedures](../../deploy/README.md).

Before enabling client-certificate enforcement, confirm that every existing
executor presents a certificate trusted by the retained client CA bundle.
Replacing that trust bundle or enabling enforcement for uncertified executors
will disconnect them. Keep enrollment disabled until this prerequisite and both
advertised native control endpoints have been verified. Publish a matching full
package and installation guide before enabling the console setup flow.

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
