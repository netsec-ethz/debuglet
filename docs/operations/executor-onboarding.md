# Add your executor

Use the console's **Operator → My nodes → Add executor** flow to connect a Linux
machine to a dispatcher that supports account-owned enrollment. Your existing
account owns the machine; it does not need dispatcher administrator privileges.

1. Give the machine a name. It appears as **Awaiting setup** until enrollment.
2. Install the operator's compatible **full** package using the
   [installation guide](../../README-install.md). Set `dbl_cli=/usr/bin/dbl` for
   apt, `dbl_cli=/usr/local/bin/dbl` for system-wide tar, or
   `dbl_cli="$HOME/.local/bin/dbl"` for user-local tar. Confirm
   `"$dbl_cli" --output json version` matches the supplied version and source
   revision. The published v0.2.0 package predates `executor join`.
3. Use the setup values from the console with that selected CLI on the executor
   machine. For a system service, follow [persistent setup](#run-persistently-on-linux)
   instead of this terminal trial:

   ```sh
   "$dbl_cli" executor join --dispatcher https://debuglet.example/api \
     --executor YOUR-EXECUTOR-ID --state-dir ./debuglet-node
   ```

   Add `--host-tag` once per public tag that describes the host, such as
   `--host-tag home --host-tag fibre` (see
   [probe status and tags](executor-discovery.md#probe-status-and-tags)).

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
compatible full bundle. Select `dbl_cli` in that SSH shell as above, then run
`"$dbl_cli" executor join` with the displayed values and paste the token at the
hidden prompt. For a system service, use the canonical
state directory in [persistent setup](#run-persistently-on-linux) from the start.
For a terminal trial or container, run the printed start command and keep its
process and state directory. A container's supervisor is managed separately.

### Without a browser anywhere

For a dispatcher that allows account-key registration, the existing CLI and
HTTP API support the whole setup. Select `dbl_cli` as above; this example also
needs `curl` and `jq` and uses a **publicly trusted HTTPS API**, including its
`/api` prefix if present.
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
"$dbl_cli" --config "$setup_dir/connections.toml" connect "$api" --name operator
"$dbl_cli" --config "$setup_dir/connections.toml" --dispatcher operator login \
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
"$dbl_cli" executor join --dispatcher "$api" --executor "$executor_id" \
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
with `"$dbl_cli" --config "$setup_dir/connections.toml" --dispatcher operator login
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
pass its public CA file to `"$dbl_cli" connect --ca-file /path/to/api-ca.crt`; this
trust is saved for subsequent CLI commands. The `curl --cacert` and
`join --ca-file` options must
trust that API certificate. No account session or recovery file is needed by
the running executor; retain its generated identity and database for later starts.

## Run persistently on Linux

For a Linux amd64 machine with systemd, install the operator's compatible full
package through apt or system-wide tar using the [installation guide](../../README-install.md).
Set `dbl_cli=/usr/bin/dbl` for apt or `dbl_cli=/usr/local/bin/dbl` for tar in this
shell, and check `"$dbl_cli" --output json version`. Use the same selection for
the maintenance commands below; an unqualified `dbl` may select another package.

Apt creates the missing service account and parent directories. **For tar only**,
prepare them before enrollment:

```sh
# Create this account once; omit useradd if debuglet already exists.
sudo useradd --system --user-group --home-dir /var/lib/debuglet --shell /usr/sbin/nologin debuglet
sudo install -d -m 0755 /var/lib/debuglet /var/lib/debuglet/executors
```

For either installation, use this sequence for a **new enrollment**, replacing
the dispatcher URL and executor ID with the supplied values. `worker` is the
local service name; keep it consistent in the state path and service commands.
The new state directory must not already exist:

```sh
sudo "$dbl_cli" executor join --dispatcher https://debuglet.example/api \
  --executor YOUR-EXECUTOR-ID --state-dir /var/lib/debuglet/executors/worker
# Paste the setup token at the hidden prompt. Do not start a foreground daemon.
sudo "$dbl_cli" service install --role executor --name worker \
  --enrolled-state /var/lib/debuglet/executors/worker --start=true --enable=true
sudo "$dbl_cli" service status --role executor --name worker
sudo journalctl -u debuglet-executor-worker.service -n 50 --no-pager
```

Administrator privileges are needed for these setup commands. Service installation
assigns the enrolled files to `debuglet`; the executor itself runs as that account
with `NoNewPrivileges=yes`. Confirm service readiness and **Ready** in My nodes.
New Linux enrollments at this managed path select `packet_counter = "auto"`.
For an enrolled configuration
that explicitly selects `auto`, the unit grants only `CAP_BPF`,
`CAP_PERFMON`, `CAP_NET_ADMIN` and `CAP_NET_RAW`. Separate isolated worker
processes drop those capabilities before executing code; the default trusted
in-process execution shares the daemon process. The parent directories must remain
traversable by that account. Installation enables the
existing managed unit at boot and starts it; readiness is confirmed from the
daemon's own record. The service manager restarts it after an unexpected exit.

`auto` attempts the eBPF counter and falls back only after a clean rollback.
Inspect the node's reported enforcement and tagging modes after startup; starting
a service does not prove eBPF attached or that each run's packets are tagged.
The counter's TCX attachment requires Linux 6.6 or later with the required kernel
support. Older or restricted kernels may use fallback. The documented
[packet-counter limits](executor-discovery.md#packet-counter-limits) still apply.

Some restricted service hosts refuse ambient capabilities before the executor
starts, so `auto` cannot recover from that service-launch error. On such a host,
set `[network] packet_counter = "fallback"` in the saved `service.toml` and repeat
the same service-install command. An enrolled fallback service receives no
capabilities; it may report tagging `none` if raw sockets are unavailable.
No `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE` is granted.

The installer adopts only the exact directory for the selected name:
`/var/lib/debuglet/executors/NAME`. It keeps `service.toml`, `executor.sqlite`,
the private key and both certificate files in place. It validates the existing
TLS identity and database without regenerating them or disabling TLS. Reinstall
the same package with the same `--enrolled-state` option; omitting that option
cannot replace an enrolled configuration with a local profile. Existing enrollment
configurations are never changed to `auto` automatically. To opt an existing
fallback enrollment into eBPF, stop it cleanly, set `packet_counter = "auto"` in
its saved configuration, and reinstall the same package with `--enrolled-state`.
This updates that unit's capability set while preserving the identity and data.

Stop any foreground executor before adoption and keep it stopped throughout
installation. The installer refuses an observed executor using the same
identity, configuration or database. This check does not serialize simultaneous
administrator launches. After adoption, use service commands to run this state.
Existing enrollments in another directory remain usable with their printed
foreground command; this installer does not move them or rewrite their paths.

Normal service uninstall keeps the identity and database for recovery.
See [managed services](services.md)
for stopping, removal and package handling. Back up an enrolled executor by
stopping it cleanly and preserving its entire private state directory; the
foreground TEST backup command does not include enrolled credentials.

To change the package of this enrolled managed executor, follow
[controlled package replacement](services.md#replace-an-enrolled-executors-package).
For apt, start with the [Debian update procedure](debian.md#updates-and-rollback).
It requires a clean joined shutdown, a disabled unit, an offline private backup
and explicit `--replace-package PATH --start=false --enable=false` using a CLI
that supports replacement. It preserves the existing enrollment and service
account; do not obtain another setup token or purge the state to upgrade.

## Restart and recovery

Keep the generated state directory. Restarting with the same configuration,
private key, certificate and database preserves the machine identity and does
not need another setup token. A stopped machine remains in My nodes. For a
managed service, select `dbl_cli` as in [persistent setup](#run-persistently-on-linux)
in this shell, then perform a planned restart with:

```sh
sudo "$dbl_cli" --output json drain --role executor --name worker
# Continue after joined: true and enabled: false.
sudo "$dbl_cli" drain --role executor --name worker --resume
sudo "$dbl_cli" service status --role executor --name worker
```

Check **Ready** in My nodes afterward. Do not use Set up again for an ordinary
restart or package upgrade.

Setup tokens expire after 24 hours and are shown only when issued. If setup did
not finish, use **Set up again** to get a new token. Issuing it invalidates any
unused older token but leaves the existing machine connected. Completing setup
with the replacement token replaces its certificate binding: the old machine
can no longer renew its control lease. Stop the old executor before replacement.
An existing connected status alone does not confirm a replacement machine.

If a response was lost or writing the local state failed, obtain a fresh token
and use a new private state directory. `join` refuses to overwrite an existing
identity. Never put a setup token in a command argument, URL or shared log.

## Renew a managed executor's certificate

Enrollment certificates last at most 90 days, bounded by the issuer's expiry.
Renewal is manual. Before expiry, use a full package with `executor join --renew`
and select `dbl_cli` as in [persistent setup](#run-persistently-on-linux). Keep
the same managed executor ID and state directory. This operation uses
a fresh **Set up again** token from the existing node; it retains the private key,
configuration, database, native trust, service account and installed package.
It replaces only `executor.crt`. Do not create another node or move its state.

1. Drain the service and require `joined: true` and `enabled: false`:

   ```sh
   sudo "$dbl_cli" --output json drain --role executor --name worker
   ```

2. Keep other administrators, automation and foreground executors from starting
   this instance during renewal. Take a private offline backup of its full state
   directory. In My nodes, choose **Set up again** for this same executor, then
   run the renewal command and paste the fresh token at the hidden prompt:

   ```sh
   sudo "$dbl_cli" executor join --renew \
     --dispatcher https://debuglet.example/api --executor YOUR-EXECUTOR-ID \
     --state-dir /var/lib/debuglet/executors/worker
   ```

   Add `--ca-file` only if the HTTPS enrollment API needs a private CA. A private
   `--token-file` also works; remove it after success. Do not add capacity or host
   tag flags: renewal preserves the existing configuration.

3. After the CLI reports successful certificate renewal, resume and inspect it:

   ```sh
   sudo "$dbl_cli" drain --role executor --name worker --resume
   sudo "$dbl_cli" service status --role executor --name worker
   ```

The service stays stopped and disabled until you resume it. An expired old
certificate can be renewed with this same procedure after a clean joined stop.
A failed or uncertain request may already have consumed the token and replaced
the dispatcher's binding. Keep the service stopped, get a fresh **Set up again**
token, and repeat the exact `--renew` command. Do not restore the old certificate
and assume its binding still works. The command preserves local state on refusal;
a filesystem error after atomic publication can leave the new certificate in
place, so an uncertain result still needs this retry procedure.

The command refuses changed native endpoints, a new certificate outside the
retained native trust, a changed executor ID, a modified unit, or a service that
has not shut down cleanly. Ask the service operator for recovery if the issuer
or endpoints changed, the key is lost, or shutdown cannot be confirmed. This
renewal option requires an installed canonical managed service; foreground
trial directories are not automatically converted or renewed.

## Enable enrollment on a dispatcher

Self-service enrollment is disabled by default. It requires native TLS with
client certificates, an explicitly configured certificate issuer and public
connection addresses. Back up and upgrade an existing dispatcher database using
the release's normal database upgrade procedure before starting the new binary.
The dispatcher requires a database schema supported by the selected package even
if enrollment remains disabled. Check the existing database with that package's
`debuglet-dispatcher -config /path/to/dispatcher.toml -check-database` command;
an incompatible schema is refused with the explicit upgrade instructions.
A source merge does not migrate the running service. Schedule deployment
separately: preserve the current package, configuration and a consistent database
backup; stop the dispatcher; run the selected package's explicit database upgrade;
then start that same package and verify existing executors and measurements.
Rolling back requires restoring the matching backup and package, not only the
old binary. See the [deployment procedures](../../deploy/README.md).

Client-certificate enforcement binds each executor ID to the SHA-256
fingerprint of one certificate, and refuses an executor without a binding even
when its certificate is trusted. Before enabling it, confirm that every
existing executor presents a certificate trusted by the retained client CA
bundle and is bound to that certificate: an administrator-issued certificate
with `debuglet-dispatcher -bind-executor EXECUTOR_UUID -bind-certificate
client.crt`, or a token from `-enroll-executor`. The Ansible deployment binds
its inventory executors automatically before it enables enforcement, and
re-binds a certificate it reissues (see "Requiring client certificates" in
the [deployment procedures](../../deploy/README.md)). Replacing the trust
bundle, or enabling enforcement for uncertified or unbound executors, will
disconnect them. Keep enrollment disabled until this prerequisite and both
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
bounded by issuer expiry. Use the [managed renewal procedure](#renew-a-managed-executors-certificate)
before its certificate expires; automatic certificate renewal is not provided.
Existing host-administered enrollment remains available.

The new routes require API 1.10. Each account can create at most ten executors;
their names and inventory are scoped to that account. Existing executors enrolled
through host administration are not automatically claimed by console accounts.
This flow does not enable payments, payouts or earnings reporting. The service's
supported workload and containment limits still apply to machines that join it.

## Public name and location

In **My nodes**, edit a node's public display name, city, country and network.
These labels are owner assertions, not verified host observations. Country is an
uppercase ISO 3166-1 alpha-2 code (for example `CH`); other fields accept up to 64
printable characters. Clear a field to remove your value. The private registration
name remains unchanged. Dispatcher-configured values override your corresponding
fields and carry source `operator`; your remaining values carry source `owner`.
Edits survive dispatcher and executor restarts and affect new result snapshots.

Deployment operators can label nodes outside the inventory with
`dispatcher_executor_labels`, keyed by executor ID, in their deployment variables.
These entries merge with inventory labels, with explicit dictionary fields taking
precedence. Configuration updates preserve them through normal template rendering.

The join command offers `--capacity BITS_PER_SECOND` (default `10000000`). Choose
a sustainable host and uplink limit. New Linux enrollments at the canonical managed
service path use `auto`; other state paths use `fallback`.
Check the node's reported capabilities after starting it. Fallback userspace
tagging covers IPv4 UDP/ICMP only when raw sockets are permitted; TCP/TLS remain
untagged.
