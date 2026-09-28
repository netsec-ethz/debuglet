# Monitoring and response

The checked-in [Prometheus configuration](../../deploy/monitoring/prometheus.yml.example)
and [alert rules](../../deploy/monitoring/alerts.yml) provide an initial availability
alert. They need an existing Prometheus instance and an operator responsible for
its notifications. The files do not install a monitoring service, configure a
notification destination or grant anyone access to Debuglet.

## Configure a collector

1. Copy the example and rules into your Prometheus configuration directory.
   Set the actual dispatcher HTTPS address and its trusted CA. Keep the job name
   `debuglet-dispatcher`, which the rules select explicitly.
2. Use a dedicated operator account. Store its session in the file named by
   `authorization.credentials_file`, readable only by the collector identity;
   refresh it before expiry. Never store the token in Git, command-line arguments,
   a target URL or alert labels. An expired or revoked session makes the scrape
   fail and fires the availability alert.
3. Run `promtool check config prometheus.yml` and
   `promtool test rules alerts.test.yml` before reloading. The repository records
   the tested Prometheus version and archive checksum in
   [prometheus-version.env](../../deploy/monitoring/prometheus-version.env).
4. Route `owner=debuglet-operator` to the team's existing on-call destination in
   Alertmanager. The deploying team must choose the actual person or rotation.
   Verify receipt using that system's existing notification test. The local drill
   below verifies firing/resolution, not external message delivery.

Every configured target is evaluated independently. The `absent(up)` condition
also catches a completely missing job. Removing one target from a multi-target
job removes its monitoring; retain and review the intended target inventory.
Prometheus itself needs independent monitoring: it cannot send an alert while
its own process or notification route is down.

## Availability

`DebugletUnavailable` fires when the scrape fails or a required observation is
missing, API admission readiness fails, or no currently eligible executor has
positive advertised bandwidth. It also refuses a control observation more than
45 seconds away from the collector's wall clock. Synchronize those hosts' clocks;
a clock discrepancy is a diagnostic condition, not evidence of readiness.

Defaults are 15-second scrape and evaluation intervals, a five-second scrape
timeout and a 45-second pending period. The conservative observation budget is
**90 seconds after the failure becomes authoritative**. Silent network loss can
first require expiry of the dispatcher's configured control lease (normally
60 seconds); add that lease interval to the failure-to-alert budget. An immediate
control disconnect does not need that grace period. These are initial operating
thresholds, not an availability SLA.

Recovery clears the condition after a successful scrape and rule evaluation
(normally within 30 seconds, allowing the one-second metrics cache). The alert
checks readiness and positive **advertised** capacity before reservations. It is
not proof that a requested bandwidth/window/destination can be admitted.

When it fires:

- Inspect Prometheus's target error first. Distinguish an expired collector
  session or CA/network failure from an unavailable dispatcher.
- Read `/healthz`, `/readyz`, `/health` and authenticated `/metrics`. A live
  dispatcher can have zero eligible executors. Heartbeat telemetry does not
  renew the authority of an expired executor control session.
- On a managed host run `dbl --output json service status --role dispatcher`
  and the corresponding executor status. For a foreground role, inspect its
  launcher and daemon log in that role's state directory.
- With the operator CLI installed, run
  `dbl --endpoint https://dispatcher.example --timeout 10s --output json doctor --connection`.
  On the daemon host, run
  `dbl --output json doctor --role executor --file /etc/debuglet/executor/executor.toml`
  as the service identity. Check configuration, permissions, available storage
  and capability mode. Doctor's invoking process is not proof that a differently
  sandboxed service has the same permissions. Do not add `--offline` to a running
  database check: stop its writer first. Releases without `doctor` need the
  operator CLI update before using this part of the runbook.
- Correct the diagnosed configuration, credential, resource or transport problem,
  then restart/resume only the affected role. Confirm a new available control
  session and positive capacity, and inspect the metrics observation timestamp.
- Inspect retained run states and `debuglet_retained_runs_unknown` afterward.
  Reconnection and alert resolution do not replay lost work or change an unknown
  outcome into success. Resubmit only through the normal application decision.

Do not repair an availability alert by deleting the database, journals, WAL
files, executor identity or active package directory. Keep stopped state and
logs for diagnosis; use the documented upgrade/recovery operations where needed.

## Local drill

Run only in an owned disposable Linux container with its own network namespace;
no host network and no external endpoint. It needs Python 3, a full installed
Debuglet package containing `/metrics` and `debuglet_api_ready`, the pinned
Prometheus executable, and the existing `examples/debuglets/go/loop` guest built
for WASI. It creates new local dispatcher/executor state and an operator session,
scrapes with that session from a private file, submits a running guest, abruptly
stops only verified child daemons and restarts them.

```sh
promtool check rules deploy/monitoring/alerts.yml
promtool test rules deploy/monitoring/alerts.test.yml
GOOS=wasip1 GOARCH=wasm go build -o /tmp/alert-loop.wasm ./examples/debuglets/go/loop
python3 deploy/monitoring/drill.py \
  --install-root /tmp/debuglet-install \
  --prometheus /tmp/prometheus/prometheus \
  --loop-wasm /tmp/alert-loop.wasm
```

The report checks executor control loss while dispatcher liveness remains true,
a dispatcher outage, both alert resolutions within the configured budget, and a
retained nonterminal/unknown result after recovery. The fixture uses the explicit
loopback development profile, not a production TLS deployment. It supplies a real
operator credential but does not validate external provisioning or notification
routing. A successful drill joins children and removes its private state. On
failure it prints the retained private diagnostic directory; remove the owned
container after inspection.

## Storage and backups

Enable [storage-alerts.yml](../../deploy/monitoring/storage-alerts.yml) and the
[backup scrape](../../deploy/monitoring/backup-scrape.yml.example) when operating
the supported offline backup profile. `DebugletStateStorageLow` checks the
**dispatcher's state filesystem**, firing below 10% space available to
unprivileged writes, or when that observation is missing. This does not cover
executor disks, filesystem quotas or inode exhaustion; retain host monitoring
for those. A failed dispatcher scrape is covered by `DebugletUnavailable`.

Backups currently require a clean, joined foreground shutdown and `--offline`.
They do **not** cover running systemd services or independently started daemons.
Use a package providing the installed `dbl backup` command; the wrapper does not
make an unsupported state directory safe to copy. It does not stop services or
schedule backups. Schedule a supported offline maintenance window at least daily
if using the default 24-hour freshness threshold; choose a different documented
threshold when your recovery objective requires one.

Use an existing node_exporter textfile collector on the same host as Prometheus,
listening on loopback. The tested version/checksum is in
[node-exporter-version.env](../../deploy/monitoring/node-exporter-version.env).
Create a dedicated textfile directory owned by the backup identity, readable by
the collector, and not writable by any other user. For example:

```sh
node_exporter --web.listen-address=127.0.0.1:9100 \
  --collector.textfile.directory=/var/lib/debuglet-backup-metrics
python3 deploy/monitoring/backup-metrics.py \
  --dbl /opt/debuglet/bin/dbl --state-dir /srv/debuglet-stopped \
  --destination /srv/backups/debuglet-20260928 \
  --metrics-file /var/lib/debuglet-backup-metrics/backup.prom --offline
```

Choose a **new** destination each time. This configuration monitors one backup
state directory per collector target; do not publish duplicate metric names from
multiple profiles into the same textfile collector. Keep the actual backup directory private;
the `.prom` file contains only fixed numeric outcomes and timestamps, never
credentials, identities or paths. The wrapper serializes its own invocations,
runs the installed command with a five-minute timeout, and accepts success only
after exit zero plus a matching published backup manifest. The installed command
owns SQLite, schema and inventory verification. The wrapper never inspects the
credential payload or treats a directory's mtime as proof of a valid backup.

`DebugletBackupFailed` fires on a failed last completed attempt, missing result,
failed scrape or textfile parsing error. `DebugletBackupStale` fires when there is
no verified backup, its completion is over 24 hours old, or its timestamp is in
the future. Failed or malformed output preserves the previous verified timestamp.
Killing the wrapper cannot advance success; freshness will still expire even if
that abrupt termination prevented recording a completed failure. These are
**last completed attempt** metrics, not proof that a backup is currently running.
Use the same 15-second collection/evaluation and 45-second pending period as the
availability rules; the conservative observation budget is 90 seconds.

When storage or backup alerts fire:

- Inspect collector errors and the last completed result first. Check capacity,
  permissions, quota/inodes, package compatibility and whether the foreground
  writer really joined before invoking backup. Preserve the failed destination
  for diagnosis; retry into a fresh destination.
- Recover space by expanding the filesystem or moving verified, inactive backup
  copies according to retention policy. Never delete the active installation,
  state database, WAL/journal/SHM sidecars, executor identity or an in-progress
  backup to silence an alert.
- Complete a new verified backup. Confirm both backup alerts clear and the
  verified timestamp advances; periodically exercise documented restore into a
  **fresh** state directory. A green backup alert alone is not a restore drill.

For the owned storage drill, provide a dedicated 64 MiB tmpfs at `/pressure`
inside a disposable container (`--tmpfs /pressure:size=64m,mode=700`, no host
network or published ports). Keep Prometheus data outside that tmpfs. The script
refuses non-tmpfs or filesystems over 128 MiB and creates its own state directory.

```sh
python3 -m unittest discover -s deploy/monitoring -p '*_test.py'
promtool test rules deploy/monitoring/storage-alerts.test.yml
python3 deploy/monitoring/storage-drill.py \
  --install-root /tmp/debuglet-install \
  --backup-install-root /tmp/debuglet-backup-install \
  --prometheus /tmp/prometheus/prometheus \
  --node-exporter /tmp/node_exporter/node_exporter --pressure-dir /pressure
```

The two installed roots may be the same version once both capabilities are
included. The drill measures an actual low-space alert, removes only its filler
file, checks a missing-backup alert, makes an installed verified offline backup,
injects a failed attempt using an existing destination, and verifies that a new
successful backup resolves both failure and freshness. Rule tests separately
advance synthetic time to cover expiration and future timestamps. No external
notification delivery is claimed.
