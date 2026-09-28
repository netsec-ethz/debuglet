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
