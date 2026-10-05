# Configuration reference

`dbl demo`, `dbl up`, `dbl dispatcher up`, and `dbl executor up` generate safe loopback configuration. This page applies when an operator starts `debuglet-dispatcher` or `debuglet-executor` with `-config FILE`.

## Dispatcher

A networked dispatcher needs a SQLite database path, reachable HTTP and gRPC listeners, and TLS. Keep `server.local_development = false`; the credential-free profile is only for loopback local development. Configure a trusted certificate authority when enrolling executor client certificates.

Optional `[executors."<executor-id>"]` tables label executors with `display_name`, `city`, `country` (ISO 3166-1 alpha-2) and `network` for the executor listing and result provenance; see [executor discovery](executor-discovery.md#vantage-point-metadata).

### Dispatcher attribution history

The dispatcher keeps the history that probe verification needs in its database: every TESLA chain an executor announced (anchor k0, t0, epoch length, disclosure delay, chain length), each disclosed key that verified against its chain, stored once, and the interval and source address of every run. `GET /attribution/candidates` and `GET /attribution/keys` answer from it without an account; see [probe verification](../verification.md). The optional `[attribution]` section sets how long it is kept:

| Key | Unit | Default | Allowed |
| --- | --- | --- | --- |
| `retention_days` | days | 90 | 0 (default) or 1–3,650 |
| `trusted_proxies` | IP addresses or CIDR prefixes | empty | at most 64 |

The dispatcher prunes older records on its expiry loop, at startup and hourly: runs whose interval ended, and keys whose epoch ended, more than one epoch before the cutoff (a lookup at the cutoff lists runs within one epoch of it), and chains with neither left. The cutoff is published as `retained_from`, so a verifier can tell history that is no longer held from a time when no run was active. The history starts when the database is upgraded to schema 14; earlier captures report `missing`. A run's interval is its reserved window, narrowed to the dispatcher's receipt of its exit; the address is the peer the dispatcher observed on the executor's control connection (`ip_source: observed`), or the executor's own claim when none was observed.

The two routes are rate-limited to 10 requests per second, with a burst of 40, per TCP peer address (per /64 for IPv6). By default forwarding headers are not trusted, so behind a reverse proxy all clients share the proxy's allowance. List the proxies in `trusted_proxies` to count clients separately: for a request whose TCP peer is listed, the client is the right-most `X-Forwarded-For` entry that is not itself listed, and a malformed entry falls back to the last listed hop. Configure the proxy to append the peer it saw to `X-Forwarded-For` (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`). A TCP (stream) proxy, such as the rig's `tls-edge` profile, sets no header; rate-limit per client at such a proxy instead.

### Destination limits and opt-outs

An operator account sets the policy of one destination with `PATCH /destination` and lists the current policies with `GET /destinations` ([API](../api.md#destination-policies)). A destination is the exact address string runs declare; no normalization is applied, so a policy for `192.0.2.1` does not cover `192.0.2.1:443` or a hostname.

To honour an opt-out request, deny the destination with a reason, for example `{"destination":"192.0.2.1","denied":true,"reason":"opt-out request from the address owner"}`, optionally with `expires_at` (RFC 3339). Then:

- Every new allocation on the destination is refused, whatever its floor, including a zero floor. A submission naming it can still be accepted and then fails when its executor allocates it.
- The deny is appended to the dispatcher database before it applies, with the operator account as actor, the reason, the time and a revision. Events are never changed or deleted. The dispatcher applies the latest event of every destination again at startup, before any executor connects, so a restart no longer loses it.
- The deny is sent at once to every executor holding an allocation on the destination as a zero limit with the denied flag. `GET /destinations` reports `delivery: confirmed` when every such executor acknowledged it, and `unconfirmed` with the number that did not (refused, unreachable, or a legacy executor that cannot confirm ordered application). The count describes the application in the current dispatcher lifetime; a policy restored at startup has no recipients, because no allocation survives a restart.
- At `expires_at` the expiry loop returns the destination to the default capacity and records an `allow` event with actor `system` and reason `expired`.

What a deny does not do yet: it does not stop traffic that is already running. Executors of this release that received the deny apply the zero limit, which reduces every run on the destination to its admitted floor bandwidth, and keep sending at that floor until the run ends or is cancelled. Closing active connections on the denied flag is a separate executor change. Until it is deployed, cancel the affected runs as well when traffic has to stop before their windows end, and verify the outcome before reporting that traffic has stopped.

## Executor

An executor needs a stable `identity.executor_id`, a private SQLite database, dispatcher control addresses, and TLS credentials for a networked deployment. Run exactly one executor daemon process per database; the raw daemon does not take a cross-process ownership lock. Use the same release as the dispatcher. Choose `packet_counter = "fallback"` unless the host is deliberately configured for eBPF accounting.

The optional `[clock]` section sets `max_error_ms` (default 100, at most 60,000; zero selects the default), the kernel's estimated clock error above which the executor reports and logs its clock readiness as degraded. It does not refuse admission. `dbl doctor --role executor` checks the same bound; see [host probes](executor-discovery.md#host-probes).

### Executor TESLA key schedule

The `[tesla]` section sets the key schedule that attribution tags are made
with. Each chain key k_i signs the packets of one epoch i, and is published
d epochs later so that anyone can verify the tags afterwards.

| Key | Unit | Default | Allowed |
| --- | --- | --- | --- |
| `epoch_seconds` | seconds | 10 (0 selects it) | 0–86,400 |
| `disclosure_delay_epochs` | epochs | 0: the smallest d with d × `epoch_seconds` ≥ 15 minutes (90 at 10 s, 30 at 30 s) | 0, or at least 2 and with (d − 1) × `epoch_seconds` ≥ 10 s, up to 7 days' worth of epochs |
| `chain_length` | epochs | 0: 7 days of epochs | 0–604,800 |
| `seed` | text | empty: random | any |

`delay` is the deprecated name of `epoch_seconds`. It is still read when
`epoch_seconds` is unset, the executor logs a warning when it is used, and
setting both is an error. Despite its name it was never the disclosure delay.

The disclosure delay is a security parameter. A verifier accepts a tag
captured in epoch t with the key of epoch t or t−1, the second to absorb an
executor clock that is up to one epoch behind. The key k_i is published at the
start of epoch i + d. The dispatcher rejects an earlier disclosure and logs it
once as a misbehaving executor. With d = 1, k_{t−1} would already be public
during epoch t, and anyone who had fetched it could forge tags that verify for
packets they timestamp in epoch t. A delay of at least two epochs is
therefore enforced. The margin (d − 1) × `epoch_seconds` must exceed the
verifier's clock tolerance plus the skew between the executor, the dispatcher
and the capture host; an explicit delay is refused below 10 seconds of margin
(the dispatcher's 5-second skew allowance plus the verifier's tolerance), so
at 1-second epochs d is at least 11. The 15-minute default is in the range the
TRACER design uses, far beyond that bound. Tags become verifiable once the
delay has elapsed.

The keys live only in the running executor, and every start builds a new
chain. The keys of the last d epochs before a restart are therefore never
disclosed, and packets tagged in them (the last 15 minutes by default) can
never be verified. (The dispatcher already accepts a disclosure for an earlier
chain it has on record, named by `tesla_key_anchor` on the heartbeat, but the
executor does not yet re-derive and disclose its previous chain's tail.) Stop an executor only once its last attributed packets are
d epochs old. When the chain runs out, the executor logs
`final_disclosure_at`, d − 1 epochs after the expiry, when its last key is
disclosed; restart it after that time.

A kernel tagger holds a key back further while its refresh fails, so a key is
never disclosed while an installed copy can still sign. The schedule and every
disclosed key are published by `GET /attribution/candidates` and `GET
/attribution/keys`. The deprecated `GET /executors/:id/tesla` publishes `epoch_seconds`, `disclosure_delay_epochs`,
`disclosure_delay_seconds` and the time the next key is due
(`next_disclosure_at_ns`). A verifier does not have to derive them.
[`tools/verify_pcap.py`](../../tools/verify_pcap.py) refuses a schedule with d
< 2, and refuses a key that could have been public when the packet was
captured.

### Executor output limits

The optional `[output]` section uses the defaults shown in the [executor example](../../configs/executor/executor.toml): 8 MiB and 65,536 frames emitted per run, 64 MiB queued per executor, 65,536 retained run records, and 1 MiB/s per run with a 64 KiB burst. Zero selects the default. Stdout and stderr share one ordered writer, 16 KiB chunks and a 256 KiB accepted queue. Rate limits apply backpressure; a total-byte or storage limit cancels that guest and marks its accepted output prefix as truncated.

The spool budget charges payload plus 64 bytes per frame and 256 bytes per retained run; it is a logical quota, not an upper bound on SQLite file size or WAL space. Acknowledged payload is released, and a run whose end the dispatcher acknowledged no longer counts against `retained_runs` or the per-run charge. No age-based deletion occurs. Existing data above a lowered cap remains readable; new admission can fail until capacity is raised or an explicit retention policy is applied. A storage write failure can make executor output admission unavailable until restart; a failed finality write stays pending.

The dispatcher's `[output]` section bounds each run with `run_bytes` (8 MiB) and `run_frames` (16,384), plus `account_bytes` (64 MiB) and `node_bytes` (512 MiB), including 64 bytes per frame and 256 bytes per run. `control_reserve_bytes` (16 MiB) preserves advisory SQLite/filesystem headroom for control/final records. Shared deployments require positive aggregate caps; only explicit local TEST configurations may use zero to disable them. Reaching a cap refuses new payload; owner deletion or configured expiry releases its exact charge. See [account admission](account-admission.md) for separate queued-work/request limits and [retention](data-retention.md) for the default of no automatic measurement expiry.

Durable output requires both peers to negotiate output version 1. Retained output may resume over a new control session only with the same still-enrolled TLS certificate and original run binding. Plaintext local sessions and executors without an enrolled certificate cannot resume output across control bindings: when such a session ends, the dispatcher finalizes that output as `truncated` with reason `executor_interrupted` at its committed prefix, and the executor releases its local copy. Workloads themselves are never restarted, and output completion remains separate from the guest's exit status.

## Stored state

State belongs to the service account and contains plaintext secrets. Protect the
whole directory and backups, including SQLite WAL/journal companions, with the
same access controls as the database. A component-only package changes which
binaries are installed; it does not change the state's contents or retention.

| Location | Retained data and lifetime |
| --- | --- |
| Dispatcher `database.path` | Accounts, hashed credentials and sessions, OAuth identities, executor enrollment/ownership, transaction/order records, saved profiles, batch and retry identities, submitted configuration, account reservations, result provenance, cancellation intent, and retained output/finality. Payload expiry is disabled by default; configured expiry or owner deletion retains identity, accounting and verification references. Announced TESLA chains, verified disclosed keys and run intervals follow the separate attribution retention period. |
| Executor `database.path` | Queued workload bytes and policy, original run bindings, retained terminal reports, TESLA chain descriptors and the durable output spool. Completed execution rows can be removed by normal cleanup; interrupted prior-binding rows remain quarantined for inspection and are never automatically resumed. Acknowledged output payload is released according to the output protocol. |
| Role configuration and enrollment directory | Executor identity, configured inline secrets and paths to external TLS credentials. The current TESLA private chain is generated in memory on startup; persisted chain descriptors contain public anchors/schedules, not a recoverable history of private keys. |
| Foreground state directory | Generated configuration, role/package identity, SQLite databases, readiness/shutdown records and rotated daemon logs. Use the same package/source revision; editing recorded metadata is not an upgrade. |
| CLI configuration | Connection profiles and saved credentials in the configured CLI directory. These are separate from daemon state and are excluded from foreground state backups. |
| Dispatcher/executor memory | Live control credentials, leases and current scheduling authority, undisclosed executor TESLA keys. Destination policies are kept in the dispatcher database; the delivery state reported for them is memory only. These do not become durable merely because a database backup exists. Verified disclosed keys also have the dispatcher database record described above. |

See [output limits](#executor-output-limits) for the configured byte, frame and
record budgets, [daemon log retention](services.md#foreground-daemon-logs) for
log rotation, and [recovery inspection](recovery-inspection.md) for retained
interrupted work. Exported [portable results](../results.md) are copies under the
exporter's control; exporting does not delete the server's record.

The [foreground backup/restore procedure](backup-restore.md) supports only its
listed local TEST layouts and matching full package. Direct daemon, systemd,
OAuth, external TLS and SCION state need the deployment's complete backup plan;
a database snapshot alone does not include every required credential or config.
Never start original and restored copies with the same identity simultaneously.

Dispatcher schema 16 and executor schema 6 are the current schema boundaries.
Recognized older databases require the explicit upgrade below. Dispatcher
schemas below 3 and executor schemas below 2 lose recorded `debuglets` and
`debuglet_logs` on upgrade and require explicit acceptance. Preserved paid rows
are not reconciled payment state: migration 4 leaves old earnings without a
payout wallet, and re-registration does not repair it. Keep payments disabled
and retain paid databases and backups for operator reconciliation.

## State and upgrades

Daemons never migrate a database at startup. Back up the dispatcher database, use the release's explicit migration process, and deploy a single reviewed version across the service. An interrupted executor run is not resumed after restart.

### Creating a database

A normal daemon start requires `database.path` to name an existing, supported database. To create a schema without starting any service, use the installed daemon's explicit initialization command as the service account:

```sh
mkdir -m 700 /path/to/new-state
debuglet-dispatcher -init-database /path/to/new-state/dispatcher.db
# On an executor host, use debuglet-executor with the executor database path.
```

The parent must be a real mode-0700 directory owned by that account. Initialization creates a mode-0600 database exclusively and refuses an existing database or SQLite companion file without changing it. It takes an explicit path, reads no runtime configuration, and cannot be combined with other flags. Set the daemon configuration's `database.path` to that file afterward.

Local `dbl` services and the Docker seed service use the same implementation. For Ansible, run `make deploy-build deploy-seed-db`; seed generation uses the daemons from that verified payload, and the roles install a seed only when the host has no database yet. See [deploy/README.md](../../deploy/README.md).

The former goose CLI `make upgrade` and `make downgrade` targets are removed. Use the daemon commands below for explicit upgrades. Rollback means stopping the service and restoring the pre-upgrade database and its matching executable/configuration; it is not an automatic down migration. Never run an older binary against a newer database unless its schema policy explicitly accepts it.

### Upgrading a database

`debuglet-dispatcher -config FILE -check-database` (and the same for `debuglet-executor`) reports whether the configured database is supported by this build, then exits. It only reads the database, so it can run while the daemon serves it, as the file's owner. Its exit status is:

| Status | Meaning |
|---|---|
| 0 | The database is current for this build; there is nothing to upgrade. |
| 3 | The database is outdated, and `-upgrade-database` brings it to this build keeping its data. |
| 4 | The database is outdated, and its upgrade drops the recorded runs and their logs; it needs `-accept-data-loss`. |
| 1 | Any other refusal: the database is absent, unreadable, not this role's, newer than this build, or incompletely migrated. |

To upgrade by hand, stop the daemon, back up the database file together with its `-wal` and `-shm` files when present, and run the new release's daemon with `-config FILE -upgrade-database` as the service account. It takes exclusive SQLite ownership, applies the packaged migrations and checks the result before releasing ownership; another writer cannot interleave between migration commits. A held writer causes a bounded refusal. An idle daemon is not proof of shutdown: stop every process using the database first. On a current database the command changes nothing. An upgrade from a dispatcher schema below version 3 or an executor schema below version 2 drops the tables `debuglets` and `debuglet_logs`, so the runs recorded there and their logs are lost; such an upgrade is refused unless `-accept-data-loss` is given as well. A deployment uses `deploy/ansible/upgrade-database.yml`, which runs these steps on every host and is described in [deploy/README.md](../../deploy/README.md).

Both modes act on the `database.path` of the configuration file given with `-config` and print the absolute path of the database they check or upgrade. A copied local-service directory keeps a `service.toml` whose `database.path` still names the original database, so edit that path, or write a separate configuration, before upgrading a copy. The daemons report the configuration's `server.version` (dispatcher) and `identity.version` (executor), which an upgrade does not change: after a hand-run upgrade, update those fields; a deployment re-renders them with the normal deployment command.

Each upgrade leaves its backup in place. Removing old `backup-*` directories is the operator's decision, after the upgraded service has been verified; a backup of a database with paid state is kept until its reconciliation is complete.

The [configuration examples](../../configs) and [Ansible templates](../../deploy/ansible) are the canonical key-level references. Use the [Wiki](https://github.com/netsec-ethz/debuglet/wiki) for deployment, TLS, and operator procedures.
