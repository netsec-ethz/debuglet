# Operational metrics

The dispatcher serves `GET /metrics` in Prometheus text format. It requires an
operator's session credential, using the same bearer authentication as the API.
An ordinary account receives 403; an unauthenticated request receives 401. The
explicit loopback development profile also permits its local operator. The
public health endpoints retain their separate readiness contract.

Use the dispatcher's existing HTTPS endpoint and trust configuration. For
example, with a valid operator session in `DEBUGLET_SESSION`:

```sh
curl --fail --silent --show-error \
  --header "Authorization: Bearer $DEBUGLET_SESSION" \
  https://dispatcher.example/metrics
```

Configure the collector to supply that session as its bearer credential and
refresh it before expiration. Do not put a session in a URL, a committed scrape
configuration or dashboard. Revoking the operator role or session takes effect
on the next request, even while a metric report is cached.

## Meaning and units

All numeric observations are **gauges**, not lifetime counters. The prefix of
every metric below is `debuglet_`. There are no account, run, executor,
destination, path or free-text error labels.

| Metric | Meaning |
| --- | --- |
| `control_observed_timestamp_seconds` | Unix timestamp at the start of collection. |
| `executors_registered` | Entries in the executor registry. |
| `executors_ready` | Entries whose control session is available for admission. |
| `ready_capacity_bits_per_second` | Sum of their advertised bandwidth, before reservations. This is not uncommitted capacity. |
| `retained_runs_admitted` | Run rows retained in dispatcher storage, including failed uploads and uncertain outcomes. A stored admission is not proof the upload or execution succeeded. |
| `retained_runs_pending` | Pre-start rows with an available binding and an unexpired window. |
| `retained_runs_started` | Started rows with an available binding and an unexpired window. |
| `retained_runs_reported_success` | Terminal rows with no reported error. |
| `retained_runs_reported_error` | Terminal rows with an error, including cancellation; no inference about its cause. |
| `retained_runs_unknown` | Nonterminal rows with an unavailable binding, expired window, unreconciled submission or unknown lifecycle state. |
| `pending_scheduled_start_overdue_seconds` | Largest elapsed time since the scheduled start of a current pending run; zero if none is overdue. This is not time since submission or observed execution start. |
| `process_rss_bytes` | Resident memory of this dispatcher process, from Linux `smaps_rollup`. |
| `process_open_fds` | Open file descriptors of this dispatcher process. |
| `state_available_bytes` | Space available to unprivileged writes on the filesystem containing the dispatcher database, excluding per-user quotas. |
| `state_capacity_bytes` | Total capacity of that filesystem. |

The five retained lifecycle categories partition `retained_runs_admitted`.
Duplicate or stale control reports cannot increment an event counter: the next
scrape reads the same durable rows used by the API, whose guarded transitions
reject those reports. Retention or restoring an older database can reduce these
gauges. Do not calculate admission throughput using `rate()` on them.

A terminal success reports the guest outcome only. It does not certify that all
output reached durable storage. Losing a control session or passing the run's
end time without a terminal report changes its observed outcome to unknown;
neither event invents success or an interruption result.

## Unavailable observations

`debuglet_observation_available{observation="...",reason="..."}` is 1 when its
observation is available and 0 otherwise. `reason` is a fixed product code,
never a database error or host path. Numeric samples are omitted when
unavailable, rather than replaced with zero.

The current durable contract does not record an admission timestamp, actual
start timestamp, allocation timestamp, acknowledged output sequence/finality or
structured interruption reason. Accordingly `queue_age_seconds`,
`start_delay_seconds`, `allocation_age_seconds`, `output_lag_seconds`,
`output_truncated`, `output_complete` and `interrupted_runs` are explicitly
unsupported. The supported scheduled-start overdue gauge does not substitute
for these observations.

Denied traffic, independently verified enforcement, TESLA clock uncertainty,
end-to-end disclosure delivery lag and settlement backlog remain unsupported.
Collection never changes
admission, packet enforcement, terminal state, payment or readiness decisions.

## Executor health

The existing authenticated control reports also provide the following aggregate
gauges. They cover **all registered executors**, including those whose control
session is unavailable. Each `state` label is from the fixed list below; there
are no executor or error-text labels. A mode is the executor's selected packet
counter, not evidence that the kernel still enforces every packet.

| Metric | Meaning |
| --- | --- |
| `executors_enforcement_mode{state="..."}` | Counts for `ebpf`, `fallback` and `unknown`. |
| `executors_counter_attachment{state="..."}` | Counts for `present`, `missing`, `unknown` and `not_required` (a fresh fallback selection). Presence checks both owned TCX links against their interface, hook and loaded program identity. |
| `executor_process_rss_bytes_max` | Largest executor daemon RSS; excludes separate guest worker processes. |
| `executor_process_open_fds_max` | Largest executor daemon descriptor count; excludes guest workers. |
| `executor_state_available_bytes_min` | Least space available to unprivileged writes on any executor database filesystem. |
| `executor_state_capacity_bytes_min` | Smallest such filesystem capacity. |
| `executor_state_available_ratio_min` | Lowest available/capacity ratio, calculated per executor before aggregation. Quotas and inode exhaustion require host monitoring. |
| `executors_attribution_state{state="..."}` | Counts for `available`, `epoch_zero`, `chain_exhausted`, `refresh_failing`, `disclosure_held` and `unknown`. |
| `executors_clock_readiness{state="..."}` | Counts for `ready`, `degraded` and `unknown`, from the kernel clock report and its configured error threshold. |
| `executors_schedule_unknown` | Executors without a usable fresh schedule observation. |
| `executors_schedule_expired` | Announced signing schedules whose expiry has passed on the dispatcher's clock. |
| `executor_schedule_remaining_seconds` | Minimum nonnegative remaining signing lifetime, using the announced start, epoch length and chain length on the dispatcher's clock. |
| `executor_clock_estimated_error_seconds` | Maximum reported kernel error estimate; this is not a measured uncertainty bound. |
| `executor_disclosure_held_seconds` | Maximum reported age of an installed-key disclosure hold. It does not measure delivery or durable storage of keys at the dispatcher. |

Mode, attachment, attribution and clock groups each partition `executors_registered`.
Missing, malformed, future-dated or 90-second-old reports become `unknown`, as
do reports from disconnected sessions. A missing report does not clear a known
problem by claiming recovery. New valid reports restore the current observation.
The `executor_health` availability sample says whether registry aggregation
completed, not whether the executors are healthy.

Numeric extrema are omitted with `reason="incomplete"` if any required
executor observation is unknown, and with `reason="no_executors"` when none is
registered. State counts remain available, so a partial report cannot masquerade
as a healthy zero. A fresh attribution report with no installed-key hold has an
observed hold of zero. Clock estimates and schedule expiry can disagree between
machines with bad clocks; inspect clock readiness before interpreting timings.

Resource extrema additionally export `<metric>_unknown`, the count of registered
executors lacking that observation. A known zero remains numeric. A partial
maximum/minimum is withheld rather than appearing to cover the whole registry.
These resource and attachment details are available only through operator metrics,
not public executor discovery. Older executors omit them and count as unknown.

## Collection limits

Reports are cached for one second. Another request arriving while collection is
in progress receives 503 with `Retry-After: 1`. Availability failures within a
report return 200 with the affected observations unavailable. The report's
collection time is exported; intermediaries must not cache authenticated
responses.

Registry work is capped at 10,000 entries. Storage reads at most 10,001 retained
run rows with a two-second query context. A history larger than 10,000 produces
`reason="limit"` for `retained_runs` and omits **all** retained-run gauges; it
does not publish a partial total. Registry and host observations still work.
Database failures or timeouts produce `reason="storage"`. A registry above its
limit also makes binding-dependent run classification unavailable.

The scrape accepts executor identifiers up to 1,024 bytes and control binding
identifiers up to 64 bytes. Larger retained identities make run metrics
unavailable; a larger registry executor identity makes registry/run observations
unavailable. These are collection limits only and do not change registration.

Registry locks are released before storage and filesystem I/O. Registry, run
rows and host resources are sequential observations, not a single atomic
snapshot. A concurrent transition can therefore appear on the next scrape.
Executor health reads only the bounded registry snapshot; it makes no remote
calls, opens no sockets and changes no packet-counter or key-schedule state.

Executors collect their own resources and attachment metadata with the existing
30-second capability refresh, outside runtime locks. Filesystem, link and process
reads are sequential, not an atomic health check. Successful link inspection after
a detach is insufficient: the expected interface, hook and program must still
match. An inspection error becomes unknown. Presence does not establish packet
coverage, correct accounting or effective rate policing. The dispatcher uses
local receipt freshness and does not contact executors while serving metrics.

Linux host collection limits RSS input to 32 KiB and descriptor enumeration to
65,536. Beyond those bounds it reports `limit`; missing files and permission
failures have their own fixed reasons. Host filesystem calls have no imposed
kernel deadline; the configured database directory must be on a supported
local filesystem. Non-Linux host measurements are explicitly unsupported.
Available disk bytes are an observation, not a promise a future write succeeds.
