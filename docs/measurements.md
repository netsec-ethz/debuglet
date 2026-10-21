# Run and reuse measurements

## Run your first measurement

Use this walkthrough on a deployment whose operator confirms compatible console,
dispatcher and executor versions and provides the console URL.

Ask the operator for a health endpoint they own that returns a small **HTTP 200**
response and is permitted from the chosen executor. For example,
`https://service.example/health` is a placeholder: replace it with that endpoint's
complete URL, including the correct scheme, port and path. A public website is
not a guaranteed test target. The console cannot inspect the operator's private
destination and port restrictions in advance.

1. Sign in and open **New measurement**. Choose **HTTP timing & status** and
   enter the approved URL in **HTTP target**. Leave **Response time threshold**
   empty for this first check.
2. Under **Vantage point**, select an executor marked **Available** and
   **TEST · no wallet**. Open **Node details** to check its identity and reported
   capabilities. Availability does not prove that your target is permitted or
   reachable.
3. Choose **Review measurement**. Check the executor, endpoint, **Permitted
   destinations**, timeout and bandwidth. Keep the immediate start and default
   limits if the deployment accepts them, then choose **Run with TEST**.
4. On the run page, wait for **All program output received.** Inspect
   **Measurement results** for **Checks passed**, **HTTP status** `200`,
   **Time** and **Response body**. Check the **Raw program output** JSON too:
   its `schema` is `debuglet.measurement.v1`, `template` is `http`, and `ok` and
   the check's `ok` should be `true`. Keep the run ID from **Run details**;
   **Download output** saves the received program output.

TEST needs no wallet. If the dispatcher enforces TEST allowances, your account
also needs enough operator-granted units; signing up does not grant them
automatically. See [TEST allowances](operations/configuration.md#dispatcher-usage-allowances).

The template preserves `http://` or `https://` as entered; HTTPS uses TLS. It
makes one GET request and requires a 2xx response. It does not follow redirects.
**Time** measures the whole HTTP check, including connection setup, TLS when
used, request transmission and reading the response body. Service processing
contributes to it; this is not a pure network round-trip time (RTT).

An **exited** state means execution ended, not that the check passed. A parsed
result can appear before all output arrives. Confirm the result, execution state
and output completeness separately; **All program output received.** alone
does not mean success.

| What you see | Next step |
| --- | --- |
| No available executor, **Offline** or **Maintenance** | Wait for readiness or ask the operator; the list refreshes automatically. |
| Target denied by the operator network policy | Ask for a permitted endpoint or an executor whose policy permits it. Changing HTTP to HTTPS does not grant permission; do not bypass the policy. |
| **Checks failed** with HTTP 3xx | Use the final URL only if the operator approves it. A redirect fails the template's 2xx expectation. |
| Output still arriving, incomplete or completeness unconfirmed | Wait while output arrives; reload if completeness is unconfirmed. Keep incomplete output marked as incomplete rather than inferring success. |

## Compare two executors

1. Open **Grouped measurement**, choose **Compare HTTP responses**, and enter
   the same approved **HTTP target**. Confirm that both operators permit it.
2. Under **Choose your nodes**, select two available TEST executors. Keep the
   same timeout, bandwidth and response threshold for both. Choose **Review
   group**, check both participants and their permitted destinations, then
   **Submit group with TEST**.
3. On **Grouped measurement**, open **Details and output** for each participant.
   Check its complete output and result as above, then compare HTTP status,
   response size and time alongside the executor and run IDs. **Export group
   results** saves a snapshot; it can still contain running participants or
   incomplete output.

These are two independent HTTP probes in one submission. They do not wait for a
synchronized start, and one sample per executor does not establish a stable
latency difference. For coordinated programs, see
[Coordinate a batch of debuglets](#coordinate-a-batch-of-debuglets).

## Save and apply a profile

The catalogue contains versioned HTTP, TCP and service-check templates. Each
entry identifies its immutable program digest, argument schema and defaults,
required transports and default policy. A template version and digest must match;
an unknown version is rejected instead of silently using new defaults.

A private profile stores the program bytes and digest, arguments, executor choice
and policy. It contains no account or payment credentials and no absolute start
time. Applying a profile opens an editable request; select a new schedule and
review its policy before submission. Saving a later edit does not change earlier
runs. Profiles persist until their owner deletes them. Each account can keep 32
profiles, and an encoded profile request is limited to 8 MiB.

The Go client provides `MeasurementTemplates`, `Profiles`, `Profile`,
`SaveProfile` and `DeleteProfile`. `SaveProfile` with an empty ID creates a profile;
an existing ID updates that owner's profile. See the [HTTP contract](../api/openapi.yaml)
for the versioned fields and validation limits.

## Reopen a batch or run

A submission's transaction ID groups its ordered child run IDs. Labels and
program display names are retained with the original argument array, target
addresses, full policy and requested schedule. The admitted policy is separate:
for example, admission can resolve a requested host address.

`Client.Measurements` lists batches with pagination, state/search filters and
summary counts. `Client.Measurement` returns the first 25 child references;
`Client.MeasurementRuns` accepts a page size of 1–100 and an offset. Use
`Client.RunDetail` for each child's original configuration, admitted provenance,
outcome and cost. Details do not load output, so a large log does not prevent
configuration inspection. Deleted payloads return `410 payload_deleted`.
Each detail response is bounded to 32 MiB, independently of the smaller profile
upload limit; older retained configurations remain readable within that bound.

Requested start, reserved window and observed execution are different facts.
`execution.started_observed_at` and `terminal_observed_at` are dispatcher receipt
times, not exact executor timestamps. `reported_exit_code` is the executor's
report. Missing historical observations remain null. Costs distinguish the
reserved amount from confirmed accounting and use exact base-unit strings with
their currency and units. A terminal state alone is not proof of success or
complete output.

The console's reuse action opens a new editable request and clears the previous
absolute schedule. It does not copy payment credentials. Reuse alone does not
create retry lineage; use the explicit linked retry action for that purpose.

## Reopen the source and keep a highlight

A builder run with saved source can be opened as a new editable copy. A community
run opens its recorded revision; later changes to that shared experiment do not
change the original run. Rebuild and review the copy before submitting it. Runs
without a saved builder document retain configuration reuse, but cannot recover
an editable block graph from the WASM alone.

Save a useful workflow output to the personal or project results library with a
title, note and collection. Each highlight links back to its original run and
available source. It remains subject to the run's current access and payload
retention. See [results and source reuse](results.md).

## Request one linked retry

A retry is a new execution linked to a parent run. The parent keeps its identity,
output and recorded outcome, including uncertainty. The old workload may still
execute. Inspection, an expired reservation or a recovery report never starts a
retry automatically.

Choose a UUID for the retry request and retain it together with the exact new
configuration. Repeating that request ID with the same parent and configuration
recovers the same intent and admitted child after a lost response. A different
configuration is rejected; a new request ID deliberately requests another
execution. Admission still checks authorization, capacity and payment policy.

```sh
dbl --dispatcher research retry PARENT_RUN_ID --request-id REQUEST_UUID \
  --executor EXECUTOR_ID --sample hello --wait --allow-remote-test
```

The CLI and console linked-retry flow use TEST currency. The Go equivalent is
`Client.RetryTEST(ctx, parentID, requestID, preparedBatch)`, where the prepared
batch contains exactly one request. Keep returned transaction and admitted run
IDs even when an error reports an uncertain response. Neither client replays an
ambiguous submission automatically. Portable retry exports use result format
1.2; ordinary exports retain format 1.1.

## Run a two-executor echo measurement

The full installed package includes a bounded server/client echo workflow:

```sh
dbl --dispatcher research --timeout 60s rendezvous \
  --server-executor SERVER_ID --client-executor CLIENT_ID \
  --server-allow CLIENT_SOURCE_ADDRESS --duration 30s --allow-remote-test
```

The server needs a configured TCP public host and port that the client can reach.
The allowlist must admit the client's source address. For an owned loopback test,
both executors also need local targets enabled. Capability and policy refusals
are reported before the dependent client starts.

The command submits the server once and waits for its authenticated, run-bound
listener report before submitting the client on the other executor. It does not
parse an address from output. Output pages identify their role and run ID; the
final receipt includes both run IDs, endpoint and cleanup dispositions. Listener
readiness means the executor installed its socket, not independent reachability
proof.

The Go helper is `Client.RendezvousTEST`: supply two requests and use the complete
argument `{server_endpoint}` where the client needs the endpoint. It replaces
that argument after readiness and permits the corresponding destination host.
The helper supports a readiness deadline and a whole-operation deadline, and
never replays an ambiguous submission. On success, failure, deadline or caller
cancellation it requests cancellation of every known run, then inspects cleanup
under an independent ten-second bound. `confirmed_absent` records a current
executor observation; `unconfirmed` requires follow-up using the returned IDs.

## Coordinate a batch of debuglets

An experiment submits a fixed set of ordinary runs together. Choose each run's
executor, WASM, arguments and policy independently. The existing transaction ID
groups their results. `Client.SubmitExperimentTEST` accepts a saved definition
and returns a receipt with run IDs and program hashes; `ExportExperiment` reads
the group's results and `CancelExperiment` requests cancellation of its known runs.

Each guest finishes its setup, then calls `debuglet.Ready(ctx, metadata)`. Once
all batch members have declared readiness, it receives their bounded metadata
and a common future start time. Call `debuglet.WaitStart(ctx, experiment)` before
starting the measurement. Hosts need synchronized clocks for close timing;
this is not a guarantee of simultaneous execution. Experiment traffic uses the
normal permitted sockets, while readiness travels through the dispatcher.

The [five-executor example](../examples/experiments/README.md) includes a manifest,
runner and UDP guest. It requires the new dispatcher and executor readiness
extension; it does not add a console flow. Missing members, retries and partial
results remain decisions for the experiment's author, within the run deadlines.
