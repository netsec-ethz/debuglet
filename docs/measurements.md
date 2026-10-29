# Run and reuse measurements

## Run your first measurement

Open the [hosted console](https://debuglet.netsec.ethz.ch/console/), or the console
URL supplied by your dispatcher operator, and sign in with an enabled provider.
You need an available executor and a permitted HTTP endpoint to measure.

1. Open **Templates** and choose **Chart HTTP timing without hiding failures**.
2. Set **HTTP endpoint** to a health or test URL you are allowed to measure,
   including `https://` or `http://` and the full path. Keep the default five
   samples, then choose **Open editable copy**.
3. Choose **Run**, select **one** available executor, then **Configure selected
   nodes**. Check the destination, timeout and bandwidth limits. Use an immediate
   start for this first run.
4. Choose **Review measurement**, review its permissions and quote, then
   **Run with TEST** if the deployment offers TEST funding.
5. On **Results**, inspect the attempt table and timing chart. Each row records
   the response status, duration or error. Wait for complete output; **Activity**
   contains raw output, and **Details** contains the configuration and run ID.

TEST needs no wallet. A deployment with TEST allowances still requires enough
operator-granted units; account registration does not itself guarantee credit.
See [TEST allowances](operations/configuration.md#dispatcher-usage-allowances).

The template uses new HTTP requests and does not follow redirects. Its chart
includes transport-complete responses, **including HTTP error statuses**; check
status codes separately. Durations include connection setup, TLS for HTTPS,
server processing and reading the response, so they are not pure network RTT.
The small sample demonstrates the method, not an SLA or statistical confidence.

A finished run is not necessarily a successful measurement. Check errors and
output completeness as well as the chart. If all requests fail, there are no
completed-response timings to compare.

| Problem | Next step |
| --- | --- |
| No available nodes | Choose another node or ask the operator when one will be ready. |
| Destination refused by network policy | Use a permitted endpoint or ask its operator to authorize the measurement. |
| HTTP 3xx | Inspect the redirect; use the final permitted URL if that is the endpoint you intended to measure. |
| No chart or incomplete output | Inspect **Activity** for errors and wait while output is still arriving. |

Use **Edit and run again** to change the saved source. **Save result** keeps a
useful report accessible through **Highlights**. See [source reuse and results](results.md).

## Compare two executors

Open the same template, keep the target and sampling settings identical, and
select two executors after **Run**. Choose **Configure selected nodes**, then
**Review group** and **Submit group with TEST**. On the result page, select each
participant to inspect its reports or compare the group's observations.

These are independent copies of one program. They start as they become ready;
there is no synchronized-start barrier. Compare repeated observations and errors,
not just one latency sample. To make programs exchange messages or wait for one
another, use **Add program** in the editor and follow
[coordinated experiments](development/workflow-authoring.md).

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
runner and UDP guest. It uses the dispatcher and executor readiness extension
through the SDK. For visual authoring, use the [experiment editor](development/workflow-authoring.md)
instead. Missing members, retries and partial results remain decisions for the
experiment's author, within the run deadlines.
