# Reusable measurements and deliberate retries

HTTP API 1.12 adds saved profiles, durable batch details, linked retries and TCP
listener readiness. These operations use the same account ownership checks as
run output. The companion console exposes the catalogue, profiles, measurement
history and editable new requests.

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
