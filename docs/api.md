# HTTP API

The dispatcher's public API is defined by [`api/openapi.yaml`](../api/openapi.yaml). That OpenAPI document is the authoritative wire contract: routes, request and response shapes, fields, units, defaults, and error responses. A running dispatcher serves the document it was built with at `/openapi.yaml`.

```sh
curl -s https://dispatcher.example/openapi.yaml
curl -s https://dispatcher.example/version
```

## Use the API

- Use [`pkg/client`](client.md) from Go.
- Use `dbl` for shell workflows.
- Generate or write a client from the OpenAPI document for other languages.
- Authenticate protected requests with a session token. See the `securitySchemes` and per-operation requirements in OpenAPI.

## Compatibility

`GET /version` reports three independent values:

| Field | Meaning |
| --- | --- |
| `api_version` | HTTP API compatibility version. |
| `binary_version` and `binary_revision` | Dispatcher build identity. |
| `protocol_version` | Dispatcher/executor control protocol; not for HTTP clients. |

Clients may send `Debuglet-API-Version: major.minor`. Within one API major version, clients must ignore unknown response fields and unknown values in open string fields. Breaking wire changes require a new API major version.

## Pricing and TEST bookkeeping

An order is priced from its executor's `price_per_bw`, the price per bit per second and second of run time in the executor's currency: `price_per_bw × floor_bw × timeout_ms / 1000`, computed exactly and rounded up to the next whole unit, so a run of any positive length at a positive rate and floor costs at least one unit. A batch costs the sum of its orders. `floor_bw` lies between 0 and 1000000000000000 bits per second and `timeout_ms` between 1 and 9223372036854; an order or a batch whose price exceeds 9223372036854775807 is refused as `invalid_policy` before anything is written.

A `TEST` intent has no payment backend: its transaction row is the intent, written in one database transaction together with its orders and, when the caller is an account, its owner, and it counts as paid on creation. The transaction records the total of its batch as its price and `TEST` as its currency, and every order records its own price and `TEST`; these amounts are bookkeeping only and move no funds. A `TEST` transaction recorded by a version older than 0.2.0-rc.2 carries the price 0 and an empty currency: it remains spendable as before, its amount can be read as the sum of its order rows, and nothing on the `TEST` path reads those two fields. `USDC` is the only chain method the HTTP API admits, and it is refused with `payments_disabled` while blockchain payments are disabled; this section describes `TEST`.

## Executor listing

API 1.9 also adds `admission`, operator `display` metadata, the executor-reported `scion_isd_as` and `listeners` to `GET /executors`. Each value carries a source label; see [executor discovery](operations/executor-discovery.md#vantage-point-metadata). It also adds the executor's host probes: `capabilities.icmp`, `capabilities.enforcement_reason` and `clock`. Host platform detail is operator-only and is never listed; it appears only in result provenance ([host probes](operations/executor-discovery.md#host-probes)).

## Recovery inspection

`GET /debuglet/{id}/recovery` inspects a known run without changing its state, reservations or payments. It reports stored outcome, control availability and at most one dated executor observation separately. See [recovery inspection](operations/recovery-inspection.md) for classifications and nullable provenance. The route was added in API 1.5.

## Cancellation inspection

API 1.9 adds `GET /debuglet/{id}/cancellation` for an account's recorded cancellation request. It returns the stable `request_id`, original binding, first request and attempted-delivery times, nullable executor acknowledgement time, and the separately stored run result. `requested` and `delivery_attempted` do not confirm receipt. `unresolved` gives a bounded reason. `not_needed`, with reason `already_terminal`, means the run was already terminal and no delivery was needed. A local cancellation after session loss may be terminal while remote acknowledgement remains unknown. Repeated explicit cancellation reuses the first request and reason; a stored acknowledgement permits local completion without another Abort. There is no automatic replay or retargeting to a replacement. Inspection is read-only. A run without a cancellation request returns 404.

## Output completeness

API 1.6 adds `output` to each log page: `state`, nullable `final_cursor`, and
`loss_reason`. Logs, output metadata and workload state describe one database
snapshot. `pending` means output delivery can continue even after the workload
exits. `complete` or `truncated` declares an immutable final cursor; zero means
empty output. Drain through that cursor, including all pages, before finishing.
`has_more` only describes page fullness and does not establish finality.

`truncated` preserves the accepted prefix and reports a fixed loss reason:
`output_limit`, `spool_limit`, `storage_limit`, `executor_interrupted`, or
`producer_failed`. It never inserts synthetic output for missing bytes.
Historical output is `unknown`; older servers omit the metadata. Neither case,
nor an unknown future state, proves completeness. Workload success and output
completeness are separate results.

## Portable results

API 1.8 adds `GET /debuglet/{id}/result`, an owned-run snapshot containing retained
output, output finality and immutable admission facts. The portable file format
has its own version. Missing historical facts remain unknown; an export does not
verify measurement truth. See [portable results](results.md) for bounds and
offline SDK/CLI use.

## Account-owned executors

API 1.10 adds authenticated `GET` and `POST /operator/executors`, plus
`POST /operator/executors/{id}/enrollment-token`. These are ordinary account
operations scoped to the caller's machines; they do not grant dispatcher-wide
operator privileges. Inventory includes pending and offline machines.

`POST /executor-enrollment` exchanges a single-use setup token and a signed CSR
for a machine certificate. It uses the token in the request body rather than a
user session. The executor creates and retains its own private key. See
[executor onboarding](operations/executor-onboarding.md) for setup, TLS trust,
replacement semantics and deployment configuration.

## Errors and health

API failures use `{"code": "…", "message": "…"}`. Programmatic clients should branch on `code`, not the human-readable message.

A `message` contains only fixed text written for that failure or a value from your own request repeated back and cut to at most 64 bytes (with `...` marking the cut and control characters replaced by spaces). It never contains database, runtime or transport diagnostics, and never a credential: no session token, CSRF token, account key, recovery code or payment `auth_key`, whether valid or rejected. The `error` field of a run's state and logs contains the recorded workload error; for results recorded by this version, it is cut to 512 bytes and marked with `...`, with control characters replaced by spaces. Earlier results are returned as stored. Failures inside the dispatcher answer `internal_error` with a fixed message; their cause is written to the dispatcher's log as a Warn entry `request failed` with the route, the status, the code and the underlying error. There is no API route that returns these details: an operator reads them in the daemon log.

Health endpoints are public:

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | Process is serving requests. |
| `/readyz` | Dispatcher can admit new work. |
| `/health` | Expanded readiness observations. |

`GET /metrics` requires an operator account (or the explicit local development
profile) and exports aggregate gauges in Prometheus text format. See
[operational metrics](operations/metrics.md) for authentication, units, unavailable
observations and collection limits.

The OpenAPI document contains the complete status-code and schema reference. Deployment authentication and transport security are covered in the [project Wiki](https://github.com/netsec-ethz/debuglet/wiki).

## Run states

`GET /debuglet/{id}/state` and `GET /debuglet/{id}/logs` report a run's `state` as an opaque string. An owner can observe:

| State | Meaning |
| --- | --- |
| `RunStateUploading`, `RunStateUploaded` | The dispatcher is handing the run to its executor, or has done so. |
| `RunStateInitializing`, `RunStateStarted` | The executor reported that the run is being prepared or is executing. |
| `RunStateUnreconciled` | The submission the run belongs to failed and the dispatcher could not confirm the run's cancellation: the executor refused it or it was not delivered. The run may still execute. |
| `RunStateExited` | Terminal. `error` is empty for a successful run. |

A later report from the executor supersedes `RunStateUnreconciled`, as it does any earlier state. A run that is not terminal about two minutes after the end of its reserved window (its start plus its timeout plus a ten-second grace) is classified as `RunStateExited` with an `error` that starts with `outcome unknown:`; this also covers a `RunStateUploading` or `RunStateUploaded` that no longer changes, for example because the control session of its executor ended before the run started. A run recorded before control bindings were stored has no binding; it is neither cancellable nor classified and keeps its stored state. Nothing is replayed, and no success is ever inferred: only the executor's own report records one.
