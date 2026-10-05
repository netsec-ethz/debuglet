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

Every intent records the name of the rule that priced it in the `pricing_rule` column of its transaction; the rule above is `bw-s-ceil-ms-v1`, and a transaction written before the column existed carries an empty name and was priced by the rule of the release that wrote it. A `USDC` intent is a local record of the price, the auth key and the addresses the payer uses, created without any chain call, so an intent that fails leaves nothing external to reconcile.

Creating a `USDC` intent requires `refund_address` to be a Sui address: `0x` followed by one to 64 hexadecimal digits; short addresses such as `0x1` are accepted. An omitted, empty or malformed address returns HTTP 400 `invalid_request`, with `field_errors` naming `refund_address` and code `invalid_address`, before the intent or any order is written. While blockchain payments are disabled, the method still returns HTTP 503 `payments_disabled` first. `TEST` does not validate this field and accepts an omitted, empty or arbitrary value. `POST /payment/quote` does not evaluate `refund_address`.

## Quotes and economics (API 1.15)

`POST /payment/quote` takes the body of `PUT /payment/intent`, under the same authentication and account request quota, and prices it with the rule described in [Pricing and TEST bookkeeping](#pricing-and-test-bookkeeping), named `bw-s-ceil-ms-v1`. Only `floor_bw` enters the price; `ceil_bw` does not. A `timeout_ms` of 0 is refused like any timeout outside its range: `timeout_ms must be positive and at most 9223372036854`. A quote writes nothing: no transaction, order, auth key or run, and no capacity is reserved. It answers `{pricing_rule, currency, unit, total, orders, errors}`, where every amount is a decimal string of integer base units of the currency and `unit` names them (`TEST units`, `micro-USDC`, otherwise `base units`). A batch the intent would refuse is still answered 200: each order lists its own problems in `errors` with an empty `price`, including a `start_time` outside its range and a policy the executor cannot currently serve (for example `require_icmp` on an executor without ICMP), reported with the field and reason submission would use; problems of the whole batch (an empty batch, a total above the signed 64-bit maximum) appear in the top-level `errors`, and `total` is empty unless every order was priced. A malformed body, an unsupported payment method, a chain method while blockchain payments are disabled and a missing credential keep the intent's status. `retry` is not evaluated.

The intent prices the batch again when it is created and returns the result as `quote` in its response, in the same shape, so a client can compare it with an earlier quote; a changed `pricing_rule` means the server's rule changed in between. An intent recovered through an explicit retry does not repeat its quote.

`GET /me` adds `economics`: `payment_methods` lists the methods the intent admits now (`TEST`, and `USDC` when blockchain payments are enabled), `chain_payments` whether blockchain payments are enabled and `allowances` whether usage allowances are enabled on this dispatcher (see [usage allowances](#usage-allowances-api-115)).

`GET /me/orders` pages the caller's own payment intents, newest first. An intent has no stored creation time, so the order is that of its expiry time, which is creation plus five minutes, then of its ID. `limit` is 1 to 100 (default 25); pass the `next` value of a page as `before` to read the following one, and `next` is empty on the last page. Each intent reports `id`, `method`, `status` (`outstanding`, `paid`, `refunded`, `expired`, `aborted`, or `unknown`), its recorded `price` and `currency`, `pricing_rule` (empty when the dispatcher did not record one) and `expires_at`, and each of its orders `order_id`, `executor_id`, `price`, `currency`, `settlement` (`pending`, `credited` or `refunded`, as in run detail costs) and, once admitted, `run_id`. Another account's intents are never listed; a `before` value that is not one of your intents returns an empty page.

## Usage allowances (API 1.15)

A dispatcher may cap what authenticated accounts reserve with `TEST` intents at fixed grants of TEST units issued by an operator. Allowances are non-transferable usage credits, not money. They are disabled unless the deployment enables them (`[allowance]`, see [configuration](operations/configuration.md#dispatcher-usage-allowances)); `GET /me` reports `economics.allowances`. The request without a credential that the local development profile admits is never capped.

An account's allowance is `granted`, the sum of its grants, less what its `TEST` orders hold. An order whose run reached a settled outcome is `consumed`, whether it was credited or refunded: a run that ran used its allowance whatever its exit code. Any other order of a paid intent is `reserved`: an admitted run whose outcome is not known yet, which stays reserved until it is, or an order not admitted yet. `remaining` is `granted - consumed - reserved`; it is negative when the account used more `TEST` units before its grants than it was granted since. Totals are never wrapped or clamped: when a total of an account's grants or orders, or `remaining`, does not fit a signed 64-bit integer, `GET /me/allowance` and a grant answer 409 `allowance_out_of_range` instead of a balance (a grant is then not recorded), an intent is refused without writing anything, and an operator has to reconcile the history. While allowances are enabled, `PUT /payment/intent` creates an account's `TEST` intent only if `remaining` covers its total price, checked and reserved in one database statement so that concurrent intents cannot overdraw it; otherwise it answers 429 with `allowance_exceeded`, a message naming the remaining and the required TEST units, and writes no transaction, order or owner. Before that check, the account's paid `TEST` intents past their expiry (five minutes after creation) that admitted no run are released: their reservation returns to the allowance, and submitting one answers 400 `payment_incomplete`. A release and an admission of the same intent exclude each other. A quote never consults the allowance.

`GET /me/allowance` returns `{currency, granted, reserved, consumed, remaining, pricing_rule}`, with amounts as decimal strings of TEST units; while allowances are disabled it answers 404 `not_found` with the message `allowances are not enabled`.

`POST /operator/accounts/{id}/allowance` grants the account `{id}` an allowance and requires an authenticated operator account, which is recorded as `granted_by`. The body is `{amount, reason, idempotency_key}`: `amount` is an optional decimal string of TEST units (the configured `default_grant` when omitted), `reason` is required (at most 200 characters) and `idempotency_key` is required (at most 128 characters). It answers 201 with `{grant, allowance}`, the recorded grant and the account's allowance after it. The same key with the same amount and reason answers 200 with the same grant and records nothing; with a different amount or reason it answers 409 `conflict`. An unknown account answers 404, and so does every request while allowances are disabled. Grants are never changed, reset or renewed.

## Executor earnings (API 1.15)

`GET /operator/executors/{id}/earnings` reports, to the account that owns the executor, `{currency, total_income, current_balance, transfers, payouts}`: the earnings the dispatcher has credited to the executor in the currency it announces (or, while it is not connected, the first currency it earned in), and up to 100 of the newest outbound chain transfers that name it, each `{id, kind, amount, currency, receiver, state, digest, created_at, updated_at}` with `kind` `payout` or `refund` and `state` `reserved`, `sent`, `confirmed`, `failed` or `unknown`. Amounts are decimal strings of base units. `payouts` is `disabled` while blockchain payments are disabled, and nothing is paid out then. The route starts no payout. Another account's executor answers 404 like a missing one.

## Executor listing

API 1.9 also adds `admission`, operator `display` metadata, the executor-reported `scion_isd_as` and `listeners` to `GET /executors`. Each value carries a source label; see [executor discovery](operations/executor-discovery.md#vantage-point-metadata). It also adds the executor's host probes: `capabilities.icmp`, `capabilities.enforcement_reason` and `clock`. Host platform detail is operator-only and is never listed; it appears only in result provenance ([host probes](operations/executor-discovery.md#host-probes)).

## Probe attribution

API 1.11 adds two public routes for [probe verification](verification.md). They need no credential and are rate-limited per client address; an excess answers `429 rate_limited` with `Retry-After`. Behind a reverse proxy the address is the proxy's unless the proxy is listed in `[attribution] trusted_proxies` ([configuration](operations/configuration.md#dispatcher-attribution-history)).

- `GET /attribution/candidates?ip=&at=` lists the runs active from `ip` within one epoch of `at` (RFC 3339), oldest first and at most 32 (`truncated` when more matched). Each candidate gives `executor_id`, `run_id`, `active_from`, `active_to`, `ip_source` (`observed` or `advertised`), the chain `schedule` `{chain_id, k0, t0_unix_ns, epoch_seconds, disclosure_delay_epochs, chain_length, tag_spec}`, `disclosed_through` (the latest disclosed epoch, 0 for none), `disclosed_through_at_ns` (when the dispatcher recorded that key) and `next_disclosure_at_ns` (the earliest disclosure time of the next key). `tag_spec` is 1 for debuglet-tag-v1 and 0 for a legacy chain whose executor did not report debuglet-tag-v1, which a v1 verifier reports as unsupported. The answer's `retained_from` is the start of the retained history: before it, no candidate is no evidence either way.
- `GET /attribution/keys?executor_id=&chain_id=&from_epoch=&to_epoch=` returns a chain's disclosed keys in ascending epoch order, at most 1024 epochs per page, with `next_epoch` for the next page. Only keys that verified against `k0` are recorded, but a verifier checks each against `k0` itself.

API 1.16 adds the server-assisted check, public and under the same rate limit:

- `POST /attribution/verify` takes `{packets: [{data, captured_at}]}`: 1 to 256 packets, each the base64 of the first min(64, Total Length) bytes of the IPv4 packet with its capture time, in a body of at most 64 KiB that forms at most 16 groups (one per source address and epoch of each candidate chain). Each group in `groups` gives `source`, `epoch`, `chain_id`, `executor_id`, `run_id`, `verdict`, `reason`, `method` (`server` when the executor answered before disclosure, `offline` when a disclosed key did, empty when nothing was checked), `packets` (indices into the request) and, for a group with a chain, `budget` `{limit, remaining, resets_at}` in candidate trials and, when pending, `pending_until`. `receipt` `{key_id, payload, signature}` is an Ed25519 signature over the canonical JSON in `payload`. `503 service_unavailable` means the receipt key could not be read or created.
- `GET /attribution/receipt-keys` lists every receipt key `{key_id, public_key, valid_from, valid_to}`, oldest first; `valid_to` is null for the current key.

[Probe verification](verification.md#http-api) defines the groups, the budget and the receipt.

A candidate names the run and its executor, never the account; a run ID grants no access to owner routes. `GET /executors/by-ip` and `GET /executors/{id}/tesla` are deprecated in favour of these routes and keep working within API major 1.

## Recovery inspection

`GET /debuglet/{id}/recovery` inspects a known run without changing its state, reservations or payments. It reports stored outcome, control availability and at most one dated executor observation separately. See [recovery inspection](operations/recovery-inspection.md) for classifications and nullable provenance. The route was added in API 1.5.

Optional `ip_metadata` on `GET /executors` contains offline ASN and approximate
country/city lookups for observed and advertised addresses. Each lookup records
its database source/build epoch, registration observation time and an explicit
unknown reason. Existing `display` fields stay operator-only; new clients may
derive an automatic fallback from `ip_metadata`. Operator location takes
precedence; executor opt-out suppresses
automatic location. The same object is captured immutably as
`provenance.vantage_point.ip_metadata`, additive within vantage-point schema 1
and result format 1.1. Older files omit it. See
[offline metadata and database updates](operations/executor-discovery.md#offline-asn-and-approximate-location).

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

## Reusable measurement profiles

API 1.12 adds `GET /measurement-templates` and account-owned
`/measurement-profiles` CRUD. A profile stores a bounded program and its digest,
arguments, executor choice and policy; applying it creates an editable request
with a new schedule and payment intent. Template references name an immutable
version and matching program digest. Existing runs are independent of later
profile edits or deletion. See OpenAPI for field and account limits.

## Measurement history

API 1.12 adds account-owned `GET /measurements` and `GET /measurements/{id}`.
A batch keeps its transaction ID and ordered child run IDs across refreshes.
Its paginated child list contains lightweight references; each child’s full
configuration is read separately.
Listing supports pagination, label/ID search and outcome filters with counts.
`GET /debuglet/{id}/detail` returns retained original and admitted configuration
without loading output, so large output does not prevent inspection. Historical
facts remain null when unavailable; reserved cost and confirmed charges are
reported separately in exact base-unit strings.

## Errors and health

API failures use `{"code": "…", "message": "…"}`. Programmatic clients should branch on `code`, not the human-readable message. API 1.12 optionally adds `field_errors`, identifying a dotted request field, stable refusal reason and order ID where available. Intent and submission bodies must be one JSON document containing supported fields; `listen_icmp` is refused with guidance to use `require_icmp`.

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

A later report from the executor supersedes `RunStateUnreconciled`, as it does any earlier state. After the reserved window ends plus one minute of grace, the dispatcher records local allocation reclamation and releases bandwidth allocations and scheduler floors. The sweep runs every thirty seconds in bounded batches. Recovery inspection exposes `allocation_reclaimed_at` (API 1.14). This does not change the stored state/error, infer that the guest stopped, settle payments, authorize replay, delete retained work, or release account retained-work quotas. A late real terminal report may still establish an outcome under its original control binding. A run stored without a complete binding is neither cancellable nor reclaimed automatically. Older terminal records whose error begins `outcome unknown:` remain readable.

## Provider identities and scoped credentials (API 1.13)

`GET /auth/providers` lists enabled providers, the exact API audience and the
configured device-approval page. CILogon and GitHub callbacks create local browser
sessions; provider tokens are never API credentials. `/me/identities` supports
explicit linking and removal after recent browser authentication. `/me/credentials`
lists and revokes sessions or creates scoped API credentials; `/auth/device/*`
provides browser-approved CLI login. Account management uses cookie sessions plus
CSRF, and API tokens cannot authorize these operations. All existing account
ownership checks still apply. See [authentication](operations/authentication.md)
for permission scopes, expiry, provider setup and current limits.

### Destination allocation delivery

Allocation delivery failures return `Unavailable` to the executor; the recorded
allocation is idempotent and stays until normal release or window reclamation.
Each exact session retries pending delivery on its heartbeat, with no separate
notification worker. Executors advertising bandwidth version 1 or later apply complete
allocation snapshots in revision order, including after an older RPC times out.
An acknowledgement means the current packet-counter updates succeeded.

`PATCH /destination` records its accepted policy even if delivery fails.
A failed response means some executors have not confirmed it; inspect the named
executor in dispatcher diagnostics. Legacy executors remain compatible for run
allocation but cannot confirm ordered live changes: this operation reports that
an executor upgrade is required. Reconnection never retargets an old update.

### Destination policies

API 1.17. `PATCH /destination` (operator) states the complete policy of one
destination: `limit`, or `denied: true`, which refuses every new submission
and allocation there whatever its floor and records no limit; `denied: false` lifts a deny.
Destination keys use the executor policy normalization: host without port,
lower-case name without a final dot, or canonical IP without mapping/zone.
Equivalent spellings address the same policy, reservation and limiter.
`reason` (at most 500 bytes) is required to deny or to lower the limit, and
`expires_at` (RFC 3339, in the future) returns the destination to the default
capacity at that time. Answers: 204 recorded and delivered, 400 invalid, 403
not an operator, 409 a limit below the floors admitted there (a deny is never
refused for floors), 500 recorded but not acknowledged by every executor
holding an allocation there.

Each change is appended to the dispatcher database before it applies and is
applied again after a restart. `GET /destinations` (operator) lists the latest
event of every destination: `kind` (`limit`, `deny`, or `allow` for an
expiry), `denied`, `limit` (null for the default), `reason`, `actor` (account
ID, `local`, or `system`), `set_at`, `expires_at`, `revision`, and `delivery`
(`confirmed` or `unconfirmed`) with `recipients` and `unconfirmed` counts for
the executors that held an allocation when it was applied in this dispatcher
lifetime. A deny is sent as a zero limit with the denied flag. An executor of
this release (bandwidth version 2) closes the active sockets to the destination
before it acknowledges; only its acknowledgement confirms a deny. An executor
that predates this release only applies the zero limit, stays unconfirmed even
when it acknowledges, and the PATCH answers 500 asking for its upgrade.
An unconfirmed deny retires only its captured control session within the
five-second delivery deadline, preventing further lease renewal. Remote work
stops no later than its existing lease expiry under the supported control
contract; delivery remains unconfirmed. Reconnecting does not remove the
durable policy. A failure to record the change answers 500 "destination policy could not be
recorded"; nothing was applied and the previous policy stays in force. See
[destination limits and opt-outs](operations/configuration.md#destination-limits-and-opt-outs).
