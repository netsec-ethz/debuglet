# HTTP API contract

The dispatcher's public HTTP API is described by [`api/openapi.yaml`](../api/openapi.yaml), an OpenAPI 3.0 document tracked in this repository. A running dispatcher embeds the document of the build it was compiled from and serves it:

```sh
curl -s http://127.0.0.1:9000/openapi.yaml
```

The document is the wire contract: request and response shapes, which fields may be `null`, the unit of every numeric field, the accepted query parameters with their defaults and bounds, and the status codes each route returns. The Go SDK in [`pkg/client`](SDK.md) is one consumer of that contract, not the definition of it.

## What is versioned

Three identities are versioned independently, and `GET /version` reports all three:

| Field | Meaning |
| --- | --- |
| `api_version` | The HTTP contract in `api/openapi.yaml`, as `major.minor`. This is the only version that is a promise to HTTP clients. |
| `binary_version`, `binary_revision` | The dispatcher build. An unstamped build reports its configured version string and no revision. |
| `protocol_version` | The executor control protocol between dispatcher and executor. No HTTP client speaks it. |

`version` remains the dispatcher's configured version string, unchanged for clients written before the contract was versioned.

The current contract version is **1.3**. A major version changes when a client that satisfied the previous contract can no longer read the new one. A minor version changes when the contract only grows.

## How a client selects a version

A client sends the contract version it was written against:

```
Debuglet-API-Version: 1.3
```

Every response carries the version the dispatcher implements in the same header, and the dispatcher exposes it through CORS so that a browser client can read it. The header is part of the machine-readable contract: every operation declares it as a request parameter, and every documented response declares it as a response header. A request that requires a major version the dispatcher does not serve, or a minor version above the one it implements, is answered with HTTP 400 and an explicit incompatibility error rather than a best-effort body. `GET /version` and `GET /openapi.yaml` always answer, whatever the header says, so a client that has been rejected can still discover what the dispatcher speaks.

A request without the header, or with an empty one, states no requirement and is served as before. Clients written before contract versioning keep working unchanged, and a dispatcher written before it ignores the header, so a current SDK also works against an older dispatcher.

## What a minor version may change

Within a major version the dispatcher may:

- add a route;
- add a response field, including one that a previous version would not have produced;
- add an optional request field or query parameter with a documented default;
- accept a request that was previously rejected;
- add a value to an open string field such as a run state or an error code.

A client must therefore ignore unknown response fields, ignore unknown values of open string fields, and never depend on the absence of a field. The SDK does this.

The run state `RunStateUnreconciled` means that the dispatcher failed the submission the run belongs to and the run's executor refused its cancellation: the run may still execute, its outcome is recorded when the executor reports it, and nothing is replayed.

## What requires a major version

- Removing or renaming a route, request field, response field or query parameter.
- Changing the type, unit or nullability of an existing field.
- Changing which status code a documented failure returns.
- Narrowing what a request may contain.

## Deprecation

A route or field that is to be removed is first marked deprecated in `api/openapi.yaml` and in this document, in a minor version, while it keeps working. It is removed only in a following major version, whose contract is published as a new `api/openapi.yaml` before the removal takes effect. Release candidates may still change before the final `v0.2.0`; pin the exact tag as described in [the SDK guide](SDK.md).

## Supported revisions

Only the latest release candidate (currently `v0.2.0-rc.1`, published from `main`) and the current commit of the `dev` integration branch are supported; fixes are not backported to earlier candidates. Across commits there is no compatibility promise for the `dbl` command line, the control protocol between dispatcher and executor, or the database schema: two commits are not promised to interoperate, and a state directory created by one commit is not promised to be readable by another. The HTTP API is the exception: it is versioned as this document describes above, and that versioning is unchanged by this rule.

## Errors

Every failure answers with one envelope, whatever the route and whichever layer rejected the request:

```json
{"code": "capacity_exhausted", "message": "capacity exceeded"}
```

`code` is the stable part: branch on it. `message` is a bounded diagnostic for a human and must not be parsed; it never carries a credential, a stack trace, or internal database or transport text. A failure inside the dispatcher answers `internal_error` with a fixed message and keeps its own diagnostic in the dispatcher's log.

| Code | Typical status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | Malformed or incomplete request. |
| `invalid_policy` | 400 | A policy that cannot be priced or scheduled. |
| `unknown_executor` | 400 | The named executor is not registered. |
| `intent_mismatch` | 400 | The submitted debuglets differ from the ones the intent was created for. |
| `payment_incomplete` | 400 | The transaction is not paid. |
| `unsupported_payment_method` | 400 | The API does not admit that payment method. |
| `unsupported_api_version` | 400 | The required contract version is not served. |
| `cancel_refused` | 400 | The dispatcher did not accept the cancellation. |
| `unauthorized` | 401 | The request presented no credential, or one that is unknown, expired or revoked. It never says which. |
| `forbidden` | 403 | The authenticated account may not perform that operation, or a cookie-authenticated state change carried no CSRF token. |
| `not_found` | 404 | No such debuglet, transaction, user, executor or route — or one that belongs to another account. |
| `method_not_allowed` | 405 | The route does not serve that method. |
| `capacity_exhausted` | 409 | The scheduler cannot admit the batch, or a destination limit lies below the floors charged to active allocations on that destination. |
| `payload_too_large` | 413 | The body exceeds the 33554432-byte (32 MiB) limit: a declared length above it is refused without reading the body; a body of unknown length is cut at the limit, so a decode that needs more fails with this code. No handler sees a byte beyond the limit. |
| `unsupported_media_type` | 415 | The route does not read that representation. |
| `internal_error` | 500 | A failure inside the dispatcher. |
| `payments_disabled` | 503 | A chain payment method while blockchain payments are disabled. |
| `service_unavailable` | 503 | A temporarily unavailable capability. |

A minor contract version may add codes, so treat an unknown code as a plain failure of the status it arrived with. The `message` field kept its name and position when the envelope was introduced in contract version 1.0, so a client that read `message` keeps working. Three things did change in 1.0:

- Failures that previously serialized an error value as an empty object `{}` now answer with the envelope.
- The few failures that answered with a bare JSON string now answer with the envelope.
- One status changed: a failure to store the orders of a payment intent answered 400 with the database error text and now answers 500 `internal_error`. It is a server failure, not a bad request, and the Go SDK consequently reports it as `OutcomeUnknown` at the intent stage rather than as a definite rejection.

For `DELETE /debuglet`, an internal failure while reading or recording a cancellation answers 500 `internal_error`. This does not confirm a stored result or remote termination: the executor may have acknowledged cancellation, or the dispatcher may have failed to record it after the control session ended. Read the run's state before deciding whether to repeat the request.

## Health

Three public routes report health separately, so a deployment can act on the right one:

| Route | Answer | Means |
| --- | --- | --- |
| `GET /healthz` | 200 `{"status":"ok"}` | The process serves requests, and nothing more: a live dispatcher may be paused or cut off from its dependencies. |
| `GET /readyz` | 200, or 503 `{"status":"unready","reasons":[...]}` | This dispatcher would admit new work: admission is open, its database answers one bounded read, and its control listener accepts executor sessions. `reasons` carries fixed identifiers — `admission_paused`, `storage_unavailable`, `control_unavailable` — never an operator's note or a path. |
| `GET /health` | 200 | The observations behind that decision, including `executors.eligible`, the executors whose control session lease was valid when checked, out of `executors.registered`. |

The dependencies are evaluated on demand, and `GET /readyz` and `GET /health` reuse the completed report for one second. This is a cache interval, not a maximum observation age: evaluation time adds to the age of the earlier readings in the report. Admission does not wait for it: a submission reads the maintenance switch itself. A readiness file written at startup says that a daemon once started, and a heartbeat is what an executor claims, so neither is authority here. Each check is one in-memory read or one single-row query with a short timeout; none scans, changes run state or needs a credential. A 503 from `GET /readyz` refuses new work only: accepted runs keep running, results keep being reported and every query keeps answering. That 503 carries the status report above rather than the error envelope every other failure answers with: a probe reads `status` and `reasons`, and there is no `code` to branch on.

## Units and limits

Units are stated per field in the contract document. The recurring ones:

- Bandwidth (`floor_bw`, `ceil_bw`, `price_per_bw`, `usage` on a listed debuglet, `limit` on `PATCH /destination`) is bits per second. A debuglet's `usage` is the `floor_bw` it was admitted with, not a measured consumption.
- `floor_bw` and `ceil_bw` must each be between 0 and 1000000000000000 (1 Pbit/s), and `ceil_bw` at least `floor_bw`. Both the payment intent and the submission reject anything else with `invalid_policy`. The bound keeps a single reservation in a range a reader can check; what keeps an aggregate exact is that admission adds the reservations of a window with a checked addition and refuses a sum that does not fit, rather than the bound itself.
- `timeout_ms` is milliseconds and must be between 1 and 9223372036854; above that the run budget would no longer fit a Go duration, and below it no run could be given the budget. Both the payment intent and the submission reject anything else with `invalid_policy`.
- The price of an order is `price_per_bw` × `floor_bw` × `timeout_ms` / 1000, computed exactly and rounded up to the next whole unit of the executor's currency: a run of any positive length at a positive rate and floor costs at least one unit, and a `timeout_ms` that is a whole number of seconds prices as the product of whole seconds. A batch is priced as the sum of its orders. An order or a batch whose price does not fit a signed 64-bit integer is rejected with `invalid_policy`, an empty batch with `invalid_request` and a repeated `order_id` with `invalid_policy`. The payment intent writes its order rows only after every order of the batch has been validated and priced, so a rejected intent writes nothing.
- A TEST transaction records the total of its batch as its price and `TEST` as its currency; the amounts are bookkeeping only and move no funds. A TEST transaction recorded before this was the case carries price 0 and an empty currency; it remains spendable exactly as before, its amount is the sum of its order rows, and nothing on the TEST path reads those two fields.
- `start_time` is Unix seconds and must be between 0 and 9223372036 (2262-04-11). A `start_time` already in the past starts the run as soon as the schedule allows, as does an absent one.
- The documented maxima bound each field, not a submission. The window a run reserves is `start_time` plus `timeout_ms` plus ten seconds for the executor's processing delay, and that window must end no later than 2262-04-11. A submission whose window does not fit is answered 400 with `invalid_policy` naming the fields, rather than reserved against a wrapped instant, even though every field is within its own range: `timeout_ms` at its maximum never fits, and a `start_time` near its maximum is admissible only with a budget that ends before 2262-04-11.
- `limit` on `PATCH /destination` must be between 0 and 1000000000000000 (1 Pbit/s); it becomes the capacity the runs of that destination are shared out of. Anything else is rejected with `invalid_policy`. The new limit applies to admission at once, and the share it gives each run is pushed to every executor holding an allocation on the destination, with a five-second delivery timeout. 204 means every one of them acknowledged it. 500 with `internal_error` means the limit is recorded but at least one delivery failed; the request may be repeated, which records the same limit and pushes it again. Pushes are unversioned: concurrent updates can arrive out of order, so an older share can overwrite a newer, lower one at an executor. This route does not guarantee revocation.
- The same bandwidth and timeout ranges are enforced again on the executor control protocol, on the policy an Upload carries and on the destination limits an allocation answers with. Neither side relies on the other, or on the SDK, having checked the numbers.
- A `limit` on `PATCH /destination` below the floors charged to active allocations on the destination is refused with 409 and `capacity_exhausted`, and nothing is recorded or pushed. These floors do not include future scheduler reservations whose runs have not allocated bandwidth yet. The runs holding active allocations keep their floors; lower the limit once they release them. A limit equal to those floors is accepted.
- `tesla_delay_sec`, `delay_sec` and `expires_at_s` are seconds; `tesla_anchor_timestamp_ns` and `anchor_timestamp_ns` are Unix nanoseconds; `start_time`, `end_time` and `last_seen` are Unix seconds. Log entry `timestamp` is a UTC string formatted `2006-01-02T15:04:05Z`.
- `wasm`, `output`, `tesla_anchor_key`, `anchor_key` and `disclosed_key` are base64.

Request limits:

- `GET /debuglet/{id}/state`, `GET /debuglet/{id}/logs` and the `debuglet_id` of `DELETE /debuglet`: the ID must be the lowercase 36-character hyphenated UUID spelling that submission returns, and not the nil UUID. Uppercase, braced, `urn:uuid:` and unhyphenated spellings are rejected with 400 `invalid_request`.
- `GET /debuglet/{id}/logs`: `after` must be a non-negative integer and `limit` a positive integer when present; both are rejected with 400 otherwise. `limit` defaults to 100 and is clamped to 1000.
- `GET /list-debuglets`: `limit` defaults to 100 and is clamped to 100; `offset` defaults to 0. Neither may be negative and `limit` may not be zero.
- `GET /executors/by-ip`: `ip` is required; `n` defaults to 10 and must be positive when present. It is clamped to 100 candidates before ownership is applied, but the executor registry retains at most 20 recent identifiers per executor, so at most 20 can ever be returned and usually fewer, since only the caller's own are listed. An account owning none of them receives an empty array, never null.
- Every request body is limited to 33554432 bytes (32 MiB) by the dispatcher. A declared `Content-Length` above the limit is answered 413 `payload_too_large` before any handler acts and without reading the body. A body of unknown length is cut at the limit: a handler never receives a byte beyond it, a decode that needs more fails with the same 413, and a value complete within the limit is handled as it arrived, after which the connection is closed. The SDK measures the exact encoded envelope of `PUT /payment/intent` and `PUT /debuglet` against the same bound before sending and always declares the length, so nothing it sends is refused for size.
- `PUT /debuglet`: an identical resubmission of a batch this dispatcher already admitted answers 200 with the run IDs it recorded for that batch, in the order of the batch, and admits, schedules and uploads nothing again. A submitter whose response was lost can learn the IDs this way while the dispatcher admits work; a resubmission that arrives while admission is paused is handled like any submission then: the paid order is refunded where its payment method supports refunds and the answer is 503, after which the transaction is refused. A batch whose upload to its executor failed is refunded where its payment method supports refunds, and a refunded transaction is refused with `payment_incomplete` rather than answered. A TEST transaction is not refunded, so a resubmission of its failed batch answers the IDs of the runs that failed submission recorded.

Run errors:

The `error` field of `GET /debuglet/{id}/state` and `GET /debuglet/{id}/logs` is the run's recorded result for its owner. It is one line: at most 512 bytes of text, followed by `...` when longer text was cut. A failed run records the guest's exit code (`debuglet exited with code 7`), the policy timeout (`timeout of 30s exceeded`), a cancellation (`cancelled via API`, `debuglet cancelled`), a refused destination (`destination refused: ...`), a module that does not compile (`module does not compile: ...`), or `debuglet failed; the executor log has the details` when the cause is the executor's own; a guest trap, such as `unreachable`, is reported the same way. The executor daemon's log holds the full diagnostic under the run ID. Results recorded before this bound are returned as stored. The field remains free text, so this changes no contract version: no field or status is added.

## Authentication

Requests are authenticated with a server-issued session. Nothing else is a credential: a user identifier, a debuglet identifier and a payment auth key authenticate nobody.

### Obtaining a credential

`PUT /user` registers an account and returns, exactly once, its **account key** and its **recovery code**. The dispatcher stores only their SHA-256 digests and cannot show either again. `POST /auth/login` exchanges the account key for a **session**; `POST /auth/recover` exchanges the recovery code for a replacement account key and recovery code, revoking every session the account had. A recovery code names its own account and can name no other, so recovering never grants access to somebody else's.

A deployment may also enable GitHub browser login. `GET /auth/github` starts the authorization-code flow and `GET /auth/github/callback` completes it. The dispatcher binds the immutable GitHub numeric user ID to one Debuglet account, stores no GitHub access token, issues the same Debuglet session and CSRF cookies as account-key login, and redirects only to the console URL fixed in deployment configuration. OAuth state is held in a short-lived HttpOnly, Secure, SameSite=Lax cookie. Account-key login remains available to native clients.

Every credential is printed as `<prefix>_<selector>.<verifier>`: 16 random bytes of public selector and 32 random bytes of secret verifier, both unpadded base64url. The prefix names the kind (`dba` account key, `dbr` recovery code, `dbs` session token), so a credential of one kind cannot be presented as another. The verifier is compared in constant time against the stored digest.

### Presenting a credential

```
Authorization: Bearer dbs_<selector>.<verifier>
```

is what a native client sends. A browser client receives the same token in the `session_token` cookie (`HttpOnly`, `SameSite=Strict`) together with the session's CSRF token in the readable `session_csrf` cookie, and must repeat that CSRF value in the `X-Debuglet-CSRF` header of every state-changing request. The cookie's `Secure` attribute is set when the dispatcher terminates TLS itself or when its configuration states that a TLS terminator stands in front of it; it is never derived from `X-Forwarded-Proto` or any other request header, because a request cannot be trusted to describe its own scheme. A bearer token is not ambient browser authority and needs no CSRF proof.

A session expires 12 hours after it was issued and is not extended by use; a client logs in again. `POST /auth/logout` revokes it before that. A missing, malformed, unknown, expired or revoked credential all answer 401 `unauthorized` with the same message: the difference is only useful to someone probing the server.

### Access matrix

| Operation | Route | Who may perform it |
| --- | --- | --- |
| Read the contract and version | `GET /openapi.yaml`, `GET /version` | Anyone |
| Read liveness, readiness and health | `GET /healthz`, `GET /readyz`, `GET /health` | Anyone. They carry no run data and no operator note |
| List executors, read TESLA parameters | `GET /executors`, `GET /executors/{id}/tesla` | Anyone. This is deliberately public attribution data, not run data |
| Register an account | `PUT /user` | Anyone. It is the credential issuer and a caller has no credential yet |
| Obtain, end or replace a credential | `POST /auth/login`, `/auth/logout`, `/auth/recover`; `GET /auth/github`, `/auth/github/callback` | Whoever holds the corresponding credential, or completes the configured GitHub flow |
| Report the caller's account | `GET /me` | Any authenticated account, about itself |
| Price a batch, submit a batch | `PUT /payment/intent`, `PUT /debuglet` | Any authenticated account. A submission may only spend a payment order of the account that created it |
| Read the payment status | `GET /payment/{transaction_id}/status` | The account that created the order |
| Read run state and output, cancel | `GET /debuglet/{id}/state`, `/logs`, `DELETE /debuglet` | The account that owns the run |
| List the caller's runs | `GET /list-debuglets` | Any authenticated account, about its own runs |
| Find the executor serving an address | `GET /executors/by-ip` | Any authenticated account. The returned run identifiers are the caller's own |
| Change a destination limit | `PATCH /destination` | An operator account. The change reaches admission and the executors holding the destination, as described under units and limits |
| Enumerate accounts | `GET /user-ids` | An operator account |

No route grants the operator role. It is given to an existing account on the dispatcher host, against the configured database and with the same schema checks the daemon applies before serving:

```sh
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml -grant-operator <account UUID>
debuglet-dispatcher -config /etc/debuglet/dispatcher/dispatcher.toml -revoke-operator <account UUID>
```

Both print what they changed and exit; an identifier that names no account is reported rather than created. This is the **only** way to obtain the role, apart from the account the local development profile below bootstraps. A role change takes effect on the account's next request, including one made with a session it already holds. [docs/environments.md](environments.md) describes where to run these commands.

Executor identities are administered on the host the same way, and are unrelated to accounts. `-enroll-executor <executor ID>` prints a single-use token, valid for 24 hours, that binds that ID to the client certificate the executor presents; `-revoke-executor <executor ID>` deletes the binding, after which that certificate is refused and recovery is a new token. An executor ID is whatever string the deployment uses, so `-enroll-executor` accepts any identifier and enrols it, including one no executor has ever used.

An operator's authority is over the dispatcher, not over other accounts' data: another account's run, output and payment order answer 404 to an operator exactly as they do to any other account. Operator accounts read administration, not private run data.

### 404 or 403

The distinction is deliberate and stable:

- A **private object** the caller may not reach — another account's run, another account's payment order — answers **404 `not_found`**, exactly as an identifier that names nothing does. The response is no existence oracle. A submission that presents another account's transaction answers the 401 `unauthorized` that route already gives an unknown transaction, for the same reason.
- A **restricted operation** answers **403 `forbidden`**. The route's existence is public; only the authority to use it is missing. Logging in again does not help, so the failure says so.

### Rows recorded before authentication existed

A run with no recorded owner, an account created before credentials existed and a payment order created before orders had an owner are not adopted by anyone. They stay in the database and are unreachable over the authenticated API: nothing silently assigns them, and no account can claim them. An account without stored credentials cannot log in and cannot be recovered.

### Local development profile

A dispatcher additionally serves a request that presents **no credential at all** as its own local operator when, and only when, both of these hold: `local_development = true` is set in the `[server]` section of its configuration, and it recognises the environment that key describes — blockchain payments disabled, the TLS listener disabled and both listeners bound to loopback, which is what the local role commands generate and no deployment example does. The key alone turns nothing off, the environment alone turns nothing off, setting the key elsewhere refuses startup, and a dispatcher serving the profile says so in a startup warning. That keeps the wallet-free local flow usable without a browser and without a wallet. It is off in every other configuration, and even there:

- a credential that is presented but does not verify is still refused;
- a request that does authenticate is scoped to its own account, so the bypass is not a way to read somebody's runs;
- `GET /me` and `GET /list-debuglets` still need a credential, because the bypass names no account;
- runs submitted without a credential are recorded without an owner and are therefore unreachable once the profile is turned off.

`POST /auth/login` with an empty `account_key` is the documented way to obtain a real credential there without a browser: it issues a session for the fixed local development account, which holds the operator role.

## Current limits of this contract

- The contract describes the routes a dispatcher registers. `GET /connection` exists only when the dispatcher was started with local connection metadata; other deployments answer 404 for it.
- The document is validated against real handler responses and SDK requests by the repository's tests. It is not generated from the handlers, so a change to a handler that is not reflected in the document is a bug in the change. That validation has two known blind spots: field and route descriptions are prose and are checked by nobody, and a status code that no test provokes is never compared against the schema documented for it. Field names, types, nullability, units expressed as bounds, query parameters and the codes are checked.
- There is no content negotiation beyond the version header, no ETag or caching contract, and no rate limit.
