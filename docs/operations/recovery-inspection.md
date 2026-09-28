# Inspecting an interrupted run

`dbl recovery ID` separates three facts: the last state stored by the dispatcher,
the availability of the run's original control session, and an optional dated
observation from the executor. It does not retry, cancel, finalize or refund work.
It never says that replay is safe.

```sh
dbl --dispatcher lab recovery RUN_UUID
dbl --dispatcher lab --output json recovery RUN_UUID
```

The command makes one HTTP request. A failed workload, an unavailable executor or
an unknown observation is a successful inspection (exit 0). HTTP and transport
failures exit 1, a command deadline exits 124 and interruption exits 130. Global
options precede `recovery`. Human output quotes server strings so that embedded
newlines and terminal control characters are visible rather than interpreted.

## What the result means

`state` and `error` are the last stored outcome; existing status and log responses
remain unchanged. `control_status`, dated by `checked_at`, is:

| Value | Meaning |
| --- | --- |
| `current` | The original bound control session is available at this check. It may stop immediately afterward. |
| `unavailable` | The stored binding exists, but its session is no longer available. A successor does not inherit it. |
| `legacy` | The dispatcher row has no complete original binding. Original control availability cannot be established. |

When original control is available, inspection needs no retained-row query.
Otherwise the dispatcher captures at most one eligible current session for the
same executor and asks it for metadata about the known run. It waits at most five
seconds, subject to the request's own deadline, and never follows a replacement.

| Observation classification | Meaning |
| --- | --- |
| `not_attempted` | The original control session was available when the request captured it. |
| `unavailable` | No captured eligible session could be queried. |
| `retained_unstarted` | The observer retained a matching row without a start marker. This does not authorize replay. |
| `started_unknown` | A matching retained row has a start marker. The marker does not prove the guest ran or finished. |
| `legacy` | The observer retained matching metadata without an original binding. Its execution outcome is unknown. |
| `absent` | The observer returned a successful point lookup with no row. This says nothing about another executor lifetime or past execution. |
| `filtered` | The observer deliberately excluded its own current-bound row. This is not absence. |
| `unsupported` | The captured peer does not support this inspection operation. |
| `failed` | The operation failed or exceeded its server-side bound. No missing-row conclusion follows. |
| `invalid` | The returned metadata could not be validated against the known dispatcher run. |

Unknown future classifications remain observations and must never be treated as
permission to replay. The CLI and Go client preserve their strings.

Only a validated reply carries an `observer` (executor and control binding),
`received_at` and `current_at_check`. All three fields are explicitly `null` when
no valid reply was received. `retained` is non-null only for retained metadata;
its `started_at`, `start_time` and `original_binding` may themselves be null.

A reply from a session replaced during the request remains a dated historical
observation: it keeps that observer's identity and receive time, with
`current_at_check: false`. Availability and the observation are taken at distinct
times. For example, control may become unavailable after a `not_attempted`
decision. Neither timestamp proves present liveness.

The endpoint is `GET /debuglet/{id}/recovery`, authenticated and authorized like
`GET /debuglet/{id}/state`. A run belonging to another account and an unknown UUID
both return 404. The endpoint cannot discover arbitrary executor-side orphan
runs. The Go client exposes the same document through `Client.Recovery(ctx, id)`
and preserves typed HTTP and context errors.

No stored state, receipt, log, scheduling reservation or payment is changed by
inspection. A new submission is a separate operation with a new run identity.
