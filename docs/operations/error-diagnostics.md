# Errors and diagnostic access

A failed submission can still have admitted runs. When `PUT /debuglet` returns
HTTP 500 with `code: internal_error` and `admitted_ids`, those are the durable
run identities in the original request order. Inspect each with
`GET /debuglet/{id}/state` or `GET /debuglet/{id}/recovery` before deciding what
to do next. Admission does not establish upload, execution, cancellation or
completion. `RunStateUnreconciled` preserves uncertainty; a later authorized
terminal report remains effective. Work is never replayed by reading a result.

The Go SDK retains a validated complete list in
`client.SubmissionError.AdmittedIDs` alongside `TransactionID`, the original
HTTP status/code and `OutcomeUnknown`. `dbl run` retains its run ID in a
`submission_unknown` receipt and exits unsuccessfully, including with `--wait`.
It does not automatically poll, cancel or submit another run after this error.
A missing, malformed or incomplete response retains only the identities already
known. Failure receipts have the same 4 MiB read bound as successful submission
responses; a receipt beyond that bound leaves admission unknown. Human error
messages remain limited to 8 KiB in the SDK. Do not infer rejection from a lost
response or retry the workload automatically.

## Public information and private diagnostics

| Surface | Information exposed |
| --- | --- |
| HTTP error envelope | Stable code and status, fixed public message or an explicitly bounded request value; admitted run IDs where available. Unclassified framework messages and body-decoder details are not returned. |
| Run state, logs and portable result | Fixed workload outcome categories and user-produced output. Cancellation, timeout, numeric guest exit and known policy/resource errors remain actionable. Arbitrary historical/runtime/compile diagnostic text is projected to a fixed failure category. |
| Request access log | Generated request ID, method, matched route, status and latency; no raw URL, query, body, cookie or caller-supplied request ID. |
| Dispatcher and executor diagnostic log | Routine events carry fixed classifications and correlation identifiers. Explicit private Debug entries retain bounded internal causes, with known request/control credentials redacted; startup/configuration errors remain actionable. |
| Authenticated dispatcher/executor control RPC | Explicit validation/ownership/capacity statuses remain actionable. Unclassified, Internal and DataLoss failures use fixed messages; private details remain in operator Debug logs. Known control credentials are redacted from reflected errors. |

An operator locates an HTTP failure using its `X-Request-ID` response header and
the daemon's `request failed` log entry. Runtime failures are recorded in the
executor log with the run ID. Access these through the deployment's private
service logs, using the service account or an authorized host administrator.
There is no API endpoint for arbitrary private diagnostic detail. Protect log
files, service-journal access, database copies and exported diagnostics with the
same access controls as other operator data.

API 1.12 retains the terminal-error string representation and projects both new
and historical stored messages to bounded public classifications. A nonempty
failure never becomes success; numeric guest exits, cancellation and unknown
outcomes retain their meaning. This changes display text, not execution truth
or `errors.Is`/HTTP status handling. Private raw retained diagnostics expire with
payload deletion. Enable Debug logging only for authorized diagnostics; routine
Info/Warn logs omit private causes. Host access to logs and databases is required;
there is no public diagnostic endpoint. Review exported diagnostics before sharing.
Guest output remains user-controlled measurement data under normal ownership.

Yamux transport diagnostics also use the bounded private Debug sink. They do not
write raw network errors or addresses directly to standard error.
