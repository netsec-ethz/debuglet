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
| Run state, logs and portable result | Stored workload outcome and user-produced output. Current executors classify unexpected runtime/host failures as a fixed failed outcome, preserve cancellation, timeout and guest exit classification, and bound public outcome text. Compile errors can include module content. |
| Request access log | Generated request ID, method, matched route, status and latency; no raw URL, query, body, cookie or caller-supplied request ID. |
| Dispatcher and executor diagnostic log | Internal database, transport and runtime causes correlated with request or run identity. These are operator diagnostics, not a public API. |
| Authenticated dispatcher/executor control RPC | Operational errors for the enrolled peer, potentially including internal database or runtime detail. Known control credentials are redacted from reflected peer errors; this is not a general-purpose secret filter. |

An operator locates an HTTP failure using its `X-Request-ID` response header and
the daemon's `request failed` log entry. Runtime failures are recorded in the
executor log with the run ID. Access these through the deployment's private
service logs, using the service account or an authorized host administrator.
There is no API endpoint for arbitrary private diagnostic detail. Protect log
files, service-journal access, database copies and exported diagnostics with the
same access controls as other operator data.

The API continues to return the stored terminal-error string; this change does
not introduce a new terminal-error representation or rewrite historical results.
Older stored errors can contain details that current executors would classify.
A participating executor supplies terminal reports, and guest output remains
user-controlled content. Diagnostic logs can contain secrets included by a
runtime or dependency; they are not suitable for public sharing or a claim of
server-wide secret redaction. Review and redact exports before sharing them.
