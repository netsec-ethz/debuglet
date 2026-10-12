# Correlating lifecycle logs

Dispatcher HTTP requests receive a server-generated `X-Request-ID` response
header. The `HTTP request completed` event carries that `request_id`, the
matched route template, method, response status and latency. Incoming request
IDs are ignored. URLs, query strings, headers and request bodies are not part
of this event; an unmatched route is `unknown`.

For a new submission, find `Run admitted` by `request_id`. It carries `run_id`,
`executor_id`, `dispatcher_incarnation`, `session_id` and, for an account-owned
submission, its internal `user_id`. The executor's `Run accepted` event has the
same run and control identifiers. HTTP context does not cross the control
protocol: the executor's `request_id` is `unknown`. Join these records by the
run and binding, rather than inventing a shared request or execution attempt.
`attempt` is always `unknown`; no durable attempt identifier exists today.

A failed upload emits `Run upload failed` at warning level before its error
cancels other uploads in the batch. Join it to `Run admitted` by request, run
and binding. `upload_stage` identifies `session_lookup`, `executor_upload` or
`record_uploaded`; `grpc_code` and `elapsed_ms` describe that failure.
`context_code` is the local upload context's status, and
`request_context_code` is the original HTTP context's status. A sibling can
therefore show `Canceled` while the originating request remains `OK`. These
fields identify where failure was observed; a remote `DeadlineExceeded` with
an `OK` local context does not by itself prove a database timeout.

The executor emits `Run admission failed` with the same run and binding after
validating their identity. Its stage is `validation` or `scheduler_admission`,
with its own status, elapsed time and inbound `context_code`. In particular, an
admission failure can leave no `Run accepted` event. The warning never includes
raw error text, SQL, arguments or credentials. Use existing restricted Debug
diagnostics for further details. An absent acceptance event alone does not
prove a run was never stored or executed.

Failed batches retain their admitted run IDs. Inspect each run's terminal
state and complete output; an uncertain admission is not a successful result
or permission to replay it. A later successful submission does not explain or
resolve an earlier partial failure.

`Cancellation requested` records a request, not completion. An executor's
`Run cancellation joined` means local cleanup and canonical row removal
completed. The dispatcher's `Cancellation recorded` means the terminal state
was recorded or was already terminal. A cancellation after its control session
ended explicitly reports `executor_outcome: unknown`. Batch cleanup errors
also report `cleanup_outcome: unknown` and whether terminal recording failed.
These events classify the failure without copying arbitrary remote error text;
an HTTP error is not proof that a remote
operation did not happen.

Control registration and retirement events carry the same executor and session
identifiers. Retirement does not claim joined cleanup. A reconnect uses a new
session; match the full binding when investigating an interrupted run.
Non-secret identifiers longer than 128 bytes or containing whitespace or
non-ASCII characters appear as `sha256:` followed by their digest, consistently
on both sides. Literal `unknown` or `sha256:`-prefixed IDs also use a digest,
so they cannot impersonate those rendered values. This bounds fields without confusing distinct identifier
prefixes. Credentials and raw provider subjects are never correlation fields.

These events use the daemon logger. CLI JSON receipts and readiness stay on
stdout; daemon diagnostics and guest output remain separate. Existing private
error diagnostics may contain operational details, so restrict access to daemon
logs and follow the [security policy](../../SECURITY.md).
