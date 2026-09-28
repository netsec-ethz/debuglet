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
on both sides. This bounds fields without confusing distinct identifier
prefixes. Credentials and raw provider subjects are never correlation fields.

These events use the daemon logger. CLI JSON receipts and readiness stay on
stdout; daemon diagnostics and guest output remain separate. Existing private
error diagnostics may contain operational details, so apply the documented
[retention policy](../../SECURITY.md) and restrict access to daemon logs.
