# Executor queued-work limits

The executor applies these admission limits to new uploads, including local
TEST runs:

| Resource | Limit |
| --- | --- |
| Decoded WASM per run | 24 MiB |
| Charged stored data per run | 32 MiB |
| Charged retained execution data per executor database | 256 MiB |
| Retained execution rows per executor database | 1,024 |

These limits are fixed at scheduler construction. Charged storage includes the
WASM bytes, the base64-encoded argument and destination list columns (including
comma separators), the transaction and control-binding text, and 512 bytes per
row for fixed metadata. The charge is a logical admission budget: SQLite pages,
indexes, WAL files and retained output consume additional disk space. Output
has its own configured spool and retained-output limits.

The existing HTTP limit remains 32 MiB for the entire encoded request, including
base64 and JSON syntax. A decoded module at the 24 MiB limit cannot fit in that
HTTP envelope after encoding and metadata. Direct executor gRPC messages also
have a separate 32 MiB ceiling, including protobuf overhead. The module and
stored-run checks run before queue writes or compilation. This queue control
does not bound compiler or guest memory and CPU use.

Retained rows are the storage reservations. An atomic conditional insert checks
the current byte and row totals while inserting new work. Concurrent uploads
cannot both claim the last slot. An output-metadata failure rolls back the same
transaction's execution row. A repeated run identity remains an existing-owner
or duplicate-identity error; it does not acquire or release capacity.

Queued, started and quarantined rows all count, including rows from previous
control sessions or daemon starts. Restoring a database preserves those rows,
even if the database already exceeds a new limit; further admission stays
closed until enough retained work is retired. Cancellation or completion
releases capacity only when the owned execution row is deleted successfully.
Caller timeout, connection loss, failed deletion and an uncertain remote
outcome do not release the charge. No automatic expiry or replay is introduced.

A rejected direct upload returns gRPC `ResourceExhausted` with either
`executor upload size limit reached` or `executor retained queue limit reached`.
Existing work can still be inspected and canceled, subject to its ordinary
ownership and control-session rules. A queue-full response does not specify a
retry time: only actual retirement can make room, and clients must preserve
normal submission-uncertainty rules instead of automatically replaying work.

This is the executor-node storage control. The dispatcher adds separate
[account admission and HTTP batch limits](account-admission.md); their
reservations do not replace the executor's retained rows.
