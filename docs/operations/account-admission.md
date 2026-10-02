# Account admission limits

The dispatcher limits each authenticated account across all executors. Operators
and ownerless runs in the explicit local TEST profile also have finite limits.
These controls supplement executor queue limits and scheduler bandwidth rules.

| Dispatcher setting | Account default | Operator/local default |
| --- | ---: | ---: |
| `requests_per_minute` | 60 | 240 |
| `queued_jobs` | 128 | 1,024 |
| `active_jobs` | 16 | 64 |
| `queued_bytes` | 256 MiB | 1 GiB |

Configure these under `[admission.account]` and `[admission.operator]`. All values
must be positive. The account queue count fits one maximum-size batch; its byte
ceiling matches one executor's default retained queue. Reserved concurrency is
kept below the executor's default running count of 100. The larger operator
profile is an explicit configurable allowance, never an unlimited exemption.

`queued_jobs` counts all accepted runs, including started and uncertain work,
until confirmed execution retirement. `active_jobs` counts overlapping admitted
schedule windows, including their existing grace. An ended window whose cleanup
is unresolved continues to reserve a slot. This is a reservation limit, not a
new activation protocol or a count inferred from terminal reports.

Reservation, run insertion and order claims commit atomically. Retrying the
same accepted order returns its existing identities without adding a charge.
Request cancellation, upload failure, reconnect and restart retain accepted
reservations. Only a terminal run and an authenticated executor inspection
confirming absence under its current session can release execution capacity.
Reconnect also requires continuity of the enrolled credential. A retained,
quarantined, offline or uninspectable run stays charged. Output finality is a
separate lifecycle: pending output does not retain retired execution capacity,
and execution retirement does not delete or uncharge retained output.

The maintenance pass inspects at most four candidates every ten seconds, sharing
a one-second deadline. Payload deletion may make one explicit inspection.
Reading a list never contacts executors. Delayed retirement is conservative;
there is no automatic replay or removal of quarantined executor rows.

Intent and submission share a token bucket keyed by authenticated account.
Tokens replenish continuously, with a burst equal to `requests_per_minute`.
Restart replenishes request tokens, not durable work reservations. Capacity
refusals return HTTP 429 `account_quota_exceeded`. A request-rate refusal includes
`Retry-After` seconds; work quotas have no time promise because retirement makes
room. State, output, cancellation, deletion, logout and executor control do not
consume submission tokens. Respect ordinary submission uncertainty and inspect
known IDs before choosing another request.

## Upload sizes and upgrades

Both intent and submission accept at most 128 runs. The entire HTTP JSON body
is limited to 32 MiB, including base64 and metadata; unknown-length bodies have
the same bound. Each decoded module is at most 24 MiB and each logical stored
run at most 32 MiB. The charge includes decoded WASM, base64/comma-encoded args
and destinations, transaction/control text and 512 bytes of row overhead. A
24 MiB module cannot fit in the HTTP envelope after encoding and metadata.
Direct executor uploads apply the same module/row rules and an independent
32 MiB protobuf ceiling. See [executor queue limits](queued-work-limits.md).
Size refusals are HTTP 413 `payload_too_large` or gRPC `ResourceExhausted`.

Migration 16 conservatively charges every historical run 32 MiB because earlier
versions did not store its module size. Eight unresolved historical rows fill
the default account byte allowance. Existing results and control operations
remain available; admission can be refused until authenticated retirement is
confirmed or the operator explicitly raises finite limits after reviewing
retained history. The migration does not invent successful cleanup, exempt old
work, erase data or infer absence from a passed window. Terminal historical runs
without output metadata can retire only when their original authority is still
provable; offline historical capacity can remain reserved indefinitely.

All byte quotas are logical charges. SQLite pages, WAL, retained references and
backups require additional disk space. Payload deletion and configured expiry
follow [the retention policy](data-retention.md).
