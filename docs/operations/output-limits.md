# Output storage and control headroom

The executor counts stdout and stderr together. It chunks a write before copying
it into 16 KiB frames, uses a bounded 16-frame queue, and limits each run to
8 MiB, 65,536 frames, and a default producer rate of 1 MiB/s with a 64 KiB burst.
The retained executor spool defaults to 64 MiB and 65,536 unacknowledged runs.
Charges include payload, 64 bytes per frame and 256 bytes per retained run.
The dispatcher applies its own run, account and node limits as well.

A refused frame stops the producer and records truncation at the committed
prefix. The executor reports `output_limit` for the run quota and `spool_limit`
for its retained-storage or headroom limit. A dispatcher storage refusal uses
its existing `storage_limit` receipt. These markers do not turn a workload's
failure into successful execution. Final cursors and acknowledgements continue
to refer only to committed data.

## Control reserve

`output.control_reserve_bytes` defaults to 16 MiB. Before admitting new output
identity or persisting a frame, each daemon checks both SQLite's available page
capacity and filesystem free bytes, inside the existing write transaction. It
requires the reserve plus four times the incoming payload and 64 KiB for
journal/B-tree/accounting growth. A failed inspection refuses the payload too.
The limit is configurable but must remain positive. The executor treats zero as the default; the dispatcher rejects explicit zero and values above 1 TiB.

```toml
[output]
control_reserve_bytes = 16777216
```

Final receipts, acknowledgements and control bookkeeping bypass this payload
check. Existing small writes may still fit when a larger output frame is
refused. Tests use a private SQLite page cap and a few ordinary frames to verify
that refusal preserves charges and finality while a sibling and control
Upload/Abort continue; they do not fill the host filesystem.

The reserve is advisory. SQLite/WAL growth, other writers and device failures
can defeat a free-space observation. This does not reserve disk blocks or
partition the device. Provision and monitor the database filesystem with room
for both daemons' databases, journals, logs and retained evidence. Existing
write-failure handling preserves uncertainty if a final record cannot commit.

Acknowledged executor output releases its spool charge, but its minimal end
metadata remains for idempotency/reconciliation. Storage limits do not imply
automatic age-based deletion. The [data-retention contract](data-retention.md)
defines owner deletion, operator-selected expiry and retained ownership/evidence.
