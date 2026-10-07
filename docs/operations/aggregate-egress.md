# Aggregate egress budgets

A dispatcher can reserve one shared network budget for each account, executor
node, and operator-defined target group. These controls supplement the existing
per-run bandwidth allocation, destination policy, socket limits, account job
limits and retained queue limits. They are disabled unless `[egress]` is enabled.
Let earlier unbudgeted runs finish and confirm their retirement before enabling
budgets. If needed, start with the old configuration to complete retirement.
Upgrade both dispatcher and executors before enabling them: admission refuses an
executor that does not advertise the grant protocol. Follow the normal explicit
database upgrade procedure; dispatcher schema 30 and executor schema 9 are needed.

## What is counted

| Setting | Unit and meaning |
| --- | --- |
| `bits_per_second` | Token-bucket rate for admitted guest payload writes, in bits per second |
| `burst_bytes` | Maximum simultaneous payload allowance; a single larger write is refused |
| `bytes` | Total attempted guest payload bytes per grant/window |
| `attempts_per_second` | Token-bucket rate of outgoing socket connection attempts, plus accepted TCP peers |
| `attempt_burst` | Maximum simultaneous connection-attempt allowance |
| `attempts` | Total admitted connection attempts per grant/window, including failed connects |
| `targets` | Sum of each admitted run's distinct, pinned IP addresses |

All seven settings must be finite and positive. TCP, TLS, UDP and ICMP guest
writes share the same run grant. Incoming payloads, IP/TCP/TLS overhead,
retransmissions, TCP acknowledgements, host DNS and dispatcher control traffic
are outside this payload budget. Packet accounting remains a separate control;
this setting does not claim an on-wire packet rate or continuous enforcement
verification. SCION is refused while aggregate grants are enabled. A run with no declared
network targets needs no grant; its existing policy refuses all peers.

Writes consume their requested size before sending. Failed or short writes do
not refund allowance. Exhausted volume, burst or rate allowance refuses the
operation; this guard does not wait for tokens or split UDP datagrams. The run's
existing bandwidth limiter continues to operate. Choose a burst at least as
large as the largest write a supported debuglet makes.

The dispatcher reserves the full run grant against **all** matching groups,
its authenticated account, and its executor. Reservations happen atomically with
run admission. Each group may span different destination addresses, accounts and
executors. No executor can independently replenish a shared grant. Redundant
reservations make admission conservative: two runs aimed at the same IP consume
two target slots, and a run matching two groups reserves its entire allowance
in both. Account job concurrency and retained upload storage remain separate;
if either admission check fails, the whole transaction rolls back.

## Windows, retirement and restart

Windows are fixed UTC intervals of `window_seconds`, at most one day. A run's
scheduled execution and the existing ten-second scheduling grace must fit inside
one window. Admission selects the window from the scheduled start time. Per-run
rate is the smaller of the requested ceiling and `egress.run.bits_per_second`;
a requested floor above that rate is refused.

The grants for a window collectively fit its rate, burst, volume, attempt and
target limits. They are reserved up front rather than borrowed between runs.
Cancellation, a terminal result or deleting measurement payload does not refund
that window's network allowance.

**A clock boundary alone never releases remote authority.** Until an authenticated
executor inspection proves the run absent, its grant also counts against other
windows. This includes an executor with a lagging clock, a lost control session,
quarantined work and an uncertain upload outcome. Only a grant whose window has
ended **and** whose execution is confirmed retired can be discarded. The existing
retirement maintenance performs those inspections; a disconnected executor may
therefore keep new work waiting. Do not delete reservation rows to resolve this.
Restore connectivity and use the documented recovery inspection workflow.

Executors use a one-way expiry deadline; clock rollback cannot reactivate an
expired live grant. Executor restore preserves the grant and original ownership,
and the existing no-replay rule still applies to started work. Dispatcher
reservations and its observed clock watermark are durable. A backward dispatcher
clock refuses new reservations rather than replenishing an earlier window.
Configuration changes, including disabling budgets, are refused while a different
configuration has outstanding or unretired grants. Retain the old configuration
until those commitments end; there is no advertised immediate reduction that
existing grants could exceed.

## Destination groups and DNS

A group lists IP prefixes, DNS destination names, or both. At admission the
dispatcher resolves declared targets and group names with a bounded timeout and
pins the selected literal IPs in the grant. Every matching group is reserved;
IPv4-mapped and policy-recognized embedded-address aliases match the underlying
prefix. A DNS alias resolving to the same IP does not obtain a separate budget.
The executor still applies the normal operator and run policy, then requires the
actual connection or reply peer to be one of the pinned IPs. DNS changing to a
new address requires a new admission; it cannot extend an existing grant.

Resolution failure refuses admission. DNS used for admission must be appropriate
for the executor's network; split-horizon answers can cause a safe refusal. A
prefix or shared DNS address is an accounting classification, **not** evidence
that the operator owns the target. Normal destination permission and opt-out
checks still apply.

## Example dispatcher configuration

This example allows at most ten full run grants in a shared group per hour.
A run may write up to 1 MiB and use at most four target IPs; the account and node
limits below allow the same ten grants. Configure limits for owned targets and
the measurements you intend to support.

```toml
[egress]
enabled = true
window_seconds = 3600

[egress.run]
bits_per_second = 80000
burst_bytes = 65536
bytes = 1048576
attempts_per_second = 2
attempt_burst = 4
attempts = 32
targets = 4

[egress.account]
bits_per_second = 800000
burst_bytes = 655360
bytes = 10485760
attempts_per_second = 20
attempt_burst = 40
attempts = 320
targets = 40

[egress.node]
bits_per_second = 800000
burst_bytes = 655360
bytes = 10485760
attempts_per_second = 20
attempt_burst = 40
attempts = 320
targets = 40

[[egress.groups]]
name = "owned-measurement-targets"
prefixes = ["192.0.2.0/24", "2001:db8::/32"]
# Alternatively or additionally: names = ["measurement.example.org"]

[egress.groups.limits]
bits_per_second = 800000
burst_bytes = 655360
bytes = 10485760
attempts_per_second = 20
attempt_burst = 40
attempts = 320
targets = 40
```
