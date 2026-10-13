# Coordinated update delivery

This guest compares two ways to deliver one small configuration update from an
origin to the other participants. Each participant runs the same WASM program
with a distinct role. Role 0 is the origin. The group can contain 2–8 distinct
executors; the demonstration uses five.

The guest opens no external service and needs no executor upgrade when its
application algorithm changes. It uses the existing group readiness exchange,
requested start and TCP listener, plus the optional
`debuglet_io_v1.accept_tcp` extension. Executors must support that bounded accept
operation. Build the guest with the supported compiler:

```sh
GOOS=wasip1 GOARCH=wasm go build -trimpath -ldflags='-s -w' \
  -o delivery.wasm ./examples/experiments/delivery
```

Use the ordinary [experiment runner](../README.md) or console grouped custom
program flow. Give every participant the same `delivery.wasm` and arguments
below, changing only `-role` from 0 through 4:

```text
-algorithm=direct -role=0 -participants=5 -deadline-ms=5000
-retry-ms=250 -repair-ms=750 -payload-bytes=512 -update-id=demo-1
-blocked-from=-1 -blocked-to=-1
```

Arguments are the complete WASI argument vector: Debuglet does not insert a
program name before `-algorithm`. Do not add an executable-name argument.

Enable `listen_tcp`, allow the participants' reachable listener addresses in
both operator and submitted destination policies, and reserve the same limits
for each algorithm. A 60-second host run limit leaves room for group readiness
and the five-second application window. The example generates a deterministic
512-byte update; its content hash is verified after reception. This is a small
configuration delivery experiment, not a software download benchmark.

Endpoints come exclusively from each participant's readiness metadata. Roles,
algorithm and settings must agree, and executors, run IDs and listener endpoints
must be distinct. Metadata does not grant network access. Use actual published
TCP endpoints when hosts map ports; no UDP support or NAT traversal is assumed.

## Algorithms

`direct` queues a copy for every recipient without waiting for any recipient's
acknowledgement. Unacknowledged copies are retried every `retry-ms`. Socket
operations are bounded and serviced sequentially; multiple copies may be in
flight, but the guest does not claim parallel Go socket execution.

`relay` first uses a binary tree: a role's parent is `(role-1)/2`. With five
participants the edges are 0→1, 0→2, 1→3 and 1→4. A recipient verifies the update,
forwards it to its children and acknowledges both the origin and its immediate
sender, avoiding a duplicate ACK when those are the same node. Each sender
retries its unacknowledged copies using the same interval as direct delivery.

After `repair-ms`, the origin asks an already acknowledged participant to resend
to each missing recipient. Helpers rotate in role order on subsequent repair
rounds. Only verified recipients can act as helpers. Duplicate data is verified
and acknowledged again without reapplying the update or restarting the tree.
Repeated repair can therefore recover a lost acknowledgement as well as a
missing data message. This is a bounded repair rule, not a general gossip,
routing, election or membership protocol.

All participants keep receiving until their local application deadline, even
after their own update is verified or the origin has all ACKs. This lets them
answer late duplicates and repair requests. Origin completion time is recorded
once, on the last distinct valid recipient ACK; waiting afterward does not
increase that duration. No messages are deliberately started after the local
deadline. Accept waits at most 20 ms, connect at most one second, and accepted
reads/writes at most 250 ms, each additionally bounded by the remaining window.
An unreachable endpoint can delay servicing other messages within those bounds.

## Controlled comparison

Run both algorithms in the healthy case first. Keep participant roles, update,
resource limits, deadline and settings fixed between paired trials.

`-blocked-from=0 -blocked-to=1` selects a **simulated connection failure** in
that direction. The sending guest suppresses every application message kind on
that directed pair before opening a socket. No bytes are transmitted for a
suppressed send, and a separate `simulated_failure` event records the decision.
All participants must receive the same setting. The healthy setting is `-1`
for both fields.

This is an application fault model, not measured packet loss, a TCP reset, a
router fault or evidence about an ISP. It does not bypass destination policy.
Useful comparisons include:

- 0→1 breaks a direct recipient and the relay tree's first hop; an acknowledged
  helper can repair the relay branch.
- 1→3 breaks a relay edge while leaving the direct baseline unaffected; it
  demonstrates repair overhead without guaranteeing that relay wins.
- 4→0 blocks a recipient's ACKs to the origin. That recipient may verify the
  update while the origin still reports a missing ACK.

Healthy direct delivery can be faster and cheaper. Report each observed result
instead of declaring an algorithm universally better. A few live trials are
demonstrations, not statistical performance estimates. Five executors on one
machine are five local instances, not five geographic vantage points.

## Output contract

Every stdout line is JSON with `schema: "debuglet.delivery.v1"`, `type`,
`algorithm`, `role`, `participants`, `experiment_id`, `run_id`, and
`update_sha256`. Setup failures may have empty experiment/run/hash values.

Events have `type: "event"`, `event` and `elapsed_ms`. Time is local to that
guest's actual start; readiness uses zero. Events are `ready`, `start`, `send`,
`receive`, `verified`, `acknowledged`, `repair`, `send_error`, `invalid_message`
and `simulated_failure`. Network events include `peer_role`, `message_kind`
(`data`, `ack` or `repair`) and `bytes`; invalid frames have only their received
byte count. A helper's `repair` event names the recipient it was asked to help.
The `ready` event also includes `config`.

`send` means the complete frame was accepted by the local socket write; it does
not prove remote delivery. `receive` follows frame and protocol validation.
`verified` is emitted once after payload hash verification. `acknowledged` is
emitted by the origin for each newly acknowledged recipient. Draw directed
message edges only from observed send/receive records, not from the static tree
or a missing result. Do not order different hosts' events as if their local
elapsed clocks were synchronized.

Each guest finishes with `type: "summary"` and:

| Field | Meaning |
| --- | --- |
| `outcome` | `complete`, `deadline` or `error`; non-origin completion means its own update was verified |
| `verified` | Whether this participant verified the update; the origin starts with its own verified payload |
| `completion_ms` | Origin-local elapsed time to all recipient ACKs, otherwise `null` |
| `finished_ms` | Local elapsed time when this guest summarizes |
| `acked_roles`, `missing_ack_roles` | Origin only; distinct recipient roles, excluding role 0 |
| `sent_bytes`, `received_bytes` | Application bytes actually written/read, including four-byte length prefixes and every data, ACK and repair frame; partial operations are included |
| `send_errors`, `simulated_failures` | Real failed sends and simulated suppressed sends counted separately |
| `duplicates` | Valid duplicate update messages received |
| `config` | `deadline_ms`, `retry_ms`, `repair_ms`, `payload_bytes`, `update_id`, `blocked_from`, `blocked_to` |
| `error` | Present on a setup/runtime error |

Use the origin's ACK summary for experiment completion. A missing ACK is not
proof of non-delivery. A missing guest summary remains unknown. An origin may
record all ACKs and later report a runtime error; retain both observations.
Aggregate sent application bytes across participants for traffic comparisons;
adding sent and received totals counts the same transfer twice. These are not
wire-byte or independently authenticated accounting claims. The framing and
hash detect malformed or inconsistent updates, not malicious participants.

Bounds are 1–512 payload bytes, 1–64 bytes for the update ID, a 1000–15000 ms
application window, a 100–2000 ms retry interval and
`retry-ms <= repair-ms < deadline-ms`. Frames are limited to 2048 JSON bytes.
The host lifetime, permission and resource limits remain authoritative. Failed
group submission must be inspected using its retained receipt, never blindly
replayed as a replacement experiment.
