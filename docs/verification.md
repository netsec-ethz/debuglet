# Probe verification

This note records how the recipient of a probe checks which Debuglet run sent
it. It is a design for #71, #73 and #341; steps 1 and 2 of the
[delivery order](#delivery-order) have landed, the rest has not. Keep it in
step with the code as each step lands. The tag
algorithm itself is specified in the [tag spec](tag-spec.md) (tag spec
v1).

**Today.** Each executor tags outgoing IPv4 packets with a 16-bit SipHash-2-4
tag in the IP ID, keyed by `HKDF(k_t, run_id)` over the first 64 bytes of the
canonical packet, where `k_t` is the key of epoch `t` in the executor's TESLA
chain. The executor discloses `k_t` on a heartbeat once epoch `t + d` has
started. The dispatcher records every chain an executor announces, every
disclosed key that verifies against its chain, and each run's interval and
source address, in its database for the configured retention (default 90
days, [configuration](operations/configuration.md#dispatcher-attribution-history)).
Anyone can look them up without an account through
`GET /attribution/candidates` and `GET /attribution/keys`, so captures older
than the executor's current chain or the dispatcher's last restart can still
be verified. The only verifier is
[`tools/verify_pcap.py`](../tools/verify_pcap.py), mirrored by the website's
`verify.ts`; it uses the new routes and falls back to the deprecated
`GET /executors/by-ip` (account required, the caller's own runs among the
executor's last 20) and `GET /executors/{id}/tesla` (current chain only). An
executor restart still loses the last `d` epochs of its chain: the dispatcher
accepts a disclosure for an earlier recorded chain (`tesla_key_anchor` on the
heartbeat), but the executor does not yet re-derive and disclose that tail.
Nothing can be verified before disclosure. There is no `dbl verify`,
`client.Verify` or evidence file.

## Model

Every executor has a TESLA chain with anchor `k0`, start `t0`, epoch length
`I` and disclosure delay `d ≥ 2` epochs (default about 15 minutes). The key of
epoch `t` is disclosed once epoch `t + d` has started, at
`t0 + (t + d)·I`. A packet group is the packets from one source address in
one epoch. Each group is verified in one of two ways:

| Method | When | How | Proves to |
| --- | --- | --- | --- |
| `server` | Key not yet disclosed | The dispatcher relays the group to the executor, which still holds `k_t` and answers yes or no for the whole group. The dispatcher signs a receipt. The dispatcher never holds an undisclosed key. | Anyone who trusts the dispatcher's receipt key |
| `offline` | Key disclosed | The verifier fetches the dated schedule and the disclosed keys and checks the tags itself. | Whoever trusts the capture timestamps |

After disclosure anyone can compute valid tags, so an offline check only
shows that the packets came from the run *if they were captured before the
disclosure time*. That rests on the capture's own timestamps, which are the
presenter's claim. A server receipt is the evidence to show a third party: it
shows that the executor confirmed the tags while only it held the key.

## Command

```sh
dbl verify <capture.pcap|pcapng|evidence.json> [--at <time>] [--offline]
           [--output text|json] [--evidence <file>]
```

- No account or login is needed. `--server` defaults to the configured
  dispatcher.
- Each group is verified by `server` or `offline` automatically, and the
  output says which. `--offline` never uploads packets. Groups whose key is not
  disclosed are then `pending`.
- `--at` sets the capture time of every packet, overriding the capture's own
  timestamps (for example for a capture whose clock is known to be wrong).
- `--evidence` writes the evidence bundle. Passing a bundle instead of a
  capture checks it again offline, together with its receipt.

Text output has one line per group, grouped by run:

```
verified   run 6f1c…  executor exec-zrh-1  2026-09-29T10:14Z  12 packets  via server
verified   run 6f1c…  executor exec-zrh-1  2026-09-29T09:02Z  40 packets  via offline
invalid    192.0.2.7  2026-09-29T10:15Z  3 packets  tag_mismatch
pending    198.51.100.4  2026-09-29T10:20Z  5 packets  until 2026-09-29T10:35Z
missing    203.0.113.9  2025-11-02T08:00Z  7 packets  no history retained for that time
unsupported  2001:db8::1  2 packets  IPv6 is not tagged
```

`--output json` prints the [report](#results) instead. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Every group is `verified`. |
| 1 | Usage, read or network error; nothing is concluded. |
| 2 | At least one group is `invalid`. |
| 3 | No group is `invalid`, but at least one is `pending`, `missing` or `unsupported`. |

The website's verify page follows the same flow and output. It parses the
capture in the browser and uses the same endpoints, categories and bundle
format. Before uploading packets for a `server` check, it asks the user for
permission.

## SDK

`pkg/client` gains:

```go
pkts, err := client.ReadCapture(r io.Reader) ([]client.CapturedPacket, error) // pcap or pcapng
rep, err := c.Verify(ctx, pkts, client.VerifyOptions{At: t, Offline: false})
// rep.Groups []VerifyGroup{Verdict, Reason, Method, RunID, ExecutorID, Epoch,
//                          Time, PendingUntil, Packets []int}
// rep.Evidence() Evidence; client.VerifyEvidence(ctx, ev) (Report, error)
```

`Verify` works on a client without a credential. `dbl verify` is a thin
wrapper around it. `tools/verify_pcap.py` remains the reference
implementation. It, the SDK and `verify.ts` must give the same result for the
shared vectors of tag spec v1: good, altered, truncated, expired-history and
every supported link type.

## HTTP API

The routes below follow the existing conventions. They have no path prefix;
the version is negotiated with the `Debuglet-API-Version` header, and the
routes are an addition in the next minor version (the candidates and keys
routes are part of the unreleased API 1.9). They are public
(`security: []`), rate-limited per client address (10 requests per second,
burst 40, per TCP peer and per /64 for IPv6; `429 rate_limited` with
`Retry-After`), and answer the usual `{code, message}` errors.

| Route | Purpose |
| --- | --- |
| `GET /attribution/candidates?ip=&at=` | Dated lookup: the runs active from `ip` within one epoch of `at` (RFC 3339). Each candidate gives `executor_id`, `run_id`, active interval (`active_from`, `active_to`), `ip_source` (`observed` or `advertised`), and the schedule `{chain, k0, t0, interval, delay_epochs, chain_length, tag_spec}` together with `disclosed_through` (the latest disclosed epoch, 0 for none). `t0` is Unix nanoseconds, `interval` seconds, `chain` the hex of the first 16 bytes of SHA-256(`k0`), and `chain_length` 0 when the executor did not report it. The answer includes `retained_from`, so that `missing` can be told apart from "no run", and `truncated` when more than 32 runs matched. |
| `GET /attribution/keys?executor=&chain=&from_epoch=&to_epoch=` | Disclosed keys of one chain, at most 1024 epochs per page, with `next_epoch` for the next page (null on the last). `from_epoch` defaults to 1 and `to_epoch` to no bound. Undisclosed epochs are absent. The client checks every key against `k0`. |
| `POST /attribution/verify` | Server-assisted check. The request lists up to 256 packets as `{data: base64 of the first 64 bytes of the IPv4 packet, captured_at}`. The response gives a verdict for each group, the budget `{limit, remaining, resets_at}` per group, and a signed `receipt`. |
| `GET /attribution/receipt-keys` | The dispatcher's current and past receipt-verification keys (Ed25519) with their validity periods. |

The dispatcher forms groups by source address and epoch. It asks the executor
about one group at a time: which candidate run, if any, reproduces the tag of
every packet in the group. The executor never returns tags or keys. A group
that mixes runs is `invalid`, so clients should split captures by
destination. A group whose key is already disclosed is answered from the key
store, spends no budget and is marked `method: offline` in the receipt. The
receipt is a detached signature over canonical JSON of the dispatcher ID, the
API version, the query time, the SHA-256 packet digest (see
[evidence](#evidence)) and each group's verdict, run, executor, epoch and
method.

`GET /executors/by-ip` and `GET /executors/{id}/tesla` remain unchanged
within API major 1. They are marked `deprecated: true` in OpenAPI and point to
the new routes. `verify_pcap.py` moves to the new routes. It falls back to the
old ones when the dispatcher does not offer them.

## Results

| Verdict | Meaning |
| --- | --- |
| `verified` | Every packet in the group carries a valid tag for the named run at the named epoch (±1 epoch of clock skew). The group also records whether this was established by `server` or `offline`. |
| `invalid` | History covers the time and no candidate run reproduces the tags. `reason` is `tag_mismatch`, `no_run` (no run was active from that address) or `mixed_runs`. |
| `pending` | The key is not yet disclosed and no server answer was possible. This happens with `--offline`, when the executor is offline, or when the budget is exhausted. `pending_until` is the disclosure time; retry then. |
| `missing` | The dispatcher no longer holds, or never held, the schedule or keys for that time (before `retained_from`, or lost). This is no evidence either way. |
| `unsupported` | The group cannot be checked. `reason` is one of IPv6, SCION, unknown link type, truncated packet, unknown tag spec, too many candidates, or over a work cap. |

A verdict attributes packets to a run. It says nothing about whether the
measurement was consented to or whether its conclusions are sound.

## Evidence

The evidence bundle is a JSON file that lets a verifier repeat the check
without a capture:

```json
{
  "format": "debuglet-verification-evidence", "format_version": 1,
  "created_at": "…", "tool": {"name": "dbl", "version": "…"}, "tag_spec": 1,
  "dispatcher": {"url": "…", "api_version": "1.10"},
  "packets": {"count": 17, "digest": "sha256:…",
              "items": [{"data": "<base64 first 64 bytes>", "captured_at": "…"}]},
  "groups": [{"verdict": "verified", "method": "server", "run_id": "…",
              "executor_id": "…", "epoch": 1234, "packets": [0, 1, 2],
              "schedule": {…}, "keys": [{"epoch": 1234, "key": "…"}]}],
  "receipts": [{"key_id": "…", "payload": "<base64 canonical JSON>", "signature": "…"}]
}
```

The digest is SHA-256 over the concatenated `uint16 length ‖ data ‖ int64
captured_at_ns` of all packets in order. Offline groups carry their schedule
and keys, and server groups are covered by a receipt. Once #71(b) lands, the
schedule also carries the operator signature.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Capture read by the CLI and SDK | 64 MiB, 1 000 000 packets | Bounded memory; larger captures are rejected, not truncated |
| Tag computations per `Verify` | 1 000 000 (packets × candidates × 3 epochs) | Bounded CPU; groups beyond the cap are `unsupported` |
| Hash walk per chain | At most `chain_length`, done once per chain and cached | Keys are checked against `k0` without an unbounded walk |
| Candidates per lookup | 32 | Larger answers are `unsupported: too many candidates` |
| Keys per page | 1024 epochs | |
| Packets per `POST /attribution/verify` | 256, body ≤ 64 KiB, ≤ 16 groups | |
| Server budget `R` per (executor, epoch) | 16 group queries, shared by all requesters | Each query tests at most one guess of a 16-bit tag, so forgery succeeds with probability at most `R/65536 ≈ 0.02 %` |
| Clock skew | ±1 epoch | As today |
| History retention | Operator-configured, default 90 days | `missing` before `retained_from` |

An exhausted budget only delays verification until disclosure (`pending`). It
cannot make a valid group `invalid`. Queries are also rate-limited per client
address, which makes exhausting a budget cost several addresses.

## Privacy

A verifier learns the run ID, the executor ID and its public schedule for an
address and time it names. It does not learn the account, the debuglet or the
results; a run ID grants no access to owner routes. The operator maps a run to
its account when handling an abuse report. A `server` query sends the
dispatcher the first 64 bytes of each submitted packet (the probe's own
headers and the recipient's address). The dispatcher keeps the digest and the
receipt for abuse handling, not the packets.

## Delivery order

1. Disclosure delay `d ≥ 2`, configurable, default about 15 minutes
   (fix/tesla-disclosure-delay). *Landed.*
2. #71(a): durable disclosed-key history, a dated run-by-address record, and
   `GET /attribution/candidates` and `/attribution/keys`. The old routes are
   deprecated. *Landed* (dispatcher schema 13, API 1.9), with the dispatcher
   side of disclosing an old chain's tail after an executor restart; the
   executor side, re-deriving the previous chain from its seed and
   generation and disclosing it with `tesla_key_anchor`, is open.
3. #73: `dbl verify` offline, `client.Verify` and `ReadCapture`, result
   categories, work caps, the evidence bundle, and shared vectors with
   `verify_pcap.py`.
4. #341: `POST /attribution/verify`, the executor query over the control
   session, budget `R`, receipts and `/attribution/receipt-keys`. The command
   selects the method automatically.
5. #71(b, c): operator-signed schedule parameters, carried in candidates and
   evidence; chain rollover with an overlap window.
