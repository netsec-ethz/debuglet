# Probe verification

This note records how the recipient of a probe checks which Debuglet run sent
it. It is a design for #71, #73 and #341; steps 1 to 3 of the
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
be verified. `dbl verify` and `client.Verify` check a capture offline against
these routes and write and check [evidence bundles](#evidence); the server
method (#341) does not exist yet, so a group whose key is not disclosed is
`pending`. The reference verifier
[`tools/verify_pcap.py`](../tools/verify_pcap.py), mirrored by the website's
`verify.ts`, uses the same routes and falls back to the deprecated
`GET /executors/by-ip` (account required, the caller's own runs among the
executor's last 20) and `GET /executors/{id}/tesla` (current chain only). An
executor restart still loses the last `d` epochs of its chain: the dispatcher
accepts a disclosure for an earlier recorded chain (`tesla_key_anchor` on the
heartbeat), but the executor does not yet re-derive and disclose that tail.
Nothing can be verified before disclosure.

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
           [--output text|json] [--evidence <file>] [--source <address|prefix>,…]
```

- No account or login is needed, and no credential is sent. The dispatcher is
  the selected connection (`--endpoint` or `--dispatcher`).
- Each group is verified by `server` or `offline` automatically, and the
  output says which. `--offline` never uploads packets. Groups whose key is not
  disclosed are then `pending`. Until #341 lands every check is `offline`,
  with or without the flag.
- `--at` sets the capture time of every packet, overriding the capture's own
  timestamps (for example for a capture whose clock is known to be wrong).
- `--evidence` writes the evidence bundle. Passing a bundle instead of a
  capture checks it again offline, together with its receipt.
- `--source` checks only the packets from the given addresses or prefixes and
  skips the rest before any lookup. A lookup covers one address for one epoch
  of the runs it names, but an address without a run needs a lookup per
  second of its traffic (the shortest epoch), so unrelated traffic in a
  capture costs lookups at the dispatcher's rate limit. Lookups go
  round-robin over the addresses, busiest first, so every address gets its
  first lookup before any gets its second; over the [cap](#limits) the
  remaining packets are `unsupported: work_cap`, naming `--source`.

Text output has one line per group, grouped by run:

```
verified     run 6f1c2b1d…  executor exec-zrh-1  192.0.2.4  2026-09-29T09:02Z  40 packets  via offline
invalid      192.0.2.7  2026-09-29T10:15Z  3 packets  tag_mismatch
pending      198.51.100.4  2026-09-29T10:20Z  5 packets  until 2026-09-29T10:35Z
missing      203.0.113.9  2025-11-02T08:00Z  7 packets  no history retained for that time
unsupported  2001:db8::1  2 packets  IPv6 is not tagged
```

A summary follows: the counts, each verified run in full with what an offline
verdict does and does not show, one line of explanation and next step per
reason (for example "Retry after 10:35 UTC" for `pending`), and where the
evidence bundle was written.

`--output json` prints the [report](#results) instead. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Every group is `verified`. |
| 1 | Usage, read or network error; nothing is concluded. Usage errors, including those in the global options, exit 1 here, not 2 as for other commands, so that 2 always means `invalid`. |
| 2 | At least one group is `invalid`. |
| 3 | No group is `invalid`, but at least one is `pending`, `missing` or `unsupported`. |
| 124, 130 | The command timed out or was interrupted, as for every command; nothing is concluded. |

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
routes are part of the unreleased API 1.11). They are public
(`security: []`), rate-limited per client address (10 requests per second,
burst 40, per TCP peer and per /64 for IPv6, or per `X-Forwarded-For` client
behind a proxy listed in `[attribution] trusted_proxies`; `429 rate_limited`
with `Retry-After`), and answer the usual `{code, message}` errors. Their
field names follow `GET /executors/{id}/tesla`: an integer field carries its
unit in its name (`_unix_ns`, `_ns`, `_seconds`, `_epochs`), and other times
are RFC 3339.

| Route | Purpose |
| --- | --- |
| `GET /attribution/candidates?ip=&at=` | Dated lookup: the runs active from `ip` within one epoch of `at` (RFC 3339). Each candidate gives `executor_id`, `run_id`, active interval (`active_from`, `active_to`), `ip_source` (`observed` or `advertised`), the schedule `{chain_id, k0, t0_unix_ns, epoch_seconds, disclosure_delay_epochs, chain_length, tag_spec}`, `disclosed_through` (the latest disclosed epoch, 0 for none), `disclosed_through_at_ns` (when the dispatcher recorded that key, 0 for none) and `next_disclosure_at_ns` (the earliest time the key of `disclosed_through + 1` may be disclosed, `t0_unix_ns + (disclosed_through + 1 + d)·I`). `chain_id` is the hex of the first 16 bytes of SHA-256(`k0`), and `chain_length` 0 when the executor did not report it. `tag_spec` is the version the executor reported with the chain when it registered: 1 is tag spec v1, 0 is legacy (an executor that did not report `debuglet-tag-v1`, including every executor that predates the report), and a v1 verifier reports a legacy chain's packets `unsupported`, not `invalid`. The answer includes `retained_from`, so that `missing` can be told apart from "no run", and `truncated` when more than 32 runs matched. |
| `GET /attribution/keys?executor_id=&chain_id=&from_epoch=&to_epoch=` | Disclosed keys of one chain, at most 1024 epochs per page, with `next_epoch` for the next page (null on the last). `from_epoch` defaults to 1 and `to_epoch` to no bound. Undisclosed epochs are absent. The client checks every key against `k0`. |
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
| `unsupported` | The group cannot be checked. `reason` is one of IPv6, SCION, unknown link type, truncated packet, unknown or legacy (pre-v1) tag spec, too many candidates, or over a work cap. |

Machine reasons (`reason`): `invalid` has `tag_mismatch`, `no_run`,
`mixed_runs`; `pending` has `not_disclosed`; `missing` has `not_retained`
(before `retained_from`) and `keys_missing` (the run is on record but no key
at or above the epoch is); `unsupported` has `ipv6`, `not_ipv4`,
`too_short`, `malformed`, `fragment` (the tag spec's own reasons),
`link_type`, `tag_spec` (a candidate chain reports tag spec 0, the legacy
pre-v1 tag, or another version), `disclosure_delay` (d < 2), `schedule`,
`bad_key` (a served key does not hash to `k0`), `no_signing_key` (epoch 0 or
past the chain's end), `key_public` (every candidate key may already have
been public at the capture time plus the clock tolerance), `ambiguous` (more
than one run reproduces every tag; the runs are listed),
`too_many_candidates` and `work_cap`. A group with an uncheckable candidate
and an unmatched packet is `unsupported`, not `invalid`, since that candidate
may be the sender.

Each group also reports `matched` and `unmatched` packet counts, since a
count of matches is meaningful only together with the non-matches (tag spec
section 7), the number of candidate runs, and for a verified group
`false_match_bound`, N·(2·2⁻¹⁶)^k for N candidates and k packets, and
`disclosed_at`, the earliest time the latest key it used could have been
public: the packets prove the run only if they were captured before it.

Offline checks follow tag spec section 6: candidate epochs are `t` and
`t − 1` only, epoch 0 never signs, a schedule with `d < 2` is refused, and an
epoch whose key could already have been public at the capture time plus the
clock tolerance (default 1 s) is skipped, allowing the dispatcher's 5 s for
an executor clock that leads.

A verdict attributes packets to a run. It says nothing about whether the
measurement was consented to or whether its conclusions are sound.

## Evidence

The evidence bundle is a JSON file that lets a verifier repeat the check
without a capture:

```json
{
  "format": "debuglet-verification-evidence", "format_version": 1,
  "created_at": "…", "tool": {"name": "dbl", "version": "…"}, "tag_spec": 1,
  "dispatcher": {"url": "…", "api_version": "1.11"}, "clock_tolerance_ms": 1000,
  "packets": {"count": 17, "digest": "sha256:…",
              "items": [{"data": "<base64 first 64 bytes>", "captured_at": "…"}]},
  "groups": [{"verdict": "verified", "method": "server", "run_id": "…",
              "executor_id": "…", "epoch": 1234, "packets": [0, 1, 2],
              "schedule": {…}, "keys": [{"epoch": 1234, "key": "…"}]}],
  "lookups": [{"ip": "…", "at": "…", "retained_from": "…", "candidates": […]}],
  "chains": [{"executor_id": "…", "schedule": {…}, "keys": [{"epoch": 1234, "key": "…"}]}],
  "receipts": [{"key_id": "…", "payload": "<base64 canonical JSON>", "signature": "…"}]
}
```

The digest is SHA-256 over the concatenated big-endian `uint16 length ‖ data
‖ int64 captured_at_ns` of all packets in order. Offline groups carry their
schedule and keys, and server groups are covered by a receipt. Schedules and
candidates use the field names of `GET /attribution/candidates`. `lookups`
records the dispatcher's answer for every group and `chains` every key the
check used, so `dbl verify evidence.json` and `client.VerifyEvidence` repeat
the whole check without the capture or the dispatcher: they check the digest,
walk every chain's keys to its `k0`, recompute every group from the packets,
lookups and keys as of `created_at`, and fail when a recorded group differs.
The lookups and schedules remain the dispatcher's claims, and until #71(b)
nothing in the bundle authenticates them: the chain walk ties every key to
the recorded `k0`, but `k0` and the other schedule fields (`t0_unix_ns`,
`epoch_seconds`, `disclosure_delay_epochs`, `chain_length`, `tag_spec`) and
the lookups can be edited consistently. A larger `disclosure_delay_epochs`,
for example, turns a `key_public` group into a `verified` one that still
recomputes. A bundle therefore shows that its record is self-consistent,
not that the dispatcher said it; check the schedule against the dispatcher
(or, after #71(b), the operator signature) before relying on it. `api_version` is the API
version the client requires. With `--at`, `at` records the override and the
packets carry it as `captured_at`.

## Limits

| Limit | Value | Why |
| --- | --- | --- |
| Capture read by the CLI and SDK | 64 MiB, 1 000 000 packets | Bounded memory; larger captures are rejected, not truncated |
| Tag computations per `Verify` | 1 000 000 (packets × candidates × 2 epochs) | Bounded CPU; groups beyond the cap are `unsupported` |
| Hash walk per chain | At most `chain_length`, done once per chain and cached; at most 2²⁴ SHA-256 steps per `Verify` | Keys are checked against `k0` without an unbounded walk |
| Lookups per `Verify` | 1024 candidate lookups (one per group: an address and the shortest epoch of the runs the lookup names, or a second for an address without a run; round-robin over addresses, busiest first), 256 key pages | Bounded requests at the dispatcher's rate limit (about 10 per second, so the cap takes under two minutes); groups beyond are `unsupported: work_cap` |
| Evidence bundle | 256 MiB | |
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
   deprecated. *Landed* (dispatcher schema 14, API 1.11), with the dispatcher
   side of disclosing an old chain's tail after an executor restart; the
   executor side, re-deriving the previous chain from its seed and
   generation and disclosing it with `tesla_key_anchor`, is open.
3. #73: `dbl verify` offline, `client.Verify` and `ReadCapture`, result
   categories, work caps, the evidence bundle, and shared vectors with
   `verify_pcap.py`. *Landed*: the tag functions moved to `pkg/tagspec`,
   shared by the taggers and `pkg/client`; `pkg/client` tests run the shared
   vectors through every supported capture format and link type and compare
   the per-packet outcome with `verify_pcap.py`. The website's `verify.ts` is
   a separate companion change.
4. #341: `POST /attribution/verify`, the executor query over the control
   session, budget `R`, receipts and `/attribution/receipt-keys`. The command
   selects the method automatically.
5. #71(b, c): operator-signed schedule parameters, carried in candidates and
   evidence; chain rollover with an overlap window.
