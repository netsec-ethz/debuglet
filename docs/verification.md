# Probe verification

This note records how the recipient of a probe checks which Debuglet run sent
it. It is a design for #71, #73 and #341; steps 1 to 4 of the
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
these routes and write and check [evidence bundles](#evidence). A group
whose key is not disclosed yet is sent to `POST /attribution/verify`, whose
executor answers before disclosure (method `server`); with `--offline`, or
when no answer is possible, it is `pending`. The reference verifier
[`tools/verify_pcap.py`](../tools/verify_pcap.py), mirrored by the website's
`verify.ts`, uses the same routes and falls back to the deprecated
`GET /executors/by-ip` (account required, the caller's own runs among the
executor's last 20) and `GET /executors/{id}/tesla` (current chain only). With
a configured TESLA seed and intact generation history, an executor restart can
recover its immediately previous chain for disclosure only. Recovery requires a ready
clock and retirement of the previous signers; the heartbeat carries that
chain's due keys in `extra_disclosures`. See the [recovery conditions and
retention limits](operations/configuration.md#executor-tesla-key-schedule),
including rapid restarts and the lack of a durable dispatcher acknowledgement.
A copied seed or a rolled-back generation database is not a recovery plan.
Before disclosure only the executor can check a tag, through the server
method.

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
  output says which, and names the receipt key of a `server` verdict.
  `--offline` never uploads packets. Groups whose key is not disclosed are
  then `pending`. Without it, the first 64 bytes of at most 256 packets of
  each such group are sent to the dispatcher.
- `--at` sets the capture time of every packet, overriding the capture's own
  timestamps (for example for a capture whose clock is known to be wrong).
- `--evidence` writes the evidence bundle. Passing a bundle instead of a
  capture checks it again offline, together with its receipts.
- `--source` checks only the packets from the given addresses or prefixes and
  skips the rest before any lookup. A lookup covers one address for one epoch
  of the runs it names, but an address without a run needs a lookup per
  second of its traffic (the shortest epoch), so unrelated traffic in a
  capture costs lookups at the dispatcher's rate limit. Lookups go
  round-robin over the addresses, busiest first, so every address gets its
  first lookup before any gets its second; over the [cap](#limits) the  remaining packets are `unsupported: work_cap`, naming `--source`.
- Requests are paced to the dispatcher's documented rate limit (a token
  bucket of 10 per second, burst 40; `VerifyOptions.RequestRate` and
  `RequestBurst` in the SDK). A `429 rate_limited` answer holds every request
  until its `Retry-After` has passed, and the check keeps retrying until the
  command's deadline (5 minutes by default, `--timeout`). It then fails
  with an error that says the dispatcher rate-limited it and how many groups
  remain unchecked (`client.RateLimitedError`).
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
routes are additions of API 1.11 (candidates and keys) and API 1.18
(verify and receipt keys). They are public
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
| `POST /attribution/verify` | Server-assisted check. The request lists up to 256 packets as `{data: base64 of the first min(64, Total Length) bytes of the IPv4 packet, captured_at}`. The response gives for each group `{source, epoch, chain_id, executor_id, run_id, verdict, reason, method, packets, budget: {limit, remaining, resets_at}}` (`packets` are indices into the request; `budget` only for a group with a chain) and a signed `receipt` `{key_id, payload, signature}`. |
| `GET /attribution/receipt-keys` | The dispatcher's current and past receipt-verification keys (Ed25519) with their validity periods. |

The dispatcher forms groups as the offline check does: the packets of one
source address from the first one up to the end of the current epoch of
every run a dated lookup names (a second without a run), and within that
window one group per candidate chain, in the epoch of the first packet's
`captured_at` under that chain. It checks one group at a time against the
candidates of its chain:

- A key on record for the epoch (or a later one it derives from) answers
  from the key store with the tag functions of the offline check:
  `method: offline`, no budget spent.
- An unusable schedule (`tag_spec`, `disclosure_delay`, `no_signing_key`)
  is `unsupported`; a key that is due but not on record is `pending`
  (`not_disclosed`) within two minutes of its due time and `missing`
  (`keys_missing`) after.
- Otherwise, when the executor is connected with that chain, the dispatcher
  charges the group's candidate runs, one trial each, to the budget of that
  executor, chain and epoch, in its own transaction, and then asks the
  executor over the control session which of exactly those candidates, if
  any, reproduces the tag of every packet. The executor never returns tags
  or keys. `matched` is `verified` with the run; `unmatched` is `pending`
  (`unmatched`) until the key's disclosure time: no single candidate
  reproduces every tag, which two legitimate runs from one address in one
  epoch answer as well as forged traffic, so the offline check after
  disclosure decides, per run. `ambiguous` and every executor refusal
  (`unknown_chain`, `epoch_unavailable`, `attribution_unavailable`,
  `too_many`, `malformed`) are `unsupported` with that reason. All of these
  have `method: server`. A group with more candidates than trials remain is
  `pending` (`budget_exhausted`) and charges nothing; an executor that is
  not connected or does not answer is `pending` (`executor_unavailable`).
  A pending group gives `pending_until`, the key's disclosure time.

The budget counts candidate trials because a query with N candidates tests
the presented tags against N derived keys: a forger who submits fabricated
tags learns, per trial, whether one guess matches one run's key. Trials are
charged before the query is relayed and never refunded: an answer lost to a
crash, a timeout or a broken session still counts, so neither a restart nor
a failure resets the budget. A disconnected executor is not asked, so
nothing is charged for it. Only an answer from a disclosed key, which is
split per run, can be `invalid` (`tag_mismatch`), and only when none of the
group's packets matches. With a recorded key, the HTTP response and receipt
list verified run subsets, ambiguous packets, and unmatched packets separately.
Unmatched packets alongside valid ones are `unsupported` (`unmatched`). The
request and response each allow at most 16 groups, including these subsets;
split a request into smaller batches if it exceeds this limit. Before disclosure,
the executor answers for the whole group, without splitting or returning
per-packet matches. The HTTP route checks the epoch of the capture time only,
not the one before it.

The receipt is a detached Ed25519 signature over canonical JSON (keys
sorted, no whitespace) of `{api_version, dispatcher, groups: [{chain_id,
epoch, executor_id, method, packets, reason, run_id, source, verdict}],
packets_digest, query_at}`. `dispatcher` is the configured
`[authentication] public_url`, or the origin the request was addressed to;
`packets_digest` is the [evidence](#evidence) digest of the request's
packets in request order; `query_at` is the dispatcher's clock when it
answered. The callers' `captured_at` enter only through the digest: a
receipt shows what was asked and what was answered when, not when a packet
was observed. `key_id` is the hex of the first 16 bytes of SHA-256 of the
public key, which `GET /attribution/receipt-keys` lists with its validity;
a receipt is valid when its `query_at` lies within that validity. The key is
read from `[attribution] receipt_key_path`, created when absent the first
time either route needs it, and recorded with its validity; a dispatcher
started with another key ends the validity of the earlier one.

`GET /executors/by-ip` and `GET /executors/{id}/tesla` remain unchanged
within API major 1. They are marked `deprecated: true` in OpenAPI and point to
the new routes. `verify_pcap.py` moves to the new routes. It falls back to the
old ones when the dispatcher does not offer them.

## Results

| Verdict | Meaning |
| --- | --- |
| `verified` | Every packet in the group carries a valid tag for the named run at the named epoch (±1 epoch of clock skew). The group also records whether this was established by `server` or `offline`. |
| `invalid` | History covers the time and no candidate run reproduces any packet of the group. `reason` is `tag_mismatch` or `no_run` (no run was active from that address). |
| `pending` | The key is not yet disclosed and no server answer decided the group. This happens with `--offline`, when the executor is offline, when the budget is exhausted, or when the executor found no single candidate that reproduces every tag (`unmatched`). `pending_until` is the disclosure time; retry then. |
| `missing` | The dispatcher no longer holds, or never held, the schedule or keys for that time (before `retained_from`, or lost). This is no evidence either way. |
| `unsupported` | The group cannot be checked. `reason` is one of IPv6, SCION, unknown link type, truncated packet, unknown or legacy (pre-v1) tag spec, too many candidates, or over a work cap. |

A group (one source address in one epoch) whose packets do not all
reproduce one run is split, since one executor running two measurements
toward the same recipient at once legitimately sends packets of both runs
from one address in one epoch. Each packet is attributed to the run whose
tag it reproduces (to the run every matched packet reproduces, when there
is one), and the group is reported as separate entries: one `verified` entry
per run, with that run's packets; one `unsupported: ambiguous` entry for the
packets that each reproduce more than one run; and one entry for the packets
no candidate reproduces. The unmatched entry is `unsupported: unmatched`
(or `pending`, `missing` and so on when a key it needs is not available): the
packets are attributed to no run, but since other packets of the same address
and epoch match, they are no evidence that Debuglet did not send the group
(they may have been altered on the way). A group is `invalid` only when none
of its packets matches. In the CLI and SDK report, every entry of a split
group carries `split`: `{packets, matched, unmatched, runs}` of the whole
group, so each run's match count can be read against the group's non-matches.
The HTTP response and signed receipt identify each subset by its request
packet indices; they do not include this report-only `split` summary.

Machine reasons (`reason`): `invalid` has `tag_mismatch`, `no_run`;
`pending` has `not_disclosed`, and from the server also `budget_exhausted`,
`executor_unavailable` and `unmatched` (no single candidate reproduces
every tag; the offline check after disclosure decides per run); `missing` has `not_retained`
(before `retained_from`) and `keys_missing` (the run is on record but no key
at or above the epoch is); `unsupported` has `ipv6`, `not_ipv4`,
`too_short`, `malformed`, `fragment` (the tag spec's own reasons),
`link_type`, `tag_spec` (a candidate chain reports tag spec 0, the legacy
pre-v1 tag, or another version), `disclosure_delay` (d < 2), `schedule`,
`bad_key` (a served key does not hash to `k0`), `no_signing_key` (epoch 0 or
past the chain's end), `key_public` (every candidate key may already have
been public at the capture time plus the clock tolerance), `ambiguous` (more
than one run reproduces every tag; the runs are listed),
`too_many_candidates`, `work_cap` and `unmatched` (packets of a split
group that no candidate reproduces). A group with an uncheckable candidate
and an unmatched packet is `unsupported`, not `invalid`, since that candidate
may be the sender.

Each group also reports `matched` and `unmatched` packet counts, since a
count of matches is meaningful only together with the non-matches (tag spec
section 7), the number of candidate runs, and for a verified group
`false_match_bound`, N·C(n, k)·(2·2⁻¹⁶)^k for N candidates tried and k of
the group's n packets, a union bound over the candidates and over which k
packets were picked (N·(2·2⁻¹⁶)^n for a group that is not split), and
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
  "groups": [{"verdict": "verified", "method": "server", "run_id": "…",              "executor_id": "…", "epoch": 1234, "packets": [0, 1, 2],
              "split": {"packets": 5, "matched": 5, "unmatched": 0, "runs": ["…", "…"]},
"schedule": {…}, "keys": [{"epoch": 1234, "key": "…"}]}],
  "lookups": [{"ip": "…", "at": "…", "retained_from": "…", "candidates": […]}],
  "chains": [{"executor_id": "…", "schedule": {…}, "keys": [{"epoch": 1234, "key": "…"}]}],
  "receipts": [{"key_id": "…", "payload": "<base64 canonical JSON>", "signature": "…", "packets": [3, 4]}],
  "receipt_keys": [{"key_id": "…", "public_key": "…", "valid_from": "…", "valid_to": null}]
}
```

`split` is present only on the entries of a split group; it was added
within format 1, whose readers ignore unknown fields, but a bundle recomputes
only under the verifier's current grouping. The digest is SHA-256 over the concatenated big-endian `uint16 length ‖ data
‖ int64 captured_at_ns` of all packets in order. Offline groups carry their
schedule and keys, and server groups are covered by a receipt. Schedules and
candidates use the field names of `GET /attribution/candidates`. `lookups`
records the dispatcher's answer for every group and `chains` every key the
check used, so `dbl verify evidence.json` and `client.VerifyEvidence` repeat
the whole check without the capture or the dispatcher: they check the digest,
walk every chain's keys to its `k0`, recompute every group from the packets,
lookups and keys as of `created_at`, and fail when a recorded group differs.
Each receipt lists the bundle's packets its request sent (`packets`); its
signature is checked under the key of `receipt_keys` it names, the key's ID
against its public key, the receipt's `query_at` against the key's validity
and its `packets_digest` against those packets, and its `server` answers
then decide the groups that recompute as pending, exactly as in the live
check. A group whose packets exceed the 256 of one request is checked by
its first 256 packets; the rest stays a separate `pending` entry. The
embedded receipt keys are the dispatcher's claim like the rest of the
bundle: compare their IDs with `GET /attribution/receipt-keys` of the
dispatcher you trust.
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
| Lookups per `Verify` | 1024 candidate lookups (one per group: an address and the shortest epoch of the runs the lookup names, or a second for an address without a run; round-robin over addresses, busiest first), 256 key pages | Bounded requests at the dispatcher's rate limit (paced to 10 per second, burst 40, so the cap takes under two minutes); groups beyond are `unsupported: work_cap` |
| Evidence bundle | 256 MiB | |
| Candidates per lookup | 32 | Larger answers are `unsupported: too many candidates` |
| Keys per page | 1024 epochs | |
| Packets per `POST /attribution/verify` | 256, body ≤ 64 KiB, ≤ 16 source/epoch groups and ≤ 16 result subsets | |
| Server budget `R` per (executor, chain, epoch) | 16 candidate trials (a query charges one per candidate run), shared by all requesters, durable across restarts, never refunded | Each trial tests at most one guess of a 16-bit tag against one run's key, so a forged tag for any candidate of that epoch succeeds with probability at most `R/65536 ≈ 0.02 %` |
| Clock skew | ±1 epoch | As today |
| History retention | Operator-configured, default 90 days | `missing` before `retained_from` |

An exhausted budget only delays verification until disclosure (`pending`). It
cannot make a valid group `invalid`, and neither can a server answer. A
group with more than 16 candidates cannot use the server method. Queries are also rate-limited per client
address, which makes exhausting a budget cost several addresses.

## Privacy

A verifier learns the run ID, the executor ID and its public schedule for an
address and time it names. It does not learn the account, the debuglet or the
results; a run ID grants no access to owner routes. The operator maps a run to
its account when handling an abuse report. A `server` query sends the
dispatcher the first 64 bytes of each submitted packet (the probe's own
headers and the recipient's address), which it relays to the executor of the
candidate runs. The dispatcher logs the packet digest, the number of packets
and groups and the receipt key, not the packets.

## Delivery order

1. Disclosure delay `d ≥ 2`, configurable, default about 15 minutes
   (fix/tesla-disclosure-delay). *Landed.*
2. #71(a): durable disclosed-key history, a dated run-by-address record, and
   `GET /attribution/candidates` and `/attribution/keys`. The old routes are
   deprecated. *Landed* (dispatcher schema 14, API 1.11), with the dispatcher
   side of disclosing an old chain's tail after an executor restart. The
   executor also re-derives the immediately previous chain from its seed and
   generation record (executor schema 8) and sends due keys in
   `extra_disclosures`, subject to the recovery conditions above.
3. #73: `dbl verify` offline, `client.Verify` and `ReadCapture`, result
   categories, work caps, the evidence bundle, and shared vectors with
   `verify_pcap.py`. *Landed*: the tag functions moved to `pkg/tagspec`,
   shared by the taggers and `pkg/client`; `pkg/client` tests run the shared
   vectors through every supported capture format and link type and compare
   the per-packet outcome with `verify_pcap.py`. The website's `verify.ts` is
   a separate companion change.
4. #341: `POST /attribution/verify`, the executor query over the control
   session, budget `R`, receipts and `/attribution/receipt-keys`. The command
   selects the method automatically. *Landed* (dispatcher schema 25, API
   1.18).
5. #71(b, c): operator-signed schedule parameters, carried in candidates and
   evidence; chain rollover with an overlap window.
