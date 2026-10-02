# Go client library

[`pkg/client`](../pkg/client) is the supported Go library for applications that submit debuglets and read their results from a dispatcher. It is a **client library**, not the SDK for writing a debuglet; use [`pkg/debuglet`](debuglets.md) for that.

## Use it

Create a client with a dispatcher endpoint and a credential, then create an intent and submit a debuglet. The working example is in [`examples/client`](../examples/client).

```go
client, err := client.New(client.Options{
    Endpoint: "https://dispatcher.example",
    Credential: sessionToken,
})
if err != nil { /* handle error */ }
```

The library follows the HTTP API contract, including authentication, request validation, submission, state, logs, and cancellation. Pin the module version you test and treat the [OpenAPI document](../api/openapi.yaml) as the wire-level reference.

See [measurement workflows](measurements.md) for account-owned profiles, paginated
batch details, `RetryTEST` and the two-executor `RendezvousTEST` helper.

`Client.Recovery(ctx, id)` makes one bounded request for [recovery inspection](operations/recovery-inspection.md). Unknown classifications and failed workloads are successful inspections; transport and HTTP errors retain their normal types. Older dispatchers without this endpoint return an HTTP 404. The SDK continues to request its 1.3 minimum for existing operations.

`Client.DiscoverExecutors` and `Client.SelectExecutor` provide [capability-aware discovery](operations/executor-discovery.md). Unknown capabilities fail requested filters; selection does not reserve capacity or submit work.

## Read output

`Client.Logs(ctx, id, options)` returns one page and its `Output` metadata.
`Output.State` is `unknown`, `pending`, `complete`, or `truncated`; future values
are preserved and must be treated conservatively. Missing metadata from an older
server becomes `unknown`. The SDK retains its API 1.3 minimum and validates
recognized states without requiring all operations to use API 1.6.

A follower should advance by `page.After`, drain full pages, and finish only when
it reaches `*page.Output.FinalCursor` for complete or truncated output. Complete
output is independent of workload exit. Truncated output remains incomplete;
`LossReason` explains why, including future reason values. Do not interpret
`HasMore == false` or a terminal workload as proof of completion. After draining
a terminal legacy run, report `*client.IncompleteOutputError` instead of success.
The CLI follows these rules; the SDK page method itself does not poll or fail
merely because output is pending, unknown, or truncated.

## Choose an integration surface

| Need | Use |
| --- | --- |
| Shell workflow, demos, and operations | [`dbl`](cli.md) |
| Go application that calls a dispatcher | `pkg/client` |
| WebAssembly measurement written in Go | [`pkg/debuglet`](debuglets.md) |
| Another language | [HTTP API](api.md) |

`Client.AttributionCandidates(ctx, ip, at)` and `Client.AttributionKeys(ctx, executorID, chainID, fromEpoch, toEpoch)` read the public [probe verification](verification.md) history on API 1.11 or newer and work on a client without a credential. The first lists the runs active from an address within one epoch of a time, each with its chain schedule (a `TagSpec` of `TagSpecVersionLegacy` is a pre-v1 chain that tag spec v1 cannot verify); an empty answer for a time before `RetainedFrom` is no evidence either way. The second pages a chain's disclosed keys, 1024 epochs at a time, following `NextEpoch`; check every key against the schedule's `K0` before use. Older dispatchers return 404.

`client.ReadCapture(r)` reads a pcap or pcapng capture (Ethernet with VLAN tags, raw IP, Linux cooked SLL and SLL2, BSD loopback; microsecond, nanosecond and pcapng `if_tsresol` timestamps) of at most 64 MiB and 1 000 000 packets; a larger, malformed or truncated capture is a `*client.CaptureError`, never a partial read. `Client.Verify(ctx, packets, client.VerifyOptions{At, Offline, ClockTolerance})` attributes those packets to runs as [probe verification](verification.md) describes: it groups them by source address and epoch, looks each group up in the attribution history above and checks the tags offline against the disclosed keys, with the tag functions of [`pkg/tagspec`](../pkg/tagspec) that the executor's taggers use. It needs no credential and uploads no packets. The `VerifyReport` has one `VerifyGroup` per group with its `Verdict` (`verified`, `invalid`, `pending`, `missing`, `unsupported`), machine `Reason`, `Detail`, `Method`, `RunID`, `ExecutorID`, `Epoch`, `Time`, `PendingUntil`, `Packets`, the `Matched`/`Unmatched` counts and, when verified, `FalseMatchBound` and `DisclosedAt`. Only a capture or dispatcher that cannot be read is an error; `ErrNoAttributionHistory` names a dispatcher older than API 1.11. `report.Evidence()` returns the [evidence bundle](verification.md#evidence), `client.WriteEvidence` and `client.ReadEvidence` store it, and `client.VerifyEvidence(ctx, ev)` repeats the check offline from the bundle alone, failing with `ErrEvidenceDigest` or an `*EvidenceMismatchError` when it was altered.

`Client.Cancellation(ctx, id)` inspects a durable cancellation request on API 1.9 or newer. It does not retry delivery. `AcknowledgedAt == nil` means the executor acknowledgement is unknown, including when the run has a local terminal result. Older dispatchers can return 404 for this optional route; `Client.Cancel` retains its existing signature and compatibility.

## Browser-approved credentials

`StartDeviceLogin` requests explicit scopes for the client's configured dispatcher.
Display its `VerificationURI` and `UserCode`; keep `DeviceCode` private. Call
`PollDeviceLogin` no faster than the returned interval, honor `slow_down`, and stop
on denial, expiry or consumption. Pass the approved token to `WithCredential`.
`CancelDeviceLogin` ends an abandoned request, `CredentialStatus` reports its
audience and permissions, and `Logout` revokes it. Provider tokens never belong in
`Credential`. See [authentication](operations/authentication.md).
