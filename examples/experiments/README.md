# Five-executor experiment

This example submits five ordinary TEST runs as one batch. The batch transaction
is the experiment ID; the saved receipt records each order ID, run ID, executor,
WASM path and SHA256, arguments and requested policy. Each participant may use a
different WASM file and arguments. There is no role or topology configuration.

The included `peer` guest obtains its UDP listener before announcing readiness.
The dispatcher exchanges the participants' opaque endpoint metadata and assigns
one future start time after all five are ready. Each guest waits for that time,
sends a datagram directly to each of the other four executors, and reports all
four arrivals. The output contains the requested start, actual local start,
send/receive timestamps and final peer count. No experiment traffic passes
through the dispatcher.

Use a dispatcher and five distinct connected executors built from this revision.
Configure UDP listeners with reachable public hosts and available port ranges on
each executor. Both operator destination policy and the per-run `addresses` must
permit the peer hosts; metadata does not grant network access. `dbl up` has only
one executor and is not sufficient for this example.

```sh
GOOS=wasip1 GOARCH=wasm go build -o examples/experiments/peer/debuglet.wasm ./examples/experiments/peer
# Use your existing saved connection and login:
dbl nodes
cp examples/experiments/five.json experiment-definition.json
# Replace executor-1 through executor-5 with actual IDs and the example
# addresses with peer IPs/CIDRs allowed by your operator policy.
go run ./examples/experiments/run -manifest experiment-definition.json \
  -receipt experiment-receipt.json > experiment-results.json
```

The WASM paths in the definition are relative to your working directory. Set
`sha256` to a known lower-case digest to reject changed files before submission;
leave it empty to record the submitted digest. The runner uses the same saved
connection and credentials as `dbl`; `-config` and `-dispatcher` select another
profile. `-endpoint http://127.0.0.1:9000` explicitly selects a local development
dispatcher without loading a saved credential. Remote TEST use also needs
`-allow-remote-test` and server authorization. No payment activation is performed.

The receipt file must not already exist. It is written even when submission
returns an error, preserving known identities for inspection. An uncertain
submission must not be blindly resubmitted. Existing output and cancellation
routes remain usable independently:

```sh
go run ./examples/experiments/run -action results -receipt experiment-receipt.json \
  > experiment-results.json
go run ./examples/experiments/run -action cancel -receipt experiment-receipt.json
# Decode the ordinary result exports' base64 guest output:
jq -r '.results[].output.entries[].output | @base64d' experiment-results.json
```

`results` captures a snapshot without waiting. `submit` waits up to `-timeout`
(default 90s), then requests cancellation of known runs. Cancellation
acknowledgement is not proof of termination. A missing participant is bounded by
the guest/dispatcher deadlines; a lost UDP datagram is bounded by each run's
`timeout_ms`. This example fails rather than retrying packets or replacing members.
Ready waits for at most 30 seconds and is also bounded by the run lifetime and
caller deadline. Keep the policy budget longer (the sample uses 60s). Metadata
is limited to 4KiB per participant. The guest requires the optional
`debuglet_experiment_v1.ready` host extension. Declaring readiness is persistent;
cancelling the local wait does not withdraw it. Cancel the run to withdraw.

The shared start is a requested time, not atomic distributed execution. Host
clocks may differ, and these guest-reported timestamps are not a clock
synchronization or authenticated packet-evidence claim. UDP can lose packets;
network reachability, NAT traversal and clock setup remain operator concerns.

Native applications can call `client.SubmitExperimentTEST`,
`client.ExportExperiment` and `client.CancelExperiment`. Guest authors call
`debuglet.Ready(ctx, metadata)` after their setup and
`debuglet.WaitStart(ctx, experiment)` before beginning their own algorithm.
All participants must call Ready; membership is fixed by the submitted batch.
