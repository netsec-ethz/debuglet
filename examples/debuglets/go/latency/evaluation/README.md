# Paired native/WASM UDP probe

This fixed, bounded probe is used by the [controlled latency experiment](../../../../../docs/research/latency-evaluation.md).
It echoes a 32-hex-character nonce and sequence in 1 KiB UDP datagrams and emits
one JSON report. `latency` sends twelve probes with 400 ms read deadlines;
`both` also sends a 32 KiB burst with a ten-second collection deadline.
Timeouts remain missing observations. Invalid echo identities and non-timeout
transport errors fail the command.

Build from the repository root:

```sh
go build -o latency-native ./examples/debuglets/go/latency/evaluation
make wasm SAMPLE_DIR=examples/debuglets/go/latency/evaluation
```

Arguments are `TARGET NONCE latency|both`. The controlled experiment owns the
echo target and network conditions; use its lane for reproducible baseline
comparisons. The existing parent TCP latency example keeps its own interface.
