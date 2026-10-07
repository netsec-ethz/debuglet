# Simulator trace fixtures

Generated with companion simulator commit
`9d747d40796afe4bf029330cb49ba508b930ebf3`, using Go 1.26.8 on Linux amd64:

```sh
go run . -scenario congestion -seed 7 -trace congestion.json
go run . -scenario churn -seed 7 -trace churn.json
go run . -scenario hierarchical -seed 7 -trace hierarchical.json
go run . -replay testdata/shared-destination.json -trace shared.json
```

The shared scenario uses seed 0 and explicit input, not random generation.
`sim_trace_replay_test.go` pins each whole-file SHA-256 and logical trace digest.
The congestion trace is unchanged from simulator `e918b0c1`.

Each trace replays against the real core destination owner, overlapping
scheduler reservations and per-executor application limiter. Tests compare
admission and removal, floor/ceiling bounds, destination shares handed to each
executor, runtime limit conservation and final ownership release. They include
capacity changes during churn and per-address limits expanded from small CIDR
prefixes. Prefix limits are not aggregate CIDR budgets. Sources in these
fixtures map one-to-one to executors with equal capacity; core does not have
an independent source allocator in this comparison. Per-job fair shares can
differ between models while all shared invariants hold.

The simulator's previous shared-destination allocation spent 500 Mbit/s across
a 400 Mbit/s address; hierarchical seed 7 spent 500 Mbit/s across a 200 Mbit/s
address. These inputs now complete successfully after the simulator began
reserving and sharing destination and source resources above admitted floors.
The core comparison admits the same jobs and conserves each destination budget.

A failed event prints the shortest applied prefix, including the scenario name,
seed, filter, capacities and original events. Save it as `failure.json`, then
run the companion with `-replay failure.json -trace replay.json`. A simulator
invariant violation also writes a `.minimal.json` trace. Neither model check
measures packets, kernel enforcement, burst behavior or distributed timing.
