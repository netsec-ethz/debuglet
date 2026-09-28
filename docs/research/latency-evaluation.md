# A controlled UDP latency experiment

This experiment asks one narrow question: **does a small UDP echo sample meet
an 80 ms empirical p95 round-trip limit while receiving at least 90% of its
replies?** No replies is a failed measurement condition, not zero latency.
It demonstrates local SLA checking, not fault localization, a mesh topology,
SCION behavior or production accuracy across independently clocked hosts.

The experiment runs one installed dispatcher and executor, an owned UDP echo
target and a native baseline in a container with only loopback networking.
Payment is TEST-only and the executor uses its fallback packet counter. The
same probe source is compiled natively and to WASM. Three paired repetitions
alternate which implementation runs first. Every trial sends twelve 1 KiB
nonce-and-sequence-tagged latency probes, each with a 400 ms receive deadline.
For twelve replies the nearest-rank empirical p95 is the largest observation;
this small sample does not estimate a population tail with high confidence.

The conditions and expected outcomes are declared before execution:

| Condition | Injection | Expected sample result |
| --- | --- | --- |
| Baseline | No added impairment | Pass |
| Delay 20 | 20 ms on each direction, nominal 40 ms added RTT | Pass |
| Delay 60 | 60 ms on each direction, nominal 120 ms added RTT | Fail latency bound |
| Loss 25 | 25% random drop probability on each direction | Observe; no exact finite-sample loss assertion |
| Rate 128k | Shared 128,000 bit/s shaped queue | Fail latency bound; quantify saturated goodput |
| Loss 100 | Every selected packet dropped | Fail with no RTT observations |

The baseline and rate trials also send a fixed 32 KiB burst, then collect its
32 echo responses with a ten-second deadline. The rate trial must offer at
least four times the configured rate, deliver every echo and stay below the
shared rate in measured echo goodput. Request and reply bytes share that queue;
application echo goodput is therefore not the configured one-direction rate.
The paired native trial measures the same path and workload. A dozen isolated
pings alone would not validate the bandwidth condition.

Linux HTB sends only UDP packets with the owned target's destination **or**
source port into netem; control traffic remains in the default class. Both
classes have a 10 Gbit/s carrier ceiling. Saved filter commands/configurations
and per-trial queue counters show which traffic was selected and the realized
drops. The owned netem leaf is recreated between conditions so omitted options
cannot carry over. Offline analysis checks both saved configurations against
the declared delay, loss and rate, using the pinned tool's JSON units. Random loss can vary between repetitions, and losing either request or
reply loses an echo; 25% per direction does not imply 25% missing replies.

The target independently records receive/send timestamps and processing time
for each nonce/sequence. Analysis reports RTT minus target processing and the
nominal injected delay, as well as paired WASM-minus-native median differences.
These quantities include kernel scheduling and host-call overhead; they are
not an independent wire-clock calibration. Submission-to-completion overhead
also includes scheduling, compilation and output retrieval. Clock uncertainty
and packet/measurement verification remain explicit unknown/unverified fields
in exported results. No CPU-isolated virtualization overhead is claimed.

## Reproduce and inspect

Use the repository's isolated evaluation CI lane on Linux. It needs the pinned
tools image with `iproute2`, an already available `sch_htb`, `sch_netem` and
`cls_u32`, and `NET_ADMIN` in its own network namespace. The runner does not
install host tools, load kernel modules or alter a host interface. Unsupported
kernels fail with a recorded explanation rather than silently skipping work.
Do not invoke its integration test on a shared host network namespace.

The lane builds and verifies the installed candidate, builds both probes, and
writes a directory under `.cache/ci/evaluation/`. Each WASM trial saves the real
versioned SDK result export. After both services have joined, reproduce the
analysis solely from the saved files:

```sh
go run ./internal/acceptance/evaluation /path/to/evaluation/run.DIRECTORY > summary.json
```

The standalone reader uses `client.ReadResult`, validates workload hash and
arguments, and refuses incomplete output, failed/unknown outcomes, missing
trials, mismatched target observations and contradictory predeclared cases.
It does not contact a dispatcher or need credentials. `experiment.json`, native
outputs, `*-result.json`, target events and qdisc counters are the inputs;
`summary.json` contains sample verdicts, empirical timing, actual loss and
paired differences. Keep these inputs together when sharing a plot or claim.

All subprocesses, targets and services join, and the owned qdisc is removed.
Successful raw state is deleted. Failed raw `state-*` directories may contain
ephemeral credentials and are private diagnostic material; share the explicit
measurement files and cleanup report, not those directories.

To plot the saved summary, use a separate analysis environment with
`matplotlib==3.10.3`, then run:

```sh
python3 tools/plot-evaluation.py /path/to/evidence/reproduced-summary.json /path/to/plots
```

This writes standalone SVG and PNG figures and records the plotting version.
The figures show all three repetitions, missing RTT observations, measured
reply fractions, timing excess, burst goodput, and elapsed-time differences.
Matplotlib is an analysis dependency, not an executor or dispatcher dependency.
