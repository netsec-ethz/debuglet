# Scheduled local TEST soak

The `Scheduled TEST schedule soak` workflow runs daily and supports manual runs.
It installs the candidate package and runs one dispatcher, two executors and two
owned loopback TCP destinations in a container without external networking.
SUI is disabled and traffic uses the fallback counter. Reproduce it on Linux with
Docker and the repository's prepared CI image:

```sh
bash scripts/ci-github.sh soak
```

Each executor has a one-second TESLA epoch and 120-key chain. The test records
the advertised schedule identities and runs through the later actual expiry plus
ten seconds. It submits at least 40 successful runs over at least 60 seconds,
with at most one run per executor at a time and 120 successful runs in total.
Each run exchanges a unique challenge with its assigned destination and must
report the matching output and successful terminal state. The destination's
accept timestamp measures delay from the requested start, rather than from a
status poll.

The fixture checks these provisional bounds; they are regression limits for
this small configuration, not a general capacity or production support claim:

| Measurement | Limit |
| --- | --- |
| Start delay | 3 seconds |
| Completion, including scheduled wait | 8 seconds |
| Resident memory per daemon | 512 MiB; growth after 8 runs at most 128 MiB |
| Open descriptors per daemon | 128; growth after 8 runs at most 32 |
| Combined owned databases and daemon logs | 256 MiB |

The executor currently refuses new work after its finite chain expires; this
test does not claim automatic rotation. After both expiries it submits one
two-run TEST batch and requires refusal, reconciled failed terminal results and
no destination exchange. The SDK may report an unknown upload outcome; the
fixture records that response and locates its run IDs in the owned database to
verify the public terminal results without submitting another transaction.

The workflow retains configuration, per-run timing, resource samples, outcomes,
package identity and cleanup results under `.cache/ci/soak/` for 30 days.
Failures retain the owned databases and daemon logs for diagnosis. Every normal
test exit joins the target goroutines and daemon process groups. The launcher
also removes and checks the isolation containers, including after a timeout.
This does not test eBPF enforcement, clock jumps, public deployment capacity or
funded payments.
