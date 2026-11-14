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
the original advertised schedules and runs through their later expiry plus ten
seconds or the refusal probe's last reserved end plus two seconds, whichever is
later. It requires 40–120 successful runs over at least 60 seconds before renewal,
with at most one run per executor at a time, then two successful runs after renewal.
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

Before renewal, the test submits one two-run TEST batch scheduled beyond the
later original expiry. It requires refusal, at least one failed
terminal result and at most one unknown outcome. At least one owned executor log
must identify a validation `FailedPrecondition` for one of those exact run IDs;
an unrelated transport failure cannot satisfy this check. A sibling's explicit
refusal can cancel an upload whose outcome is then uncertain; the dispatcher
preserves that uncertainty as `RunStateUnreconciled`. A failed terminal result
whose error says `outcome unknown` also counts as unknown. Neither cancellation
NotFound nor lack of a destination exchange proves that a run never executed.

Healthy runs must have no unknown outcomes. The test starts no further
sustained-load batch within 18 seconds of the first original expiry, leaving
room for the 12-second renewal lead window and run completion. Two seconds
after the later original expiry, both
executors must be ready with newer advertised anchors. The test then requires
two successful measurements, one per executor, under those replacement schedules.

The SDK may report an unknown batch upload outcome. The fixture records that
response, locates both run IDs and reserved ends in the owned database, and
checks their public states after refusal and at the observation horizon. They
must remain refused, with no unexpected destination exchange after the healthy
workload. The fixture does not retry, fabricate terminal results, or claim to
validate later window-expiry reclamation. Missing identities, query errors,
successful refused jobs, two uncertain results or missing renewal fail the test.

The workflow uploads configuration, per-run timing, resource samples, outcomes,
package identity, test/build logs and cleanup results for 30 days. It excludes
the raw `state-*` directories containing databases and ephemeral credentials.
Local failures preserve those directories under `.cache/ci/soak/` for private
diagnosis; the hosted runner discards them when its VM is removed. Every normal
test exit joins the target goroutines and daemon process groups. The launcher
also removes and checks the isolation containers, including after a timeout.
This does not test eBPF enforcement, clock jumps, public deployment capacity or
funded payments.
