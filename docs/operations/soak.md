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
ten seconds or the expiry probe's last reserved end plus two seconds, whichever
is later. It submits at least 40 successful runs over at least 60 seconds,
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
test does not claim automatic rotation. Healthy runs must have no unknown
outcomes. After both expiries it submits one two-run TEST batch and requires
refusal, at least one failed terminal result, at most one unknown outcome, and
no destination exchange during the observation interval. A sibling's explicit
refusal can cancel an upload whose outcome is then uncertain; the dispatcher
preserves that uncertainty as `RunStateUnreconciled`. A failed terminal result
whose error says `outcome unknown` also counts as unknown. Neither cancellation
NotFound nor lack of a destination exchange proves that a run never executed.

The SDK may report an unknown batch upload outcome. The fixture records that
response, locates both run IDs and reserved ends in the owned database, and
records their public states immediately and after the observation interval.
It does not retry, fabricate terminal results, or claim to validate later
window-expiry classification. Missing identities, query errors, unexpected or
successful expiry outcomes, and two uncertain results fail the fixture.

The workflow uploads configuration, per-run timing, resource samples, outcomes,
package identity, test/build logs and cleanup results for 30 days. It excludes
the raw `state-*` directories containing databases and ephemeral credentials.
Local failures preserve those directories under `.cache/ci/soak/` for private
diagnosis; the hosted runner discards them when its VM is removed. Every normal
test exit joins the target goroutines and daemon process groups. The launcher
also removes and checks the isolation containers, including after a timeout.
This does not test eBPF enforcement, clock jumps, public deployment capacity or
funded payments.
