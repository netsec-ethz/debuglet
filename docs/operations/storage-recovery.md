# Rehearse foreground storage recovery

This drill uses the [foreground TEST backup procedure](backup-restore.md) and a
verified full installed package. It measures a failed backup copy, preservation
of the last valid snapshot, restoration into separate state, and a fresh
measurement. The injected failure is **backup-destination ENOSPC**, not a write
failure in a running daemon's database. It does not test alert delivery.

## Run the drill

Use an owned, disposable Linux amd64 container with the matching source checkout,
the full package installed, and the checkout's supported Go test toolchain and
dependencies. Give that container a dedicated small tmpfs, for example Docker's
`--tmpfs /storage-drill:rw,size=16m,mode=700`. No privileged mode or published port
is needed. The test refuses ordinary filesystems and mounts larger than 16 MiB.

Inside that container, from the source checkout:

```sh
export DEBUGLET_LOCAL_INSTALL_ROOT="$(dirname "$(dirname "$(readlink -f "$(command -v dbl)")")")"
export DEBUGLET_LOCAL_SOURCE_SHA="$(git rev-parse HEAD)"
export DEBUGLET_STORAGE_DRILL_ROOT=/storage-drill
bash scripts/ci-storage-recovery.sh
```

The installed package/source identity must match. The script runs three drills
and records test events in `.cache/ci/storage-recovery-tests.json`; a failed or
missing test cannot pass the check. Each successful event includes a
`storage_recovery` JSON observation with package identity and elapsed times.

## What the observations mean

The drill first completes a real measurement and accepts a future-start run.
After both roles stop and join, it backs up their state. Another original-instance
measurement then completes after the snapshot. A larger subsequent backup fails
on the private tmpfs; the preceding backups must stay byte-identical.

Restoration must preserve the first result and identity. The known post-snapshot
result is absent, demonstrating actual local record loss rather than assuming
zero loss. A new explicitly submitted measurement must complete under a new
control binding. The accepted queued run is checked after its scheduled start;
it and additional retained queued/started fixtures must produce no replayed
output or terminal result. Original and restored instances are never run together.

| Observation | Measurement boundary |
| --- | --- |
| Detection | Failed backup invocation to its joined nonzero exit; not operator notification time |
| Snapshot age | Oldest successful backup observation to failure detection; the demonstrated local recovery-point exposure |
| Restore copy | Start of the two restore commands to their completion |
| Restored measurement | Start of restoration through role readiness and one completed fresh measurement with output |

Detection and restoration durations use monotonic elapsed time. Snapshot age uses
the backup's wall-clock timestamp, so clock changes can affect that observation.

Three sequential Linux amd64 runs of package
`v0.0.0-dev.52d79d7c30eb` on a private 16 MiB tmpfs produced:

| Run | Detection | Snapshot age | Restore copy | Restored measurement |
| --- | --- | --- | --- | --- |
| First | 79 ms | 1,860 ms | 306 ms | 1,851 ms |
| Second | 77 ms | 1,877 ms | 298 ms | 1,844 ms |
| Third | 77 ms | 1,850 ms | 297 ms | 1,845 ms |

For this small local fixture, provisional recovery-point and recovery-time
objectives of **2 seconds each** contain the observed snapshot age and time from
restoration start to fresh output. They are observations rounded up, with little
margin: the drill deliberately loses one post-snapshot result. They do not cover
human response, alerting, backup scheduling or representative production data.

The later wait past the queued run's start time is excluded from recovery timing.
All owned roles and command handles join before a successful observation is
recorded. Retained records do not establish whether earlier remote effects
occurred; this local TEST procedure does not reconcile payment settlement or
reconstruct historical attribution keys. Select operational recovery objectives
from representative measurements, backup frequency and alerting, not these
small-fixture timings alone.
