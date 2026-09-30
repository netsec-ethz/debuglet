# Compiler and guest resource limits

The executor has two explicit runtime profiles. Empty `isolation.profile`, or
`"trusted"`, keeps the local TEST engine inside the daemon. That engine limits
WASM memory to 4,096 pages (256 MiB) and uses joined cancellation and the
[socket limits](socket-limits.md), but does not provide a hard compiler or
process memory/CPU boundary.

`isolation.profile = "shared"` runs compilation and WASI execution in one private
child per run on Linux. The parent retains network policy, sockets, packet
attribution, shared bandwidth accounting, ports and durable output. The child
uses the parent’s network policy and quotas for every guest network import.
A synchronous inherited socket carries
fixed import calls and bounded memory transfers; there is no extra TCP listener.

## Required host setup

The shared profile requires Linux with cgroup v2, `CLONE_INTO_CGROUP` and
`cgroup.kill` (Linux 5.14 or newer), and writable delegated `memory`, `cpu` and
`pids` controllers. Mount cgroup v2 at `/sys/fs/cgroup`. The executor must run
inside the configured delegation, in a different leaf from its worker groups.
Use an exclusive delegation sized within the host resources available to this
service. Its root must already enable these controllers for its children and
have finite `memory.max` and `cpu.max` limits. An unlimited user service root
is insufficient; a separately limited delegated service or scope is required.
Startup refuses an absent, read-only or incomplete delegation; it does not fall
back to the trusted profile.

A systemd user delegation with the executor launched in a user scope is one
supported arrangement. A system service needs an equivalent delegated tree with
its daemon in a separate leaf. Set the root to the actual delegation on that
host. Merely creating a directory while running in an unrelated SSH session is
insufficient: Linux also checks process-migration authority. No blanket
privileged container is required. Containers need an explicitly writable
cgroup delegation; a default read-only cgroup mount cannot provide this mode.

The parent needs only the permissions already required by its selected packet
counter/tagger. The child clears capabilities, disables privilege acquisition
and core dumps, limits its descriptors to 32, and replaces its initial process
image before reading guest code. It inherits only the private bridge and null
standard streams, with a fixed runtime environment. WASI receives no host
filesystem mounts or inherited environment. Its arguments come from the admitted
run. A parent-death signal stops the worker if the supervisor exits.

## Explicit budgets

All shared-profile resource values must be supplied. This example matches the
small two-worker Linux test profile; it is not automatic host sizing:

```toml
[isolation]
profile = "shared"
cgroup_root = "/sys/fs/cgroup/system.slice/debuglet-executor.service"
node_memory_bytes = 536870912
node_cpu_quota_us = 100000
node_pids = 128
control_memory_reserve_bytes = 134217728
control_cpu_reserve_us = 25000
compile_memory_bytes = 268435456
compile_cpu_quota_us = 50000
compile_wall_ms = 10000
compile_concurrency = 1
compile_queue = 1
run_memory_bytes = 268435456
run_cpu_quota_us = 50000
run_wall_ms = 30000
worker_pids = 64
memory_pages = 1024
```

CPU quotas use a fixed 100,000-microsecond period: 50,000 allows half one CPU.
The aggregate worker group enforces the node limits; each child enforces its
phase's limits. Swap is disabled for the worker groups. Memory includes the Go
runtime, compiler, compiled module and WASI memory, not just the guest heap.
`memory_pages` uses 64 KiB pages and must fit within `run_memory_bytes`.
The positive `control_memory_reserve_bytes` and `control_cpu_reserve_us` values
are explicit capacity left outside the aggregate worker limits for the daemon,
SQLite and control connections. Before creating workers, startup checks that
node limits plus these reserves fit the finite delegation limits and every
tighter visible ancestor. CPU periods are compared exactly. For this example,
the delegation needs at least 640 MiB and 1.25 CPUs; provision additional room
for the deployment as needed. This is a configured capacity check, not an
automatic estimate of daemon usage or a guarantee of control-request latency.
The operator must keep the delegation within available host and CPU-affinity
resources, and must not place unrelated workloads in it.

Compilation has its own concurrency and queue bounds. Its wall budget includes
queueing, process startup, transfer and compilation, independent of the later
run timeout. A full compilation queue refuses immediately. Node memory and PID reservations
are checked when a compiler seat is obtained; waiting for that seat remains
inside the compilation deadline. Compilation success releases its compiler seat, but the child's larger phase
memory reservation and PID reservation remain held until the child is killed
or exits, is reaped, and its group is removed. A caller timeout alone releases
nothing. A failed cleanup keeps its reservation and causes shutdown to report
uncertainty. Reconnects retain the same node supervisor and budgets.

Execution applies the configured runtime limits and the run's existing policy
timeout, whichever ends first. A quota failure or cancellation closes the
bridge, cancels parent host calls, kills and joins the child, and closes the
parent's networking resources. A failed or expired compiler cannot start a
new guest. Repeated close is idempotent and still reports late parent cleanup
errors after host calls have joined.

Modules are at most 24 MiB and shared-profile arguments at most 1 MiB including
length prefixes. Host memory transfers are at most 8 KiB; bridge/output frames
are at most 16 KiB. The output path retains its bounded queue, rate limits and
[storage/finality contract](output-limits.md). Accepted output remains durable;
a failed worker does not invent successful execution or complete a refused
output suffix.

## Outcomes and scope

Public failures distinguish `compilation resource budget exceeded`,
`compiler worker failed`, `execution resource budget exceeded`,
`compiler capacity unavailable` and `guest worker failed`. An ordinary rejected
module reports `module does not compile`. Detailed diagnostics belong to the
operator's explicitly enabled private debug sink. Socket and network-policy
failures keep their existing fixed classifications.

These cgroups contain the compiler, WASI runtime and guest linear memory.
Network host calls intentionally execute in the parent. Their guest-directed
copies and socket registries are bounded, but parent TLS, DNS and other network
library allocations are not covered by the child's kernel memory limit and can
consume the declared control reserve.
This is a resource boundary for those worker processes, not a claim that all
parent host-call costs or a runtime escape are contained. SCION remains outside
the supported shared socket-accounting profile; startup rejects enabling it
with `isolation.profile = "shared"`. Unrelated processes and external
storage writers can still consume host capacity.

The Linux fixtures exercise small memory-page growth, ordinary invalid modules,
a finite CPU task under a short wall budget, worker admission/reaping, and real
TCP quota/cancellation, guest memory-range rejection, and a small worker memory
limit with a healthy guest and live control requests. They require an
explicit private test delegation and skip when it is not supplied; an ordinary
unit-test pass alone does not establish kernel containment on another host.
The maintained kernel CI lane supplies an owned finite delegation, requires
every shared-worker witness to pass without skips, and checks that all worker
cgroups have been removed before the unit exits.
