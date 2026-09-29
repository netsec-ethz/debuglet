# Selecting an executor

`dbl nodes` lists registered executors and their current capability observations.
Use filters to restrict the list to ready executors:

```sh
dbl nodes --protocol icmp --enforcement fallback --min-capacity-bps 1000000
dbl nodes --isd-as 1-ff00:0:110
dbl run --wasm latency.wasm --protocol icmp --allow 192.0.2.1
```

Repeat `--protocol` to require several transports: `tcp`, `tls`, `udp`, `icmp`
(ICMPv4), or `scion`. `--enforcement` selects the actual `ebpf` or `fallback`
packet counter chosen by the executor. It is not an assertion that every
transport carries attribution tags or that a destination is reachable.
`--min-capacity-bps` compares advertised **total** bandwidth; reservations,
destination limits and the requested time window still decide admission.
`--isd-as` matches the executor-reported SCION ISD-AS; equivalent spellings such
as `1-ff00:0:0110` match, and an unknown ISD-AS does not.

`run` submits only when exactly one ready executor matches. If several match,
choose `--executor ID`; that ID must still satisfy every requested filter.
Unknown or expired reports fail requested filters. A selection error issues no
payment intent or upload. The `icmp` filter on `run` also sets the existing
`require_icmp` run policy, so normal admission enforces the request. Other filters
do not create listeners or expand the allowed destination list.

In Go, use `Client.DiscoverExecutors(ctx, client.ExecutorFilter{...})` to list
matches or `Client.SelectExecutor(ctx, id, filter)` to require one. An empty ID
selects automatically. These methods fetch a fresh dispatcher snapshot and never
submit work. Construct the submitted policy separately, including `RequireICMP`
when needed. Selection is an observation, not a reservation: submission may still
be refused if the executor disconnects or available admission capacity changes.

The optional `capabilities` object in `GET /executors` has schema version 1:
positive protocol observations, actual packet-counter type, dispatcher receipt
time and total advertised capacity (`null` until known). Old peers, malformed
reports and unknown schema versions have unknown capabilities. Existing clients
and explicit unfiltered selections remain compatible with older dispatchers.

Reports are tied to the current control binding and expire after 90 seconds.
Executors refresh at most once per 30 seconds on the existing heartbeat; an
omitted heartbeat report does not refresh the previous observation. Replacing
a binding clears its old capabilities and capacity. Expired control sessions
are excluded independently of heartbeat telemetry.

## Attribution state

The `attribution` object in `capabilities` reports whether packets the executor
tags now can be attributed once their TESLA key is disclosed. `dbl nodes` shows
it in the `ATTRIBUTION` column as `available`, `unavailable(REASON)` or
`unknown`; `--output json` carries every field. It is `null` or absent for
executors and dispatchers that predate it, which means unknown, not available.
A malformed attribution state is also `null`; the rest of the report stands.
It is an executor claim, not a verification, and it is not a discovery filter.

| `reason` | Meaning |
| --- | --- |
| `epoch_zero` | The chain anchor k_0 is public and never signs, so nothing sent during epoch 0 (the first `tesla.epoch_seconds` after startup) is attributable. |
| `chain_exhausted` | The key chain has ended; nothing is tagged until the executor restarts. |
| `refresh_failing` | A kernel tagger's latest key refresh failed. Its slot is empty or may still hold the previous epoch's key; `refresh_error` gives a short error of at most 128 bytes. |
| `disclosure_held` | An installed key has held disclosure back for longer than one epoch, so the keys of new tags are not published. This is the case of a tagger whose slot could not be cleared. |

`epoch` is the current key-schedule epoch. With eBPF taggers of running
measurements, `installed_epoch` is the oldest epoch a kernel slot may still
sign with, `last_refresh_at` the oldest last successful key install and
`disclosure_held_since` the end of the held key's epoch; each is `null`
otherwise, including for the fallback tagger, which holds no key. A hold from
each epoch boundary until that boundary's refresh lands is ordinary. The times
are Unix seconds on the dispatcher's clock: its receipt time minus the age the
executor reported.

A change of reason is sent on the next heartbeat rather than waiting for the
30 second report interval. The executor log keeps the full refresh error.

## Tagging mode

The `tagging` object in `capabilities` reports which of a run's packets carry
attribution tags, per address family and for SCION:

```json
"tagging": {"ipv4": "ebpf", "ipv6": "none", "scion": "none", "tag_spec": "debuglet-tag-v1"}
```

| Mode | Meaning |
| --- | --- |
| `ebpf` | The kernel tagger on TC egress tags every packet of the run's marked sockets: TCP, TLS, UDP and ICMP, handshakes and listener replies included. |
| `userspace` | The pure-Go tagger, used where the eBPF tagger does not load: UDP and ICMP datagrams to IPv4 destinations are sent through a raw socket and tagged; TCP and TLS segments are untagged. It needs Linux and `CAP_NET_RAW`. |
| `none` | Untagged. |

`ipv6` and `scion` are always `none` in this version. The report is the node's
capability, the mode a run on this executor is set up to get: `ipv4: ebpf`
where the eBPF packet counter loaded on the configured interface, otherwise
`userspace` (or `none` without raw-socket permission). It does not follow
individual runs. A run whose kernel tagger nevertheless fails to load falls
back to the pure-Go tagger for that run only and logs a warning; the report
does not change. A changed node mode is sent on the next heartbeat. `tagging` is `null` or
absent for executors and dispatchers that predate it, and for a malformed
report of it, which means unknown. It is an executor claim, not a verification
of tags at a receiver, and it is not a discovery filter. The admission snapshot
in a [result](../results.md) keeps the capability reported at admission: what
the run was set up to get, not a measurement of its packets.

`tag_spec` names the [packet-tag specification](../tag-spec.md) the tagged
families follow, `debuglet-tag-v1` from this release on. It is absent for
executors and dispatchers that predate it, which means unknown; such executors
used the unversioned pre-v1 tag, which a v1 verifier does not reproduce. A
fleet runs one version: a verifier applies the specification it implements and
should treat a different or unknown `tag_spec` as unsupported rather than as a
failed match. Because the value is part of the capability report, the admission
snapshot of a result records which specification its tags follow.

**IPv6 on eBPF-tagged runs is refused.** The kernel tagger rewrites the IPv4
identification field and has no IPv6 counterpart yet, so an IPv6 packet from a
run that expects attribution would leave silently untagged. A run whose IPv4
mode is `ebpf` therefore:

- refuses an IPv6 destination on `tcp`, `tls` and `udp` before a socket is
  created. The guest sees the `denied` I/O status, and a run that fails on it
  reports `destination refused: IPv6 not tagged on this executor`. A name that
  resolves to both families is dialled on its IPv4 addresses only; a name with
  IPv6 addresses only is refused. IPv4-mapped IPv6 addresses count as IPv4.
  ICMP remains IPv4 only for every run.
- binds its TCP and UDP listeners to IPv4 only (`0.0.0.0`) instead of
  dual-stack, so no IPv6 peer can reach them, and refuses an inbound IPv6 peer
  should one arrive. A listener is refused when the executor's `public_host`
  is an IPv6 literal, since it could not be reached there; such a node does
  not advertise `tcp` or `udp` listeners in its vantage-point report.

A run with the pure-Go tagger (`userspace` or `none`) does not expect its
streams to be attributed and keeps IPv6 and dual-stack listeners; its IPv6
packets are untagged, as its TCP packets are. Tagging IPv6 (in a Destination
Options header) is later work.

**SCION traffic is labelled untagged, not refused.** The SCION library opens
its sockets internally and offers no hook to set the socket mark, so the eBPF
tagger cannot attribute them. Refusing SCION would remove the transport from
every eBPF node, so the executor reports `scion: none`, which the result's
admission snapshot keeps, and logs a warning once per process when a tagged run
dials SCION. Treat SCION measurements as unattributed.

TCP/TLS/UDP observations reflect the operator's transport switches. ICMP also
requires a successful process-local raw-socket probe (see
[host probes](#host-probes)). SCION requires the operator
switch plus a responsive configured SCION daemon and a local route observation.
The bounded discovery probe accepts literal IP addresses for the daemon and its
control-service address. Hostname configurations remain unknown for discovery;
execution's existing configuration support is unchanged. Initial SCION probing
has a 500 ms bound; later refreshes use at most 100 ms, avoiding DNS and runtime
locks. No measurement packet is sent by these probes. A positive local SCION
observation does not establish an external path or remote deployment.

## Vantage-point metadata

API 1.9 adds four fields to each `GET /executors` entry. Every value names its
`source`: `operator` for dispatcher configuration, `executor-reported` for the
executor's own claims. No label means verified. The
[vantage-point design note](../vantage-points.md) records the provenance model,
privacy rules and the remaining delivery steps.

- `admission`: `offline` until the current control session has sent a
  heartbeat, `maintenance` while the dispatcher's maintenance switch stops
  submission admission, otherwise `ready`. An executor whose control session
  ended is not listed. Normal admission still decides each submission.
- `display`: `display_name`, `city`, `country` and `network`, each
  `{value, source}` with source `operator`, from the dispatcher configuration.
  Unconfigured values are `null`.
- `scion_isd_as`: `{value, source, observed_at}`. The executor reads its local
  ISD-AS from the SCION daemon during the SCION capability probe, so it is known
  only when the operator enables SCION and the daemon answers. Source
  `executor-reported`.
- `listeners`: `{value, source, observed_at}`, the transports on which the
  executor can open run listeners. `tcp` and `udp` need the inbound switch, the
  transport switch and both `public_host` and `public_ports`; `scion` needs a
  positive SCION observation. The listener address is not published, and nothing
  tests external reachability. Source `executor-reported`.

ISD-AS and listeners travel in a `VantagePointReport` (schema 1) beside the
capability report, on the same cadence and 90 second expiry. A malformed report
or unknown schema clears both; older executors leave them unknown. Results
record the ISD-AS and operator metadata at admission in
`provenance.vantage_point`.

Operators label executors in the dispatcher configuration:

```toml
[executors."eth-zurich-1"]
display_name = "ETH Zurich lab"
city = "Zurich"
country = "CH"          # ISO 3166-1 alpha-2, upper case
network = "SWITCH (AS559)"
```

Every key is optional. Text is printable UTF-8 of at most 64 characters without
leading or trailing space; the dispatcher refuses to start otherwise. Changes
take effect when the dispatcher restarts.

No location is inferred from IP addresses, hostnames or account identity. This
version provides no geographical filter; location is the operator's label,
never finer than city.

## Host probes

Executors probe their own host at startup and with every capability report
(at most every 30 seconds, expiring after 90). Every result is
`executor-reported`. The probes are local and read-only: none sends a packet,
changes host state or contacts a time source.

- `capabilities.icmp`: `{state, reason}`. The executor opens and closes a raw
  ICMPv4 socket, which guest ICMP needs. `available` agrees with `icmp` in
  `protocols`. `unavailable` gives a reason: `disabled` (the operator's
  `network.policy.icmp = false`; no socket is opened), `not_permitted` (raw
  sockets need `CAP_NET_RAW`), `ping_socket_only` (raw sockets are refused but
  an unprivileged ping socket opens, which guests cannot use) or `unsupported`.
  The refreshed answer also decides guest ICMP admission on the executor. The
  hello's `icmp_enabled`, which the dispatcher's `require_icmp` check uses, is
  the probe of that hello.
- `capabilities.enforcement_reason`: why the executor uses the `fallback`
  counter: `configured` (`packet_counter = "fallback"`), `no_interface`,
  `not_permitted` (the eBPF attach lacked privilege), `unsupported` or
  `attach_failed`. The executor log keeps the full error. Empty for `ebpf` and
  when unknown.
- `clock`: `{value, source, observed_at}` in `GET /executors`. The value is the
  kernel's clock discipline, read on Linux with `adjtimex` in read-only mode:
  `state` is `synced`, `unsynced` (`STA_UNSYNC`) or `unknown` (not Linux);
  `estimated_error_ns` and `max_error_ns` are the kernel's `esterror` and
  `maxerror`, estimates kept by the host's time daemon rather than measured
  bounds. `readiness` is `degraded` with reason `unsynced` or
  `error_exceeds_bound` when the estimated error exceeds the executor's
  `clock.max_error_ms` (default 100 ms, reported as `error_bound_ns`), `ready`
  within it and `unknown` otherwise. Degraded readiness is reported and logged
  by the executor; it does not refuse admission. `dbl doctor` runs the same
  check locally.
- Host platform: OS, architecture, kernel release, logical CPUs, total memory
  and build version. This is operator-only data and never appears in
  `GET /executors`. There is no live operator view of it yet; it is recorded in
  the admission snapshot `provenance.vantage_point.platform`, which only the
  run's owner and operators can read.

A malformed clock, platform, ICMP state or reason leaves only that field
unknown; the executor stays listed with the rest of its report. Results record
the ICMP state, reason, clock and platform at admission, marked `stale` when
the report had expired.
