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

TCP/TLS/UDP observations reflect the operator's transport switches. ICMP also
requires a successful process-local raw-socket probe. SCION requires the operator
switch plus a responsive configured SCION daemon and a local route observation.
The bounded discovery probe accepts literal IP addresses for the daemon and its
control-service address. Hostname configurations remain unknown for discovery;
execution's existing configuration support is unchanged. Initial SCION probing
has a 500 ms bound; later refreshes use at most 100 ms, avoiding DNS and runtime
locks. No measurement packet is sent by these probes. A positive local SCION
observation does not establish an external path or remote deployment.

## Vantage-point metadata

API 1.10 adds four fields to each `GET /executors` entry. Every value names its
`source`: `operator` for dispatcher configuration, `executor-reported` for the
executor's own claims. No label means verified.

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
