# Selecting an executor

`dbl nodes` lists registered executors and their current capability observations.
Use filters to restrict the list to ready executors:

```sh
dbl nodes --protocol icmp --enforcement fallback --min-capacity-bps 1000000
dbl nodes --isd-as 1-ff00:0:110
dbl nodes --asn 559 --country CH
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
take effect when the dispatcher restarts. The Ansible deployment renders these
tables from each executor's `executor_display_*` inventory variables, keyed by
its `executor_id` (see [the deployment guide](../../deploy/README.md)).

`--asn` matches a known origin ASN of either the observed control address or
advertised literal address. `--country` matches the displayed country, including
an operator override. SDK callers can use `Node.Location()` to obtain the
source-labelled city/country pair without changing the wire response. Unknown values do not match. `dbl nodes` shows ASN and the
location source; `--output json` includes the detailed lookup records below.

### Offline ASN and approximate location

The dispatcher can load optional operator-supplied MMDB files at startup:

```toml
[metadata]
asn_database = "/var/lib/debuglet/GeoLite2-ASN.mmdb"
city_database = "/var/lib/debuglet/GeoLite2-City.mmdb"
```

Debuglet bundles no database, downloads none and makes no online or DNS lookup.
Acquire data under its provider's licence. Supported records use the
GeoIP2-compatible MMDB keys `autonomous_system_number`,
`autonomous_system_organization`, `country.iso_code` and `city.names.en`.
Other MMDB layouts are not implicitly translated. The ASN record includes the
covering database prefix. Location is approximate, at most country and city;
coordinates are never read or published. Missing city means country precision.

`ip_metadata.observed` and `.advertised` keep the two lookup results separate.
`address_source` says whether the lookup key was dispatcher-observed or
executor-reported; `ip_metadata` carries no address itself. The observed
addresses are listed separately as [probe addresses](#probe-addresses). Each `asn` and
`location` has `value`, `source`, `observed_at` (registration time in Unix
seconds) and `reason`. `source` is `database:<database_type>@<build_epoch>`,
using the file's embedded metadata. It identifies the data, not its correctness.
Lookups describe control/advertised addresses, not measured egress paths.

A null value has a reason: `no_database`, `no_address`, `not_ip`, `non_global`,
`not_found`, `invalid_record`, `lookup_error` or `opted_out`. A database source
is retained for negative lookups; it is null when no lookup happened. Loopback,
private, CGNAT, ULA, documentation and other special-purpose addresses stay
unknown even if a database contains a record. Hostnames stay unknown.

The existing `display` response stays operator-only for compatibility. New SDK
and CLI clients derive a display location from `ip_metadata`: an operator city
or country overrides the entire automatic display location;
otherwise the observed address is preferred, then the advertised address.
Automatic results remain visible alongside an override. `disagreements` flags
conflicting observed/advertised ASNs or locations, or a conflicting operator
location. A missing value is not treated as a disagreement.

Executors can suppress all automatic location publication:

```toml
[metadata]
location_opt_out = true
```

Restart the executor to publish a changed preference. It applies to public
listings and new admission snapshots, including when an operator location is
set. Existing immutable results are unchanged; explicitly configured operator
location remains visible. Older executors default to allowing automatic lookup.

To update databases, obtain and validate replacement files under the provider's
licence, then atomically rename them into the configured paths and restart the
dispatcher. Never overwrite or truncate an open MMDB file in place. Startup
rejects missing, malformed or unverifiable configured databases; unset paths
are supported and produce unknown values. Reconnecting executors are looked up
again. Existing results retain the old source/version and values.

`provenance.vantage_point.ip_metadata` adds these same lookup facts to schema 1
of result format 1.1. Files predating the field remain readable. No separate
live metadata table or database-update service is required.

### Probe addresses

API 1.16 adds the addressing of a [RIPE Atlas](https://atlas.ripe.net/) probe
record to each `GET /executors` entry:

```json
"is_public": true,
"address_v4": "192.0.2.10",
"address_v6": "2001:db8:10::7",
"prefix_v4": "192.0.2.0/24",
"prefix_v6": "2001:db8::/32",
"asn_v4": 64500,
"asn_v6": 64500,
"address_observations": {
  "v4": {"source": "dispatcher-observed", "via": "control", "observed_at": 1791250000,
         "lookup_source": "database:GeoLite2-ASN@1790000000", "lookup_reason": ""},
  "v6": {"source": "dispatcher-observed", "via": "reflection", "observed_at": 1791249700,
         "lookup_source": "database:GeoLite2-ASN@1790000000", "lookup_reason": ""}
}
```

`address_v4` and `address_v6` are the last addresses of each family that the
dispatcher itself observed for the executor in its current control session.
An executor's claim is never used: `public_host` and the hello's source IP are
not observations. Two connections are observed, both authenticated with the
executor's certificate and current control-session credentials, so another
host cannot submit or spoof them:

- `via: control` is the peer address of the control connection. It is
  current while that session lives, so `observed_at` is the session's last
  heartbeat. It is preferred for its own family, which keeps a multi-homed
  executor's address from alternating between paths.
- `via: reflection` is the peer address of the executor's last
  `ReflectAddress` call over the other family. The dispatcher records the
  TCP peer of the call, never a value in the request, and `observed_at` is
  the call's receipt.

To observe the family its control connection does not use, an executor calls
the address reflection over each family every 10 minutes. It resolves the host
of its configured `dispatcher.addr` for that family (only that family when the
host is a literal) and verifies the dispatcher's certificate for that name, as
on the control connection, so a resolved address that is not the dispatcher
fails the handshake. A family with a configured `connectivity.ipv4_reflector`
or `ipv6_reflector` is not called again: its 30-second
[connectivity check](#controlled-connectivity-observations) already reflects
it. A family that does not work is simply not observed; it affects neither the
connectivity report nor admission. Operators can turn the calls off:

```toml
[connectivity]
observe_addresses = false   # default true
```

A replacement control session starts without the previous session's
observations, as for the connectivity checks, so an executor that moved does
not keep its old address; until the next call its other family is null. An
executor that is not connected is listed (API 1.17) with the last addresses
the dispatcher recorded for it. A
published address is where the executor reached the dispatcher from, which
need not be the source of every measurement packet, and it can be a
non-global address when the executor reaches the dispatcher over a private
network.

`prefix_v4/v6` and `asn_v4/v6` are looked up from those addresses in the
[offline ASN database](#offline-asn-and-approximate-location), with the
database and any negative reason in `lookup_source` and `lookup_reason`. They
are null when no database is configured, or for a non-global or unknown
address.

An executor can make itself private, as a RIPE Atlas host can:

```toml
[metadata]
address_opt_out = true   # default false: public
```

The listing then reports `is_public: false` and withholds both addresses from
everyone but established operators. Nothing else changes: prefixes, ASNs,
`address_observations`, `ip_metadata` and location stay public. Location has
its own opt-out, `location_opt_out`, independent of this one; the
[vantage-point note](../vantage-points.md#privacy) explains the choice.
Restart the executor to publish a changed preference. Executors that predate
the setting are public. The admission snapshot records the same fields,
including a private executor's addresses, as `provenance.vantage_point.addressing`.

`dbl nodes` shows the addresses in its `ADDRESS_V4` and `ADDRESS_V6` columns
(`private` when withheld, `-` when unknown); `--output json` carries every
field.

### Probe status and tags

API 1.17 adds the status history and tags of a RIPE Atlas probe record:

```json
"status": {"name": "connected", "since": 1791000000},
"status_since": 1791000000,
"first_connected": 1780000000,
"last_connected": 1791257000,
"total_uptime": 9504000,
"tags": ["home", "fibre", "system-ipv4-works", "system-ipv4-capable",
         "system-ipv4-stable-1d", "system-ipv4-stable-30d", "system-ipv6-capable",
         "system-ipv4-rfc1918", "system-resolves-a-correctly"]
```

| Status | Meaning | `since` |
| --- | --- | --- |
| `connected` | The executor has a control session (its `admission` may still be `offline` until the first heartbeat). | Start of the connected streak. |
| `disconnected` | It has none, and was last connected at most 30 days ago. | `last_connected`. |
| `abandoned` | It was last connected more than 30 days ago. | `last_connected` plus 30 days. |
| `never_connected` | It was enrolled (an owned or enrolled executor ID) but has never registered. | `null` |

The dispatcher records the history in its database (schema 24). A
registration records the executor as connected; once a minute the dispatcher
advances `last_connected` and `total_uptime` of every registered executor and
records any other as disconnected at its last record, so a disconnection is
known to within a minute. A registration within two minutes of the last record
of a connected streak, such as a replacement session or a dispatcher restart,
continues the streak. `total_uptime` counts connected seconds from the
upgrade to schema 24; `first_connected` of an executor known before it comes
from its first recorded TESLA chain.

`GET /executors` keeps listing connected executors only. Ask for others with
`?status=disconnected,abandoned,never_connected` (comma-separated or
repeated; add `connected` to include those too). An entry that is not
connected carries its `id`, `display`, `version`, `last_seen` (its
`last_connected`), `admission: offline`, its status fields, host tags and the
last addresses the dispatcher recorded for it, under the same `is_public`
rule; its other fields are zero or null and it cannot run work. `dbl nodes
--status ...` and `Client.Probes(ctx, statuses...)` use this parameter and
require API 1.17; `dbl nodes` adds `STATUS` and `TAGS` columns.

**Host tags** are the executor's own description, chosen from a fixed
vocabulary and set in its configuration, or with `dbl executor join
--host-tag`:

```toml
[metadata]
host_tags = ["home", "fibre"]
```

`home`, `office`, `datacentre`, `academic`, `cloud`, `dsl`, `cable`, `fibre`,
`wifi`, `mobile`, `satellite` and `nat`; at most eight. The executor refuses to
start with an unknown or repeated tag, and the dispatcher drops a malformed
list. They are read at registration, like the opt-outs.

**System tags** are derived by the dispatcher for connected executors:

| Tag | When |
| --- | --- |
| `system-ipv4-works`, `system-ipv6-works` | A fresh measured [connectivity](#controlled-connectivity-observations) check over the family succeeded, or the family's [observed address](#probe-addresses) is current: the control connection's, or a reflection within the last 25 minutes. |
| `system-ipv4-capable`, `system-ipv6-capable` | An address of the family was observed in the current control session, or a fresh connectivity check succeeded. |
| `system-ipv4-rfc1918` | The executor reports that its local IPv4 source toward the dispatcher is an RFC 1918 address while the observed IPv4 address is global: it is behind a NAT. Only that boolean leaves the host. |
| `system-ipv4-stable-1d`, `-30d`, `-90d` (and `ipv6`) | The family's current observed address has been the recorded address for at least 1, 30 or 90 days. |
| `system-resolves-a-correctly`, `system-resolves-aaaa-correctly` | In the executor's last [address observation](#probe-addresses) round, its resolver answered the dispatcher's name with an A (AAAA) record whose address then passed the dispatcher's TLS identity check. This is stricter than RIPE Atlas's check: the family must also reach the dispatcher. |

The NAT and DNS tags come from the executor's report and expire with it, as
other vantage-point reports do; they are absent for older executors, for a
literal `dispatcher.addr` (DNS) and with `observe_addresses = false`. Address
stability starts from the upgrade to schema 24.

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
  `not_permitted` (the eBPF load or attach lacked privilege: the executor
  needs `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`), `unsupported` or
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

## Controlled connectivity observations

An operator can enable bounded checks against infrastructure they control. The
checks are disabled by default. They cannot take a target from a measurement,
resolve a hostname, follow redirects, or test arbitrary addresses. The existing
authenticated dispatcher gRPC listener provides address reflection; no additional
service or public reflector is installed.

For a local topology, the executor configuration can contain:

```toml
[connectivity]
ipv4_reflector = "127.0.0.1:9090"
ipv6_reflector = "[::1]:9090"
listeners = true
# Optional local-daemon path query to an operator-selected remote ISD-AS:
# scion_path_target = "1-ff00:0:111"
```

Each reflector must be a literal address of this executor's dispatcher, of the
named address family. It uses the existing control identity and TLS trust.
Plaintext is accepted only on loopback. The dispatcher must actually listen on
both configured addresses to observe both families. A successful check proves
TCP communication with that dispatcher over that family. It does not establish
UDP reachability or reachability to every destination. A failure is recorded as
`reflector_failed`, not as proof that the family is universally unavailable.

Listener checks also require a dispatcher-side allowlist for that executor:

```toml
[executors."example-executor"]
connectivity_host = "127.0.0.1"
connectivity_ports = "42000-42015"
```

The host must be a literal unicast address, and the list may contain at most 256
ports. Both must describe endpoints the operator controls. The executor's
existing `network.public_host` must equal that host, and its `network.public_ports`
must provide ports within the approved pool. An unapproved port or mismatching
advertisement is `untested`; the dispatcher sends nothing to it.

At each check, the executor temporarily binds one TCP and one UDP socket from
its actual guest listener pool. The dispatcher sends one fixed-size challenge
to each approved endpoint and requires a response tied to that report's random
listener token. An unrelated open service cannot satisfy the challenge. The
executor closes and joins both responders and releases their ports after the
heartbeat completes. This samples particular ports; it does not guarantee that
every port in a firewall range, or a later guest listener, is reachable.

Both sides bound checks to one attempt per 30 seconds. Each listener challenge
has a 400 ms deadline; the two family reflection calls each have a 600 ms bound.
Observations expire after 90 seconds. Re-registration discards old proof and
marks configured checks pending until the new session obtains its own results.
Only successful reflection and successful/failed connect-back checks directly
seen by the dispatcher use `dispatcher-observed`. Failed reflection calls and
local bind failures are `executor-reported`.

The optional `connectivity` object in `/executors` retains `reachable`,
`unreachable` or `untested`, the reason, source, observation/expiry times and an
explicit `stale` flag. Public views omit raw addresses, endpoints and the SCION
host. Established operators can see these details; result owners receive them
in the immutable admission snapshot. Address disagreements are reported without
silently changing the advertised address. Names are not resolved for comparison.

For a configured check, admission requires a fresh successful observation when
a policy asks for the corresponding literal address family or TCP/UDP listener.
Refusals identify `policy.addresses`, `policy.listen_tcp` or `policy.listen_udp`
in `field_errors`, including the batch order and a stable reason such as
`stale_observation`, `unmeasured` or `reachability_failed`. An unconfigured check
retains the existing declared-capability admission path: it is explicitly
unmeasured. Declared unsupported listeners and unavailable required ICMP are
refused as well. Names with an unresolved family are not resolved during this
preflight; the executor's ordinary destination policy still applies at runtime.

The SCION host is the local address selected toward the configured daemon's
control service. An optional remote ISD-AS query records whether that daemon has
a non-expired path to it. This is path metadata, not a SCION packet exchange or
proof of external listener reachability. SCION listener reachability remains
`untested` with `no_controlled_peer`; declared SCION support remains separate.

`dbl nodes --address-family ipv6` and `--reachable-listener tcp` select only
fresh measured matches. Repeat either flag to require more than one. JSON output
contains the full authorized observation; the text table labels stale and
untested outcomes explicitly. ASN filters continue to match the observed control
or advertised-host database origin. A differing hello source-IP claim is retained
separately as optional `ip_metadata.reported`, with its own lookup provenance,
and never silently adds an ASN filter match.

The additional `capability_observation` descriptor distinguishes `current`,
`stale` and `unknown` while preserving the earlier `capabilities: null` behavior
for expired reports. `admission_limits` exposes scheduling support, the existing
numeric timeout/bandwidth domain and `currency_per_bps_second` pricing units.
These bounds describe valid policy inputs, not free capacity or a guarantee that
a complete scheduled reservation fits.
