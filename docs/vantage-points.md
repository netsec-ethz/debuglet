# Vantage-point metadata

This note records how Debuglet will collect, store and expose an executor's
network, location, platform and reachability context. It is a design; steps 1
to 6 of the delivery order below have landed for controlled TCP/UDP peers. Today results record an
admission-time vantage point, executors report schema-1
[capabilities](operations/executor-discovery.md), their SCION ISD-AS,
listener transports and ICMP, clock and host-platform probes, and operators may
label executors with a display name, city, country and network. An offline
MMDB file built daily from RIPE RIS supplies ASN and announced prefix, as RIPE
Atlas does for its probes; an optional operator MMDB file can supply
approximate country/city location. Keep this note in step with the code as each step below lands.

## Provenance

Every field carries a `source`. Observations that expire, such as capability
and probe reports, also carry an `observed_at` time; other values are as of
admission:

| Source | Meaning |
| --- | --- |
| `operator` | Set by the operator in the dispatcher configuration. Values from an executor's own configuration, such as `public_host`, arrive over the control connection and are `executor-reported`, since the dispatcher cannot tell them from measurements. |
| `executor-reported` | Measured or introspected by the executor itself. |
| `dispatcher-observed` | Seen directly by the dispatcher: the remote IP of the control connection or of an address reflection call, and the result of a controlled connect-back reachability test. |
| `database:<name>@<version>` | Looked up by the dispatcher in an offline database, keyed on a dispatcher-observed or advertised address. The version comes from the database file's own metadata. The RIS-derived ASN database is `database:Debuglet-RIS-ASN@<epoch>`, where the epoch is the generation time of the RIS dumps it was built from. |

Executor claims are never labelled verified. A `dispatcher-observed` value
describes the control connection, which need not be the measurement egress.
An operator value takes precedence for display; the automatic value is kept
alongside it. A disagreement between sources is reported, not resolved
silently.

## Wire and storage

Executors send a `VantagePointReport` protobuf message, `schema_version = 1`, as
a versioned sibling of `ExecutorCapabilities` in `HelloResponse` and heartbeats.
It is not added as more top-level `HelloResponse` fields. As with capabilities,
the dispatcher discards a report with an unknown schema version or malformed
content, which leaves the fields unknown. Fields added later within schema 1,
such as the clock and platform probes, are validated one by one: a malformed
one is unknown and the rest of the report stands.

The dispatcher holds the current observation in executor-registry memory, tied
to the control binding like `Capabilities`. There is no live vantage-point
table: re-registration replaces the observation. The durable record is the
immutable admission-time [provenance](results.md#what-the-record-means)
snapshot, which gains `provenance.vantage_point` in result format 1.1. Results
therefore keep the context that was in effect when the run was admitted, even
after the executor moves or is removed. The snapshot's capability report
includes the executor's [tagging mode](operations/executor-discovery.md#tagging-mode)
per address family and for SCION, `null` when the report had none.

## Geolocation and ASN

Debuglet bundles no database and makes no online lookups; every lookup is in
an offline MMDB file on the dispatcher. ASN and prefix follow RIPE Atlas's
method: the origin AS of the longest matching prefix announced in BGP, taken
from RIPE RIS routing data. The dispatcher builds that database itself from
RIS's daily dumps, counting only prefixes at least 10 RIS peers see and
attributing a prefix with several origins to the one the most peers see. The
managed deployment rebuilds it daily and the dispatcher switches to a new file
without a restart; see
[executor discovery](operations/executor-discovery.md#asn-and-prefix-from-ripe-ris).
Location is not derived from a geolocation database in the managed
deployment: as with RIPE Atlas, it comes from the operator (or the host). An
operator may still configure an offline city database of their own (for
example DB-IP Lite or IPinfo Lite) and accepts its licence and update
procedure. Without a database, ASN and location are `unknown`. Loopback,
private (RFC 1918), CGNAT (100.64.0.0/10), IPv6 ULA and other non-global
addresses are always `unknown`, never a guessed value.

## Privacy

Debuglet follows the [RIPE Atlas](https://atlas.ripe.net/docs/apis/rest-api-manual/probes/)
probe model. A RIPE Atlas probe, home probes included, is public by default:
its addresses, prefixes, ASNs and location are published. A probe's host can
make it private, which hides only its addresses. Debuglet executors are the
same kind of vantage point and are measured against the same expectations, so
the public listing publishes the same facts and offers the same opt-out.

| Data | Visibility |
| --- | --- |
| Network (ASN, AS name, prefix, ISD-AS, address families, reachability) | Public |
| Dispatcher-observed address of each family (`address_v4`, `address_v6`) | Public, unless the executor is private (`is_public` false); then operator, and the run's owner through its result provenance |
| Location, at most city and country | Public, unless the executor opts out of location |
| Status history (status, first and last connection, total uptime) and host and system tags | Public |
| Measurement capabilities, including the ICMP probe and fallback reason | Public |
| Clock sync state, kernel error estimates and clock readiness | Public |
| Host platform (OS, kernel, architecture, CPU, memory, build version) | Operator, and the run's owner through its result provenance |
| Advertised public host, reported (hello) source IP, connectivity endpoints and the SCION host | Operator, and the run's owner through its result provenance |

The executor's NAT system tag is derived from a single boolean the executor
reports, whether its local IPv4 source toward the dispatcher is an RFC 1918
address; the local address itself never leaves the host. Host tags are the
host's own public description, chosen from a fixed vocabulary.

Only addresses the dispatcher itself observed are published: the peer address
of the executor's authenticated control connection and of its authenticated
address reflection calls. The executor's own claims, such as `public_host`,
are not observations and stay operator-only. A published address is the
address the executor reaches the dispatcher from; packets it sends elsewhere
may leave from another one. An address is already public in practice whenever
the executor measures from it, since every probe it sends carries it; the
public `GET /attribution/candidates` lookup answers for an address the querier
already holds, whether the executor is public or not.

`is_public` and the location opt-out are independent, as in RIPE Atlas, where
a private probe keeps its location public and the location is the host's own
choice. Making an executor private (`metadata.address_opt_out`) hides only
its addresses; prefix, ASN and any location stay public. Opting out of
location (`metadata.location_opt_out`) hides only the automatic city and
country; the addresses stay public unless the executor is also private. An
executor that wants neither published sets both. Location is never finer than
city.

Executors are public by default, including executors that predate the
setting: their observed addresses appear in the listing from API 1.16 on.
Before then the control-connection source IP was operator-only. An executor
that must stay private needs a release that sends `address_opt_out` (an older
executor cannot) and the setting before it registers with a dispatcher of
this release.

## Refresh

Metadata is collected at registration and on every reconnect. The RIS ASN
database is rebuilt daily; a replaced database applies to registrations after
the switch, and admitted results keep the source they were looked up with. Executor probe
results (ICMP, platform, clock, SCION, egress) use the existing capability
cadence: reported at most every 30 seconds on the heartbeat and expired after
90 seconds without a new report. Expired legacy capability values become unknown in the live
executor view, with a separate freshness descriptor. Connectivity retains its
last outcome with an explicit stale flag. The admission snapshot keeps the last report and marks it
`stale`, so a result shows what the dispatcher knew and how old it was.

## Delivery order

1. Admission snapshot in result format 1.1 (#241). Done in #336.
2. SCION ISD-AS and operator display metadata (#213, part of #237). Done in
   #338; see [executor discovery](operations/executor-discovery.md#vantage-point-metadata).
3. ICMP, platform and clock probes (#240). Done; see
   [executor discovery](operations/executor-discovery.md#host-probes). The
   dispatcher has no live operator executor view, so the host platform is
   stored with the registration and published only in result provenance. The
   bandwidth-estimate probe was dropped as disproportionate.
4. Offline MMDB ASN and geolocation (#237, #238). Implemented; see
   [configuration, opt-out and database updates](operations/executor-discovery.md#offline-asn-and-approximate-location).
   IP metadata is collected at registration, includes negative lookup reasons,
   and is retained in admission snapshots. SCION host-address reporting and
   measured reachability are described below. ASN and announced prefix now
   come from a database the dispatcher builds from RIPE RIS, as RIPE Atlas
   derives them, and a replaced database is loaded without a restart; see
   [ASN and prefix from RIPE RIS](operations/executor-discovery.md#asn-and-prefix-from-ripe-ris).
5. Controlled TCP/UDP connect-back reachability and field-level admission
   refusal (#239 part 1); see [controlled observations](operations/executor-discovery.md#controlled-connectivity-observations).
6. Dual-stack egress reflection against the authenticated dispatcher (#239
   part 2). Local SCION host/path metadata is reported separately; external
   SCION data-plane and listener reachability remain untested.
7. RIPE Atlas-style addressing in API 1.16: the observed `address_v4` and
   `address_v6`, their prefixes and ASNs, and `is_public`; see
   [probe addresses](operations/executor-discovery.md#probe-addresses).
8. RIPE Atlas-style status history and host and system tags in API 1.17,
   stored in dispatcher schema 24; see
   [probe status and tags](operations/executor-discovery.md#probe-status-and-tags).
   A DNS self-check against a name other than the dispatcher's own is later
   work.
