# Vantage-point metadata

This note records how Debuglet will collect, store and expose an executor's
network, location, platform and reachability context. It is a design, not a
description of current behaviour. Today executors report only schema-1
[capabilities](operations/executor-discovery.md) and the dispatcher keeps the
control connection's source IP; no location is inferred. Keep this note in step
with the code as each step below lands.

## Provenance

Every field carries a `source`. Observations that expire, such as capability
and probe reports, also carry an `observed_at` time; other values are as of
admission:

| Source | Meaning |
| --- | --- |
| `operator` | Set by the operator in the dispatcher configuration. Values from an executor's own configuration, such as `public_host`, arrive over the control connection and are `executor-reported`, since the dispatcher cannot tell them from measurements. |
| `executor-reported` | Measured or introspected by the executor itself. |
| `dispatcher-observed` | Seen directly by the dispatcher: the control connection's remote IP and, later, the result of a connect-back reachability test. |
| `database:<name>@<version>` | Looked up by the dispatcher in an offline database, keyed on a dispatcher-observed or advertised address. The version comes from the database file's own metadata. |

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
content, which leaves the fields unknown.

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

Debuglet bundles no database and makes no online lookups. An operator may
configure the path of an offline MMDB file on the dispatcher (for example
DB-IP Lite or IPinfo Lite) and accepts that database's licence and update
procedure. Without it, ASN and location are `unknown`. Loopback, private
(RFC 1918), CGNAT (100.64.0.0/10), IPv6 ULA and other non-global addresses are
always `unknown`, never a guessed value.

## Privacy

| Data | Visibility |
| --- | --- |
| Network (ASN, AS name, prefix, ISD-AS, address families, reachability) | Public |
| Location, at most city and country | Public |
| Measurement capabilities | Public |
| Host platform (OS, kernel, architecture, CPU, memory, clock detail) | Operator only |
| Control-connection source IP and advertised public host | Operator, and the run's owner through its result provenance |

Location is never finer than city. An executor can opt out of location; the
dispatcher then publishes no automatic location for it.

## Refresh

Metadata is collected at registration and on every reconnect. Executor probe
results (ICMP, platform, clock, SCION, egress) use the existing capability
cadence: reported at most every 30 seconds on the heartbeat and expired after
90 seconds without a new report. Expired values become unknown in the live
executor view. The admission snapshot keeps the last report and marks it
`stale`, so a result shows what the dispatcher knew and how old it was.

## Delivery order

1. Admission snapshot in result format 1.1 (#241).
2. SCION ISD-AS and operator display metadata (#213, part of #237).
3. ICMP, platform and clock probes (#240).
4. Offline MMDB ASN and geolocation (#237, #238).
5. Connect-back listener reachability and admission refusal (#239 part 1).
6. Dual-stack egress discovery (#239 part 2).
