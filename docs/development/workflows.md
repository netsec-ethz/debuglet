# Visual measurement programs

A workflow is a versioned JSON program that can be edited visually or through
an authoring tool. It compiles to one Go WASI debuglet. Network operations,
processing, branches and bounded repetition execute on the selected executor;
they do not require a round trip through an AI client or dispatcher.

An experiment connects several of these workflows. In the console,
**Workflow builder** edits one program; **Experiment builder** selects a
participant, edits its program and connects it to the others. Start with the
[authoring guide](workflow-authoring.md) to build the local editor, compile
bundles or connect an MCP client.

Start with [HTTP status branching](../../examples/workflows/http-status.json),
[Ping and RTT analysis](../../examples/workflows/ping-branch.json),
[posting JSON](../../examples/workflows/http-json-post.json), or
[a custom processing block](../../examples/workflows/custom-transform.json).
The network examples use loopback placeholders: choose an endpoint you control
and permit its address in the normal submission policy. The JSON POST example
expects its `/echo` target to return JSON. On a remote executor,
loopback refers to that executor. Ping also requires its ICMP capability.

## Blocks and connections

Blocks have named, typed inputs and outputs. An input receives either a literal
or one data connection. Types are strings, finite numbers, booleans, number
lists, string lists, objects and arbitrary JSON values. An `any` connection is
checked against the receiving type when used; strings are never automatically
converted into numbers or booleans.

Data connections carry values. Control connections determine when actions run.
A data connection to an HTTP response does not send another request. Reading an
action that has not run on the current control path is an error. Pure analysis
blocks evaluate when their value is needed and can appear more than once in the
trace. An If block receives a boolean from a comparison or other producer and
runs its `true` or `false` control branch. A second target uses another ordinary
network block with different inputs.

HTTP's `ok` indicates a completed response, including 3xx, 4xx and 5xx statuses.
Redirects are not followed. The optional `body` is text, and `headers` is an
object whose values are strings: for example `{"Content-Type":"application/json"}`.
Connect Stringify JSON to `body` to send a structured value. The HTTP block sets
Content-Length from the body's byte length and keeps the URL's host as the
request authority. Host, framing, connection, compression and upgrade headers
cannot be overridden. Request bodies are at most 16 KiB; caller-supplied request headers and received
response headers are limited to 16 KiB and 64 names. Response `headers` uses lowercase
names and lists of strings, preserving repeated values such as Set-Cookie.

Check `ok` for transport errors and compare `status`
to express the status policy you need. Ping's `rtts_ms` contains only successful
replies and `loss` is a percentage. Check `received` before calculating a mean;
analysis of an empty sample set fails rather than reporting a misleading zero.

### DNS, application exchanges and path probes

**DNS query** takes an explicit resolver IP and port, query name, record type
and UDP or TCP transport. It returns answer, authority and additional records
with TTLs, flags, response code, raw bytes as base64 and elapsed time. `ok`
means a matching DNS response was decoded: NXDOMAIN and SERVFAIL still require
checking `rcode`. Recursion, checking-disabled, DNSSEC OK and NSID request flags
are configurable. Requesting DNSSEC records does not validate their signatures.
UDP truncation is reported; the block does not retry over TCP automatically.
Replies are bounded to 8,191 bytes and 128 records. Permit the resolver address
in the run's destination policy, rather than the name being queried.

**UDP exchange** sends one datagram and receives one reply. **TCP exchange**
connects, writes one payload, and reads to an explicit boundary: a delimiter
(included in the response), exactly `max_bytes`, or end of stream. Payloads use
text or padded base64 and are at most 8 KiB. `response_base64` preserves exact
bytes; `response` is a UTF-8 display string. Check `ok`, `complete` and
`truncated` before interpreting a reply. One timeout bounds the entire exchange,
including connection setup. Neither block retries writes. UDP response limits
are 1–8,191 bytes; TCP limits are 1–8,192 bytes.

**TLS handshake** makes a normally verified TLS connection and returns protocol,
cipher, negotiated ALPN, peer address and certificate summaries. It never
disables certificate verification. Its duration includes DNS resolution and TCP
connection setup, so it is not a separate TLS-only timing measurement.

**Hop probe** sends one IPv4 ICMP echo with a chosen TTL from 1 to 255. It reports
a matching echo reply or an ICMP error quoting the probe, with the responding
address, ICMP type/code, elapsed time and `reached`. Combine Repeat's iteration
with TTL and Collect sample to inspect successive hops. A timeout means no
matching reply was observed; it does not prove that a router is down. Results
are correlated network observations, not authenticated router identities or a
guarantee that load-balanced probes followed one path. ICMP permission and raw
socket support are required.

### Receiving UDP

**UDP listener address** exposes the endpoint allocated to this run. In an
experiment, send this value to another participant before it starts an exchange.
**Receive UDP** waits on that listener with a deadline and reports the admitted
source, payload, original byte count and truncation. Its base64 output preserves
the received bytes. **Reply UDP** sends from the same listener port to the last
successfully received source; connect Receive's `source` to its `destination`.
Receiving another datagram replaces that source. A reply without a successful
receive is refused. Current destination policy, attribution and traffic limits
apply in both directions.

The compiled bundle requests a UDP listener automatically. The selected executor
must advertise a reachable UDP listener, and each run's policy must permit its
peers. TLS handshake, Hop probe and UDP receive/reply also require the new host
functions advertised by updated executors. The console shows actual executor
versions and excludes nodes without current compatible runtime support from
normal selection; operators can still see their nodes and update them.

Data blocks support Parse JSON and Stringify JSON, Get field and Set field,
List item and Append item. Set field and Append item return new values without
changing their inputs. List item uses a zero-based integer index and fails when
the item is absent. Text blocks offer Concatenate, Contains, Split and Join.
Contains is case-sensitive; an empty substring matches. Split requires a
nonempty separator and preserves empty pieces. Join of an empty list is empty
text. All produced values retain the normal string and list limits.

Mean, Minimum, Maximum, Median and Percentile require a nonempty number list.
Median averages the middle pair for even-sized lists. Percentile accepts a value
from 0 to 100 and linearly interpolates sorted samples at `p/100 × (n−1)`; this is
not the nearest-rank convention. Add, Subtract, Multiply and Divide use finite
numbers; division by zero and nonfinite results fail explicitly.

**Standard deviation** accepts `mode: "sample"` (default, divisor `n−1`, at
least two values) or `"population"` (divisor `n`, at least one). This describes
sample spread, not confidence or statistical significance. **Histogram** accepts
2–257 strictly increasing finite `edges`, making 1–256 bins. Bins include their
lower edge and exclude their upper edge; the final bin includes its upper edge.
Output `rows` contain `lower`, `upper`, `midpoint` and `count`. Separate
`underflow` and `overflow` counts retain samples outside the edges; all bin and
tail counts sum to the total output `count`. Empty samples produce zero counts.
Both blocks share the existing limit of 1,024 finite samples.

### Processing rows and reporting results

**Filter rows** keeps matching objects from a list in their original order.
Choose a field and `equals` (the default), `not_equals`, `greater_than`,
`less_than`, `at_least` or `at_most`. Equality compares JSON values without
coercion; ordering requires numbers on both sides. **Select field** extracts
one field from every row into a list. For example, filter collected measurements
where `ok` equals `true`, select `duration_ms`, then connect the result to Mean
or Percentile. Missing fields and non-object rows fail explicitly. Empty lists
are valid for these row operations and Count; check the count before using
statistics that require at least one sample.

**Sort rows** orders a copy of the list by one named `field`, in `ascending`
(default) or `descending` order. Equal keys retain input order. All keys must
be finite numbers, or all must be strings; strings use lexical order without
locale rules. It rejects missing fields and mixed key types.

**Report metric** publishes `title`, a finite numeric `value` and an optional
`unit`. **Report table** publishes `title`, object `rows` and 1–32 distinct
`columns`, each naming a field present in every row. Columns control display
order; the output still contains every original row field. **Report text**
publishes a `title` and plain `text`, displayed literally without interpreting
HTML or Markdown. **Report chart** publishes 1–256 object `rows`, naming finite
numeric `x` and `y` fields, with `kind: "line"` (default) or `"bar"` and optional
`x_label`/`y_label`. Lines connect points in input order on a numeric x axis;
sort first when x order matters. Bars keep row order, label each bar with x and
include a zero baseline. The console also provides the exact x/y data table;
all original row fields remain in the output. Connect Histogram's `rows` to a
bar chart using `midpoint` and `count`, and report its tail counts separately.
All report blocks are actions with a `next` connection and return
their report fields as outputs, so they can feed later actions.

Reports use the ordinary `debuglet.workflow.v1` events and run output. They
share the existing string, list, depth, per-event and total trace limits; they
do not create separate files or storage. A table can have up to 1,024 rows,
but the 64 KiB event limit can require fewer rows when cells are large. Report
titles and text are ordinary bounded strings. A report emitted inside Repeat
appears once per executed iteration. The [sample report](../../examples/workflows/sample-report.json)
shows filtering, field selection, a mean, a metric, a table and explanatory text
using fixed sample data, with no network access needed.

## Reusable visual groups

The editor can fold a selection into one named block. Its interface comes from
connections crossing the selection and its unconnected ports. Double-click
the group to edit its members, then close it to return to the compact view.
Saved groups are templates: inserting one copies its nodes, internal wires and
custom block definitions, so editing an instance does not change other instances.

The portable workflow keeps these ordinary nodes and wires, plus optional
`groups` metadata containing `id`, `label`, `node_ids` and `position`. Grouping
does not introduce a function call or change execution order. Metadata is retained
in compiled bundles and included in the workflow checksum. Groups currently
contain at least two nodes and cannot overlap or nest; ungrouping preserves the
underlying program.

## Experiments with several executors

An experiment contains two or three ordinary participant workflows and named,
directed channels. Participant names are labels, not fixed roles. Choose a
different executor for each participant when reviewing the grouped submission.
Every executor must advertise a directly reachable IPv4 TCP listener and permit
the other participants' addresses in its measurement policy. Channel names are
chosen by the author to identify messages, such as `reading` or `reply`; they
are not built-in operations.

The [three-node example](../../examples/workflows/experiments/three-node.json)
sends 21 from A to B, doubles it on B, adds one on C and returns 43 to A.
Each participant first publishes its listener through the existing readiness
exchange and waits for the common requested start. This is a clock-dependent
start time, not atomic simultaneous execution. The dispatcher coordinates setup;
the messages then travel directly between executors.

Send message selects a destination and channel, and supplies a typed JSON value.
Await message selects the source and channel. Both accept a bounded `timeout_ms`
and return `ok` and `error`. Test `ok` before using an Await's `value`; failure
returns `null`, not a successful zero or empty result. Send success means the
socket write completed, not that the receiver processed it.

A channel with `response_type` permits one reply per request. The
[request/reply example](../../examples/workflows/experiments/request-reply.json)
wires the initial Send's `request_id` into the sender's Await, and the receiver's
Await `request_id` into its replying Send. A late reply cannot satisfy a different
request. One-way channels leave `request_id` empty. There are no automatic
retries or participant replacement.

**Wait for phase** announces arrival at a literal named phase and waits for all
other participants to reach that phase's current repetition. Include the phase
in every participant's workflow and invoke repeated phases in matching order.
The result includes `ok`, `error`, `generation`, `missing` and elapsed time.
Timeouts and late messages remain separate from later generations; ordinary
application messages received during the wait remain available to Await.
Success means this participant observed every arrival, not that every peer also
returned successfully. It does not synchronize clocks or provide an atomic
distributed commit. Handle failure before proceeding with dependent work.

Messages are plaintext TCP, limited to 8 KiB including framing fields; the inbox
is limited to 64 KiB and 128 messages. Group identifiers and request correlation
prevent accidental mixing, but do not authenticate a peer socket or encrypt its
data. Use controlled experiments without confidential payloads. A participant
only receives while executing Await or Wait for phase: long-running blocks can delay its peers,
and cyclic waits can time out. Normal executor lifetime and traffic limits remain
authoritative.

The experiment source is at most 4 MiB, with at most 64 channels. Compilation
injects the participant ID, whole-experiment fingerprint and channel manifest
into each program's canonical workflow and digest. Build the whole experiment
after editing any participant; individual compiled programs cannot be rebuilt
as standalone workflows. Bundles are limited to 32 MiB, and the console checks
the final grouped request against the API's 32 MiB limit before submission.

## Repetition

Repeat has a `body` and a `done` output. The body runs sequentially until its
control path ends, then starts again. Its action outputs are cleared between
iterations. Repeat's `iteration` output starts at 1. After the requested count,
execution continues at `done`. A body cannot also lead into that continuation
or be entered by another control path. Arbitrary cycles are rejected.

Programs support up to 128 nodes, 100 repeat iterations and 1,000 action steps.
A single wait or network timeout is at most 60 seconds. Graph control limits
complement the ordinary executor's runtime, traffic and destination limits.

Create a **sample collection** before Repeat, wire its handle to **Collect
sample** inside the body, then **Read samples** after `done`. Unlike ordinary
action outputs, explicitly collected samples survive iteration boundaries.
Collect and Read copy their values; **Clear samples** empties the collection
without invalidating its handle. A run has at most 32 collections, 1,024 samples
and 48 KiB per collection, and 256 KiB across all collections. The returned list
can feed Mean, Percentile or Emit result.

**Start timer** creates a run-local handle; **Elapsed time** reads milliseconds
since that start without resetting it. The clock is monotonic within the run.
Do not send timer handles to another executor or compare their values as
synchronized timestamps. At most 128 timers may be created in one run.

## Custom blocks

A custom block declares its inputs, outputs and a Go function body. It receives
`inputs map[string]any` and returns `(map[string]any, error)`. JSON numbers are
`float64`, arrays are `[]any` and objects are `map[string]any`. Returned Go values
are normalized to JSON and checked against the declared ports. Custom blocks
are actions with a `next` control output; they execute only when control reaches
them. Their complete source remains visible in the workflow.

The generated program makes `fmt`, `json`, `os` and `guest` available. Referring
to `debuglet`, `time`, `strings` or `math` selects those approved packages too.
`debuglet` is the existing guest SDK, and `guest` exposes the built-in operations
such as `HTTP` and `Ping`. Arbitrary imports, additional source files, compiler
directives and dependency downloads are not accepted. For example:

```go
samples := inputs["samples"].([]any)
if len(samples) == 0 {
    return nil, fmt.Errorf("need at least one sample")
}
var total float64
for _, sample := range samples {
    total += sample.(float64)
}
return map[string]any{"value": total / float64(len(samples))}, nil
```

Custom code shares the guest's resource and network policy. It is not isolated
per block and can loop or use the SDK directly; the executor's overall runtime
limit remains necessary. Typed source validation does not prove arbitrary code
safe or establish that a supplied Wasm artifact matches that source.

## Results and artifact identity

The guest emits JSON lines with schema `debuglet.workflow.v1`,
`workflow_sha256`, `node_id`, `block`, `status`, `outputs` and optional `error`.
`completed` means the block ran: a network operation can complete with
`outputs.ok: false`. A fatal graph/type/custom-code error emits a `failed` event
and ends the run. An Emit block publishes `name` and `value` in its outputs.

An experiment program first emits one `debuglet.experiment.v1` JSON line,
before joining its peers. This bounded manifest contains its workflow and
experiment digests, participant ID, ordered membership and declared channels.
The console uses agreeing manifests from the group to restore its connection
map. If output is missing or the manifests disagree, the automatic map is
unavailable. These are program declarations, not evidence that messages were
delivered.
Consumers of block events should filter by the `debuglet.workflow.v1` schema.

Individual strings are limited to 16 KiB and lists to 1,024 entries. Each event
is at most 64 KiB; a run emits at most 4,096 events and 4 MiB of trace output.
The experiment manifest is an additional record of at most 64 KiB.
Large responses fail explicitly rather than silently producing complete-looking
measurements.

The workflow digest hashes its canonical Go JSON encoding, including layout.
A changed graph must be rebuilt. Compiler destination hints cover literal
network targets and directly connected Constant blocks. Computed or custom
network targets require the submitter to supply the intended destination policy
and enable ICMP when their custom code uses it;
the hints never grant network access. The normal dispatcher and executor checks
apply to every compiled workflow just as they do to hand-written debuglets.
