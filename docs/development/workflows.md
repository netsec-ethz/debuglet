# Visual measurement programs

A workflow is a versioned JSON program that can be edited visually or through
an authoring tool. It compiles to one Go WASI debuglet. Network operations,
processing, branches and bounded repetition execute on the selected executor;
they do not require a round trip through an AI client or dispatcher.

Start with [HTTP status branching](../../examples/workflows/http-status.json),
[Ping and RTT analysis](../../examples/workflows/ping-branch.json), or
[a custom processing block](../../examples/workflows/custom-transform.json).
The network examples use loopback placeholders: choose an endpoint you control
and permit its address in the normal submission policy. On a remote executor,
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
Redirects are not followed. Check `ok` for transport errors and compare `status`
to express the status policy you need. Ping's `rtts_ms` contains only successful
replies and `loss` is a percentage. Check `received` before calculating a mean;
analysis of an empty sample set fails rather than reporting a misleading zero.

Repeat has a `body` and a `done` output. The body runs sequentially until its
control path ends, then starts again. Its action outputs are cleared between
iterations. Repeat's `iteration` output starts at 1. After the requested count,
execution continues at `done`. A body cannot also lead into that continuation
or be entered by another control path. Arbitrary cycles are rejected.

Programs support up to 128 nodes, 100 repeat iterations and 1,000 action steps.
A single wait or network timeout is at most 60 seconds. Graph control limits
complement the ordinary executor's runtime, traffic and destination limits.

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

Individual strings are limited to 16 KiB and lists to 1,024 entries. Each event
is at most 64 KiB; a run emits at most 4,096 events and 4 MiB of trace output.
Large responses fail explicitly rather than silently producing complete-looking
measurements.

The workflow digest hashes its canonical Go JSON encoding, including layout.
A changed graph must be rebuilt. Compiler destination hints cover literal
network targets and directly connected Constant blocks. Computed or custom
network targets require the submitter to supply the intended destination policy
and enable ICMP when their custom code uses it;
the hints never grant network access. The normal dispatcher and executor checks
apply to every compiled workflow just as they do to hand-written debuglets.

See [authoring and building workflows](workflow-authoring.md) for the CLI,
local visual editor and MCP interface.
