# Create and run experiments

Choose **New experiment** (`/console/experiments/new`) to design a program, then
move to **Run** to choose executors and review its permissions. Use **Add a
program** when two or three programs need to coordinate, each on a distinct
executor. The same graph can be edited visually, authored by an MCP client or
compiled from the command line with `dbl-studio`. Existing builder links remain
valid.

Use [communities](../communities.md) to save editable source and compiled bundles
in a shared project, retain revisions and collect the resulting measurements.

The console's **Templates** library provides categorized, configurable starting
points alongside personal and community templates. **Save as template** stores
source under your account or shares a copy in a community project. Opening a
template creates a separate draft. Literal inputs and custom code remain part of
the source; compiled programs and executor bindings are not saved in personal
templates. Existing community experiments retain their revision/bundle support.

For independent observations from many vantage points, design one program and
select 1–128 executors during submission, within the dispatcher's limits. This uses ordinary grouped admission
and results, without requiring participants to listen for peer connections. Use
multiple programs when they actually need to exchange messages.

When the operator enables the optional assistant, describe the experiment in
the editor's chat panel. It proposes editable blocks or asks for clarification.
The prompt, visible source and included conversation are sent to the configured
model provider. Review the proposal on the canvas; building and submitting a run
remain explicit actions. Ordinary editing works when assistance is unavailable.

Conditions, calculations and repeats execute inside the compiled WASI program.
The dispatcher coordinates experiment readiness and stores results; it does not
compile source or orchestrate individual blocks. See the
[workflow guide](workflows.md) for HTTP bodies, processing blocks, reusable
visual groups and custom Go blocks.

`dbl-studio` is currently built from source; it is not part of the release or apt
packages. When an operator enables the [hosted compiler](../operations/hosted-studio.md),
the console can build workflows and experiments directly. Otherwise, use the
local service with Go and a trusted checkout of the matching SDK to compile a
bundle, then import it into the console.

## Start the editor

On Linux, install Go 1.26.10, clone this version of Debuglet, and build the
authoring tool from the repository root:

```sh
go build -o dbl-studio ./cmd/dbl-studio
```

In the [dashboard repository](https://gitlab.inf.ethz.ch/OU-PERRIG/yimin/debuglet/debuglet-dashboard),
follow its **Run locally** prerequisites first: Node.js 24.14.0, `npm ci`, and
both template builds with their pinned Go versions. Then build the console with
its path explicitly set:

```sh
VITE_BASE_PATH=/console npm run build
```

This sets both the application router and its asset URLs. A build for `/` will
not work under the studio's `/console/` route. Point the service at that build
and your owned development dispatcher origin:

```sh
./dbl-studio serve \
  --sdk /path/to/debuglet \
  --ui /path/to/debuglet-dashboard/dist \
  --dispatcher https://127.0.0.1:8000 \
  --listen 127.0.0.1:8090
```

Open the exact address printed by the command. The editor and its API use the same
loopback origin. `/api/` forwards to the one configured loopback dispatcher.
`--dispatcher` accepts a loopback IP or `localhost`, without an API path. For an owned
development dispatcher with local account sign-in enabled, this supports the
existing console login and submission flow. GitHub/CILogon sign-in through this
loopback proxy is not supported: provider callbacks and their cookies belong to
the hosted console's configured origin. For a provider-only dispatcher, build
locally, import the bundle into its hosted console, and sign in there normally.
The service never supplies login credentials or changes dispatcher policy. Use `--ca-file /path/to/dispatcher-ca.pem` when its HTTPS certificate is
signed by your own CA; certificate and hostname verification remain enabled. Do not
expose or tunnel this service to an untrusted network.

Without `--sdk`, the service can show the editor and validate graphs but cannot
compile. Without `--dispatcher`, editing and compilation work, while sign-in and
submission are unavailable. `--ui` must contain the dashboard's built `index.html`.

## Build and review a bundle

Inspect the compiler's exact block catalog with `./dbl-studio catalog`. For
example, from the core repository:

```sh
./dbl-studio validate --input examples/workflows/http-status.json
./dbl-studio build --sdk /path/to/debuglet \
  --input examples/workflows/http-status.json --output http-status.bundle.json
```

A bundle contains the editable graph, its canonical JSON, generated Go, compiled
WASM, destination hints and SHA-256 digests. Import it into the visual editor to
inspect the program, then choose executors and review the normal submission
policy. Editing the graph invalidates the compiled artifact and requires rebuilding.
A digest detects changes; it does not certify that a third-party WASM implements
its claimed source. Review the bundle's origin and rebuild unfamiliar source.

Compilation uses a disposable module, the explicitly configured SDK checkout,
Go 1.26.10 and an offline build with a two-minute deadline. No graph can choose
build flags, fetch a dependency or run a generation command. One build runs at a
time. Workflows are limited to 1 MiB and bundles to 24 MiB. Install the toolchain
and cache the trusted SDK's dependencies before starting an offline authoring
session. Generated builds use the SDK's pinned versions and checksums, including
the DNS codec. Hosted compiler bundles carry their required offline modules.

The **Templates** library includes DNS sampling, UDP and TCP exchanges, verified TLS
inspection, consecutive hop probes and timers. Replace documentation addresses
with permitted targets before running. Coordinated templates include repeated
phases and a UDP server/client/collector flow. Every program uses the same
primitive blocks, so an MCP-authored graph remains editable visually.

**For each item** runs a body for each value in a list of at most 100 items.
It exposes `item` and zero-based `index`; an empty list goes directly to `done`.
Body outputs are scoped to that body. Collect observations into a collection and
read it after `done` to report a combined result. The normal workflow step budget
still applies, including to nested loops.

Collection operations include distinct values, set union/intersection/difference,
grouping rows by a field and joining tables. Comparisons preserve JSON types;
there is no string/number coercion. Joins are inner joins returning `{left,right}`
pairs, including every duplicate-key match, with at most 1024 result rows. Missing
group/join fields are errors; outputs larger than 64 KiB are rejected.

DNS queries also expose address and name lists for simple wiring. Feed an address
through **Address and port** before a TCP action; IPv6 brackets are handled for you.
NSID has separate presence and Base64 outputs because it is optional binary data.
Matching identifiers or answers are observations, not proof of shared physical
infrastructure or independent failure domains.

Bundles also carry `require_udp_listener` and `required_host_functions` when
needed. The console checks these against fresh executor reports; editing or
importing a graph does not upgrade the executor. An incompatible node remains
visible in its operator's inventory with update guidance.

For a coordinated experiment, add programs in the editor or use these commands:

```sh
./dbl-studio validate-experiment \
  --input examples/workflows/experiments/three-node.json
./dbl-studio build-experiment --sdk /path/to/debuglet \
  --input examples/workflows/experiments/three-node.json \
  --output three-node.experiment-bundle.json
```

The bundle includes the editable experiment, generated source and ordinary
WASM bundle for each participant. Import it into the editor, then choose **Run**
to compile the latest design if needed and select distinct reachable executors.
Choose **Review permissions** and review the group's policies, timing and quote
before submitting. Compilation and import do not submit a measurement.
See [experiment communication](workflows.md#experiments-with-several-executors)
for listener requirements, message limits and request/reply semantics.

The resulting run opens on **Results**, showing reported metrics, charts and
tables. Select a participant to see its results, or open the optional connections
map. **Activity** contains traces and raw output; **Details** contains source,
configuration and cost. Failure and incomplete-output warnings remain visible.
**Edit and run again** opens an independent editable copy when source was retained;
older runs without source can still reuse their retained settings. Save useful
reports to the **Results library** to return to them and their originating run.

New experiment programs include a connection manifest in their output, so the
map can load after a page reload. It describes declared communication, not
observed message delivery. For older runs, **More → Load experiment map** accepts
the compiled experiment bundle when every participant's program hash matches
the retained run. That imported map is kept only for the current page visit.

## Connect an MCP client

Configure a stdio MCP server in your client's settings:

```json
{
  "mcpServers": {
    "debuglet": {
      "command": "/path/to/dbl-studio",
      "args": [
        "mcp", "--sdk", "/path/to/debuglet",
        "--workspace", "/path/to/my-workflows"
      ]
    }
  }
}
```

Available tools:

| Tool | Purpose |
| --- | --- |
| `catalog` | Inspect primitive blocks, typed ports and control outputs. |
| `validate` | Check a workflow using the compiler's validator. |
| `save_workflow` | Save the editable graph under a simple name in the workspace. |
| `get_workflow` | Read that named graph for further editing. |
| `build` | Compile the graph and return a bundle path and artifact metadata. |
| `validate_experiment` | Check participant graphs and their directed message channels. |
| `build_experiment` | Compile the whole experiment and return a portable bundle path. |
| `read_artifact` | Inspect a bundle created in the current session without returning WASM bytes. |

Ask the client to compose a graph, validate it and save it. Open the saved workflow
or bundle in the visual editor, inspect its branches and source, and change it as
needed. The tools have no submission, payment or executor-management action.
They accept workflow names rather than arbitrary paths. A session retains up to
16 build artifact references; files remain in your chosen workspace after exit.

Custom Go blocks remain visible function bodies with declared ports. They execute
with the enclosing guest's permissions and limits, not in an additional per-block
sandbox. Runtime destination permissions and operator network policy still apply;
compiler destination hints do not grant network access. See
[Workflow format](workflows.md) for supported blocks and control-flow rules.
