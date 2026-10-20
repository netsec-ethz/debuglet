# Build workflows and experiments

Choose **Workflow builder** to write one executor's program. Choose
**Experiment builder** to connect two or three participants, each with its own
workflow. The same graph can be edited visually, authored by an MCP client or
compiled from the command line with `dbl-studio`.

Conditions, calculations and repeats execute inside the compiled WASI program.
The dispatcher coordinates experiment readiness and stores results; it does not
compile source or orchestrate individual blocks. See the
[workflow guide](workflows.md) for HTTP bodies, processing blocks, reusable
visual groups and custom Go blocks.

`dbl-studio` is currently built from source; it is not part of the release or apt
packages. A hosted console can edit and export graphs and import compiled bundles.
Compilation needs Go and a trusted checkout of the matching SDK on the authoring
machine. The local service can combine editing and compilation in one browser tab.

## Start the editor

On Linux, install Go 1.26.9, clone this version of Debuglet, and build the
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
Go 1.26.9 and an offline build with a two-minute deadline. No graph can choose
build flags, fetch a dependency or run a generation command. One build runs at a
time. Workflows are limited to 1 MiB and bundles to 24 MiB. Install the toolchain
and prepare the trusted SDK before starting an offline authoring session.

For a multi-executor experiment, use the experiment editor or these commands:

```sh
./dbl-studio validate-experiment \
  --input examples/workflows/experiments/three-node.json
./dbl-studio build-experiment --sdk /path/to/debuglet \
  --input examples/workflows/experiments/three-node.json \
  --output three-node.experiment-bundle.json
```

The bundle includes the editable experiment, generated source and ordinary
WASM bundle for each participant. Import it into the experiment editor, bind
participants to distinct reachable executors, then choose **Review and run**.
Review the grouped measurement's policies, timing and TEST quote before
submitting. Compilation and import do not submit a measurement.
See [experiment communication](workflows.md#experiments-with-several-executors)
for listener requirements, message limits and request/reply semantics.

The resulting **Measurement group** page shows a participant map. Select a node
to see its reported values; connection details and raw traces remain expandable.
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
