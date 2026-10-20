# Visual workflows and AI authoring

`dbl-studio` compiles a visual workflow into an ordinary Debuglet WASI program.
The editor, command line and MCP tools share the same versioned graph and block
catalog. Conditions, calculations and repeats execute inside that program on the
executor. The dispatcher does not compile source or orchestrate individual blocks.

The first version provides a local authoring service. A statically hosted console
can edit and export graphs and import compiled bundles; it cannot compile Go by
itself. To compile and submit from the visual editor, run the local service with a
built console and a trusted checkout of the matching Debuglet SDK.

## Start the editor

Install Go 1.26.9, clone Debuglet, then build the authoring tool:

```sh
go build -o dbl-studio ./cmd/dbl-studio
```

In the dashboard repository, build with the console path explicitly set:

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

Inspect the compiler's exact block catalog with `dbl-studio catalog`.

```sh
./dbl-studio validate --input experiment.workflow.json
./dbl-studio build --sdk /path/to/debuglet \
  --input experiment.workflow.json --output experiment.bundle.json
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
