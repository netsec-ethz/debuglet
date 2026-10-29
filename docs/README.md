# Debuglet documentation

Use the [hosted console](https://debuglet.netsec.ethz.ch/console/) to run
measurements on existing executors. Installation is only needed to host a node,
use the CLI or develop locally. These guides describe the version of Debuglet
in this checkout; check [compatibility](versions.md) before mixing versions.

## Choose your starting point

| Goal | Start here |
| --- | --- |
| **Run your first experiment** | [Choose a template, select a node and inspect the result](measurements.md#run-your-first-measurement). Then compare several vantage points. |
| **Host an executor** | [Install and join a dispatcher](operations/executor-onboarding.md), including shell-only setup and a persistent service. |
| **Build experiments** | [Visual editor, AI assistant and MCP](development/workflow-authoring.md), or [write a debuglet with the Go SDK](debuglets.md). |
| **Contribute** | [Set up development, find the relevant subsystem and test a change](../CONTRIBUTING.md). |

## Using and sharing experiments

- [Measurements](measurements.md): reuse runs, retry and coordinate several programs.
- [Communities](communities.md): shared projects, experiments and group funding.
- [Results](results.md): save highlights, reopen source and export data.
- [Workflow reference](development/workflows.md): blocks, typed connections and communication.
- [CLI](cli.md), [Go client](client.md) and [HTTP API](api.md): automate submissions and retrieve results.

## Operate a deployment

Start with [installation](../README-install.md) and
[executor onboarding](operations/executor-onboarding.md). For your own dispatcher,
use the [deployment guide](../deploy/README.md).

- [Configuration](operations/configuration.md) and [managed services](operations/services.md).
- [Authentication](operations/authentication.md) and [hosted editor/compiler](operations/hosted-studio.md).
- [Debian updates](operations/debian.md), [signed releases](operations/releases.md) and [backup/restore](operations/backup-restore.md).
- [Data retention](operations/data-retention.md), [payments](operations/payments.md) and [abuse response](operations/abuse-response.md).
- [Troubleshooting](operations/troubleshooting.md), [executor recovery](operations/executor-recovery.md) and [monitoring](operations/monitoring.md).

## System reference

- [Architecture](architecture.md) and [threat model](security.md).
- [Vantage-point metadata](vantage-points.md), [probe verification](verification.md) and [packet tag specification](tag-spec.md).
- [OpenAPI contract](../api/openapi.yaml) and [versions/support policy](versions.md).
- [CI checks](development/ci.md), [generated code](development/generated-code.md) and [guest languages](development/guest-languages.md).

Read the [security policy](../SECURITY.md) before operating a networked deployment.
