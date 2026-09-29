# Debuglet documentation

This directory is the versioned source for the [Debuglet documentation site](https://debuglet.netsec.ethz.ch/docs/), including user and operator guides, architecture, and public contracts. Read the version matching your installation.

## Use Debuglet

- [CLI reference](cli.md) — commands, local demo, and scriptable workflows.
- [Go client library](client.md) — submit debuglets and read results from an application.
- [Portable results](results.md) — export retained output and admission facts for offline analysis.
- [Write a debuglet](debuglets.md) — execution model and Go authoring interface.
- [HTTP API](api.md) — public contract, authentication, compatibility, and deprecation.
- [Versions and compatibility](versions.md) — tested combinations, support policy, and breaking changes.
- [Linux client container](operations/client-container.md) — remote client with persistent credentials.
- [Troubleshooting](operations/troubleshooting.md) — first steps for setup, login, readiness and state errors.

## Understand the system

- [Architecture](architecture.md) — components, trust boundaries, protocol flow, and storage.
- [Vantage-point metadata](vantage-points.md) — design for network, location and reachability context with provenance.
- [Packet tag specification](tag-spec.md) — `debuglet-tag-v1`: authenticated bytes, key derivation, verification and false-match bounds.
- [Probe verification](verification.md) — design for how a probe recipient verifies which run sent a packet.

## Operate a deployment

- [Configuration reference](operations/configuration.md)
- [Run Debuglet across hosts](operations/remote-deployment.md)
- [Managed services](operations/services.md)
- [Executor recovery](operations/executor-recovery.md)
- [Inspect an interrupted run](operations/recovery-inspection.md)
- [Local validation checks](operations/local-checks.md)

Use the [deployment guide](../deploy/README.md) for the maintained Ansible procedures and upgrade inputs.

## Find the original walkthrough material

| Topic | Current home |
| --- | --- |
| Submission and execution flow | [Architecture](architecture.md#measurement-flow) |
| Guest-language examples | [Debuglet examples](../examples/debuglets); Go is supported, C and Rust are experimental |
| Optional SCION and eBPF controls | [Executor configuration fields](../internal/executor/config/config.go) define `network.policy.scion`, `network.disable_scion_environment`, `network.packet_counter` and `network.interface`; see [kernel checks](../scripts/ci-kernel.sh) and [support limits](../SECURITY.md). SCION is off by default. |
| Packet attribution | [Tag specification](tag-spec.md), [capture verifier](../tools/verify_pcap.py) and [current supported scope](../SECURITY.md); attribution is not destination consent or a general authentication guarantee |
| Deployment and state | [Across-host topology](operations/remote-deployment.md), [managed services](operations/services.md), and the [deployment guide](../deploy/README.md) |
| Local or legacy account-key users | [Re-login and recovery](cli.md#return-to-an-existing-account) |

## Develop and contribute

- [Continuous integration](development/ci.md)
- [CI images](development/ci-images.md)
- [Generated code](development/generated-code.md)
- [Contributing](../CONTRIBUTING.md)
