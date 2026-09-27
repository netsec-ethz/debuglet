# Debuglet documentation

This directory contains versioned documentation that describes the source tree and its public contracts. The [Wiki](https://github.com/netsec-ethz/debuglet/wiki) contains living, role-based deployment and operations guides.

## Use Debuglet

- [CLI reference](cli.md) — commands, local demo, and scriptable workflows.
- [Go client library](client.md) — submit debuglets and read results from an application.
- [Write a debuglet](debuglets.md) — execution model and Go authoring interface.
- [HTTP API](api.md) — public contract, authentication, compatibility, and deprecation.

## Understand the system

- [Architecture](architecture.md) — components, trust boundaries, protocol flow, and storage.

## Operate a deployment

- [Configuration reference](operations/configuration.md)
- [Run Debuglet across hosts](operations/remote-deployment.md)
- [Managed services](operations/services.md)
- [Executor recovery](operations/executor-recovery.md)
- [Local validation checks](operations/local-checks.md)

Use the [Wiki](https://github.com/netsec-ethz/debuglet/wiki) for complete procedures for dispatcher and executor operators.

## Develop and contribute

- [Continuous integration](development/ci.md)
- [CI images](development/ci-images.md)
- [Generated code](development/generated-code.md)
- [Contributing](../CONTRIBUTING.md)
