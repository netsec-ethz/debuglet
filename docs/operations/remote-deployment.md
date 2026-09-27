# Run Debuglet across hosts

A networked deployment has one dispatcher and one or more executors on Linux amd64 hosts. Every role runs the same Debuglet release. Use TLS, authenticate users, and keep the local-development profile disabled.

## Required topology

- Clients reach the dispatcher HTTP API.
- Executors connect outward to the dispatcher's HTTP and gRPC control listeners.
- Executors need no public inbound control port.
- The dispatcher certificate must match the name or address executors use.

## Recommended process

1. Install the release on the dispatcher and executor hosts.
2. Issue a private CA, dispatcher server certificate, and executor client certificates.
3. Create the dispatcher database and configure its TLS listeners.
4. Configure each executor with a stable UUID, private state directory, dispatcher addresses, and credentials.
5. Start the dispatcher, then executors; confirm every executor is ready before accepting work.
6. Register a client and submit one small TEST measurement.

The [Operating a Dispatcher](https://github.com/netsec-ethz/debuglet/wiki/Operating-a-Dispatcher), [Operating an Executor](https://github.com/netsec-ethz/debuglet/wiki/Operating-an-Executor), and [Deployment and Upgrades](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades) Wiki pages contain the operator workflow and recovery guidance.
