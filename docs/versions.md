# Versions and compatibility

Debuglet supports the latest published release and the current `main` revision on Linux amd64. Record the release version or source revision when reporting a problem. Security fixes are not backported.

Use the same reviewed package version for the CLI, dispatcher, and executors in one deployment. Mixed releases are not a supported configuration. The [release page](https://github.com/netsec-ethz/debuglet/releases) records user-visible changes; pull requests record candidate CI evidence.

## Version boundaries

| Surface | Rule |
| --- | --- |
| HTTP API | `Debuglet-API-Version` identifies the public wire contract. Compatible additions change its minor version; breaking changes require a new major version. |
| Control protocol | `protocol_version` identifies its message generation. It does not authenticate an executor. |
| Debuglet ABI | `guest_abi` identifies host imports and their semantics. An incompatible host-interface change requires a new ABI identifier. |
| Persistent state | Database and local-state versions follow the documented upgrade procedure for the selected release. Interrupted runs are not resumed. |

## Breaking changes

Document an API deprecation in OpenAPI and the API guide while the old field or route still works. Remove it only in a later API major, with replacement and migration instructions in the release notes. Record CLI, protocol, ABI, and state changes in the [changelog](../CHANGELOG.md).

A package version does not imply compatibility across every interface or platform. The project is a trusted-environment alpha; a passing CI run does not establish remote-deployment or untrusted-workload support.

API 1.9 adds optional durable cancellation inspection. Dispatcher schema 12 stores one cancellation request per run; upgrade explicitly before starting this build. The executor schema and Abort wire protocol are unchanged. Cancellation is never automatically replayed after restart, and requests never acquire a replacement session's authority.

API 1.9 also adds executor admission state, operator display metadata and the executor-reported SCION ISD-AS and listeners to `GET /executors`. The control protocol gains an optional `VantagePointReport` without a version change: an older executor leaves these fields unknown, and an older dispatcher ignores the report. The ICMP, fallback-reason, clock and platform probes are further additive fields of `ExecutorCapabilities` and `VantagePointReport` within schema 1, with the same compatibility.
