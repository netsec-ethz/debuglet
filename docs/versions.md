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

## Tested combinations

Evidence is scoped to the named revision and fixture. The successful
[CI run for main `46ee1637`](https://github.com/netsec-ethz/debuglet/actions/runs/36621972902)
checks the current source baseline below; it does not publish a release or
establish compatibility for later changes. Check the candidate's own CI when
selecting another revision.

| Component | Combination exercised | Evidence and limit |
| --- | --- | --- |
| Platform | Linux amd64 on the `ubuntu-24.04` CI runner and the pinned CI tools image | [CI definition](../.github/workflows/ci.yml), [CI images](development/ci-images.md). Other host/architecture combinations have no native package support. |
| Packages | Same-candidate full bundle and separate CLI, dispatcher and executor packages | Package lane installs twice, verifies each role inventory and runs `--help`; full-bundle runtime checks run in the demo/local lanes. Split packages exist in source/CI; published v0.2.0 contains only the full bundle. |
| CLI and Go client | Same-source clients and dispatcher; HTTP contract 1.10 | Test, demo and local lanes. A displayed binary version does not negotiate API features. |
| Dispatcher and executor | Same-package peers; control protocol 3 with binding and lease enforcement. Published v0.2.0 executor against the candidate dispatcher in the loopback TEST fixture | Local and compatibility lanes. The released-peer fixture checks registration, work and reconnect; it does not establish mixed-release TLS/enrollment or new optional features. |
| Guests | `debuglet-go-wasi-imports-v1`, frozen compatibility guest and packaged Go samples | [Guest compatibility gate](debuglets.md#compatibility), compatibility lane. C/Rust guest packages remain experimental. |
| State | State created by the same package; recognized historical SQLite schemas upgraded explicitly | [State reference](operations/configuration.md#stored-state), storagecheck tests. This is not a cross-package foreground-state migration promise. |
| Kernel features | Regenerated eBPF objects loaded on the CI runner's kernel | Kernel lane; the runner kernel is not pinned and this does not establish other-kernel or SCION-path support. |

The latest published package is
[v0.2.0](https://github.com/netsec-ethz/debuglet/releases/tag/v0.2.0). It predates
component packages, account-owned `dbl executor join` and subsequent protocol/API
additions documented on `main`. Use documentation from the selected release tag;
source readiness and a successful candidate build do not make an artifact a
published release.

### Control compatibility and identity

| Peer combination/profile | Support decision |
| --- | --- |
| Same reviewed package, control generation 3, valid binding/token and lease parameters | Supported control profile, subject to that package's capability checks and configured TLS/enrollment. |
| Legacy generation 0, previous generations 1/2, or an unknown future generation | Unsupported; negotiation rejects the incompatible profile before work admission. |
| Generation 3 with missing/malformed binding or token | Rejected; a version string cannot replace session authority. |
| Generation 3 without an optional capability | That capability is unavailable; matching protocol does not imply optional inspection, durable output or tagging support. |
| Published v0.2.0 executor → candidate dispatcher | The local lane installs the checksum-pinned release and checks registration, TEST work, reconnect with retained identity and fresh work. This is an upgrade compatibility fixture; use one reviewed version for deployed fleets. |
| Other mixed software releases or deployment profiles | No support established, including two releases that both report generation 3. Use one reviewed package across the deployment. |

The recorded [adjacent-build check](https://github.com/netsec-ethz/debuglet/issues/61#issuecomment-5828879951)
ran registration and work between `8bb32f4` and `10f0f4f` in both
directions, and older-executor reconnect to the newer dispatcher. Both were development builds of generation 3; this is not evidence
for two supported releases. The [installed released-peer tests](../internal/acceptance/roles/released_integration_test.go)
now exercise the published v0.2.0 archive (source `be5142f7`) against the candidate,
without rebuilding that release. Each candidate's local CI lane verifies this
exact released-peer matrix on Linux amd64 loopback before merge.
Negative negotiation fixtures cover unsupported generations and missing
authority; optional-operation tests cover unavailable capabilities.

The same installed fixture upgrades populated v0.2.0 dispatcher/executor
databases with the candidate's packaged migrations, then starts that candidate
and checks retained identities, bindings, output and verification history.
It also checks the old daemons refuse newer schemas before readiness and can
serve the restored offline backup. Follow the [deployment upgrade procedure](../deploy/README.md#upgrading-a-database);
this does not permit editing foreground local-role package metadata to bypass
its version check.

An executor's displayed software version and capability report are peer claims.
Its identity is bound to an enrolled client certificate only when the deployment
requires and verifies that certificate on both control paths. See the
[threat model](security.md#dispatcher-and-executor-control).

## Breaking changes

A breaking package change requires a new release version and release notes naming the affected interface, supported starting versions, upgrade or replacement steps, and rollback limits. Do not silently replace a published archive or apply an incompatible state change at daemon startup. During the alpha, a breaking change uses at least a new minor package version; after 1.0 it requires a new major.

Document an API deprecation in OpenAPI and the API guide while the old field or route still works. Remove it only in a later API major, with replacement and migration instructions in the release notes. Record CLI, protocol, ABI, and state changes in the [changelog](../CHANGELOG.md).

A package version does not imply compatibility across every interface or platform. The project is a trusted-environment alpha; a passing CI run does not establish remote-deployment or untrusted-workload support.

API 1.9 adds optional durable cancellation inspection. Dispatcher schema 12 stores one cancellation request per run; upgrade explicitly before starting this build. The executor schema and Abort wire protocol are unchanged. Cancellation is never automatically replayed after restart, and requests never acquire a replacement session's authority.

Packet tags follow a versioned [tag specification](tag-spec.md). Current `main`
introduces `debuglet-tag-v1`, a breaking change of the tag format: tags of
earlier builds do not verify under it. Executors report the version as
`capabilities.tagging.tag_spec`; deploy one version across a fleet and its
verifiers.

API 1.9 also adds executor admission state, operator display metadata and the executor-reported SCION ISD-AS and listeners to `GET /executors`. The control protocol gains an optional `VantagePointReport` without a version change: an older executor leaves these fields unknown, and an older dispatcher ignores the report. The ICMP, fallback-reason, clock and platform probes are further additive fields of `ExecutorCapabilities` and `VantagePointReport` within schema 1, with the same compatibility.

API 1.10 adds optional [account-owned executor enrollment](operations/executor-onboarding.md). Dispatcher schema 13 stores machine ownership; upgrade explicitly to the packaged schema before starting this build. The executor schema and control protocol are unchanged. Enrollment is disabled until the dispatcher administrator configures its signing authority and connection addresses.

API 1.11 adds the public attribution lookups `GET /attribution/candidates` and `GET /attribution/keys` and deprecates `GET /executors/by-ip` and `GET /executors/{id}/tesla`, which keep working within API major 1. Dispatcher schema 14 stores the attribution history they answer from; upgrade explicitly before starting this build. The control protocol gains the optional `tesla_chain_length` (hello) and `tesla_key_anchor` (heartbeat) fields without a version change; an older peer leaves them empty.

API 1.12 adds measurement profiles, batch details, explicit retry lineage, listener readiness and owner payload deletion. Retry clients require 1.12 so a dispatcher that only supports attribution cannot silently accept a request without retaining its retry identity. Dispatcher schema 15 stores the workflow metadata; schema 16 adds account reservations and payload tombstones.

Dispatcher schema 21 records one settlement per order and the pricing rule of each transaction; this build refuses an older dispatcher database, so upgrade it explicitly before starting this build.

Dispatcher schema 22 records chain payment receipts and outbound chain transfers. The receipt listener and the transfer code depend on it, so this build requires schema 22; upgrade explicitly before starting it. The HTTP API is unchanged.

API 1.15 adds `POST /payment/quote`, the `quote` field of the payment intent response, the `economics` field of `GET /me`, `GET /me/orders`, the usage allowance routes `GET /me/allowance` and `POST /operator/accounts/{id}/allowance`, the `allowance_exceeded` and `conflict` error codes, and `GET /operator/executors/{id}/earnings`. The Go client requires 1.15 for these routes.

Dispatcher schema 23 records usage allowance grants in `allowance_grants`. The allowance routes and the capped intent depend on it, so this build requires schema 23; upgrade explicitly before starting it.
