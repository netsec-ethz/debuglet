# Versions and compatibility

Debuglet supports the latest published release and the current validated `main` revision on Linux amd64. Record the release version or source revision when reporting a problem. Security fixes are not backported.

Use the same reviewed package version for the CLI, dispatcher, and executors in one deployment. Mixed releases are not a supported configuration. The [release page](https://github.com/netsec-ethz/debuglet/releases) records user-visible changes; pull requests record candidate CI evidence.

## Version boundaries

| Surface | Rule |
| --- | --- |
| HTTP API | `Debuglet-API-Version` identifies the public wire contract. Compatible additions change its minor version; breaking changes require a new major version. |
| Control protocol | `protocol_version` identifies its message generation. It does not authenticate an executor. |
| Debuglet ABI | `guest_abi` identifies host imports and their semantics. An incompatible host-interface change requires a new ABI identifier. |
| Persistent state | Database and local-state versions follow the documented upgrade procedure for the selected release. Interrupted runs are not resumed. |

## Tested combinations

The [CI workflow](../.github/workflows/ci.yml) checks the combinations below.
Evidence is scoped to the exact revision and fixture: check the selected
candidate's own completed CI run. A successful run does not publish a release or
establish compatibility for later changes.

| Component | Combination exercised | Evidence and limit |
| --- | --- | --- |
| Platform | Linux amd64 on the `ubuntu-24.04` CI runner and the pinned CI tools image | [CI definition](../.github/workflows/ci.yml), [CI images](development/ci-images.md). Other host/architecture combinations have no native package support. |
| Packages | Same-candidate full bundle and separate CLI, dispatcher and executor packages | Package lane installs twice, verifies each role inventory and runs `--help`; full-bundle runtime checks run in the demo/local lanes. The legacy v0.2.0 release contains only the full bundle. |
| CLI and Go client | Same-source clients and dispatcher; HTTP contract 1.29 | Test, demo and local lanes. Use `dbl version --server` to inspect the selected server's contract; a displayed binary version does not negotiate API features. |
| Dispatcher and executor | Same-package peers; control protocol 3 with binding and lease enforcement. Published v0.2.0 executor against the candidate dispatcher in the loopback TEST fixture | Local and compatibility lanes. The released-peer fixture checks registration, work and reconnect; it does not establish mixed-release TLS/enrollment or new optional features. |
| Guests | `debuglet-go-wasi-imports-v1`, frozen compatibility guest and packaged Go samples | [Guest compatibility gate](debuglets.md#compatibility), compatibility lane. C/Rust guest packages remain experimental. |
| State | State created by the same package; recognized historical SQLite schemas upgraded explicitly | [State reference](operations/configuration.md#stored-state), storagecheck tests. This is not a cross-package foreground-state migration promise. |
| Kernel features | Regenerated eBPF objects loaded on the CI runner's kernel | Kernel lane; the runner kernel is not pinned and this does not establish other-kernel or SCION-path support. |

Choose a package from the [published releases](https://github.com/netsec-ethz/debuglet/releases)
and use the documentation for that version. A source tag alone is not an
installable release. The legacy v0.2.0 package predates component packages,
account-owned `dbl executor join` and the newer authoring APIs.

## v1 support scope

The supported deployment is a managed research service on Linux amd64, with
explicitly enrolled executors, authenticated TLS and operator network policies.
Debian packages target Ubuntu 24.04 amd64. The shared executor profile adds
process and resource limits; it is not a general hostile-code sandbox. Chain
payments remain outside the supported profile and must stay disabled there.
Non-Go guest SDKs remain experimental. See the [security model](security.md)
for the boundaries and [installation guide](../README-install.md) for prerequisites.

Use the console revision identified by the release's compatibility manifest.
Upgrade the dispatcher and console before executors; mixed-version operation is
an upgrade transition, not a supported steady state. Back up stopped state,
apply the packaged migrations explicitly, and retain the prior package and
backup for rollback. For this source, the minimum database versions are
**dispatcher 35** and **executor 9**. Follow the
[upgrade procedure](../deploy/README.md#upgrading-a-database) for the actual release.

A release candidate is for evaluation. It does not replace the stable APT
channel or change existing services automatically.

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

A breaking package change requires a new release version and release notes naming the affected interface, supported starting versions, upgrade or replacement steps, and rollback limits. Do not silently replace a published archive or apply an incompatible state change at daemon startup. Starting with v1.0, an incompatible change to a supported public interface requires a new major package version. Pre-v1 packages may contain breaking changes in a minor version.

Document an API deprecation in OpenAPI and the API guide while the old field or route still works. Remove it only in a later API major, with replacement and migration instructions in the release notes. Record CLI, protocol, ABI, and state changes in the [changelog](../CHANGELOG.md).

A package version does not imply compatibility across every interface or platform. The supported scope remains managed, trusted deployments; a version number or passing CI run does not establish hostile-workload containment.

Packet attribution uses `debuglet-tag-v1`; tags from earlier formats do not
verify under it. Upgrade executors and verifiers together. Optional runtime
operations also require a fresh executor capability report; a version string
alone is not proof of support.

See [API and schema compatibility history](development/compatibility-history.md)
for the additions introduced by each API and database version.
