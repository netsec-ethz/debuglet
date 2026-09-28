# Versions and compatibility

The latest release and the current validated `main` commit are supported;
security fixes are not backported. Pin the package version and source revision you
deploy. A passing test of one combination does not establish compatibility
with other releases or make the trusted alpha suitable for untrusted workloads.

## Tested combinations

All checks below ran on Linux amd64. The [platform matrix](../README-install.md#supported-platforms)
separates client, daemon, and demo support.

| Combination | Evidence and scope |
| --- | --- |
| v0.2.0 CLI, dispatcher, and executor from the same package | [Release CI](https://github.com/netsec-ethz/debuglet/actions/runs/36314607069): installed local TEST flow, contract checks, and guest ABI checks. |
| CLI, dispatcher, and executor built from main `6ba5c2d7` | [Candidate CI](https://github.com/netsec-ethz/debuglet/actions/runs/36321287709): the same checks, plus the normal test, race, and kernel lanes. |
| Retained `debuglet-go-wasi-imports-v1` guest and current SDK guests on those hosts | The compatibility lane runs the [frozen ABI fixture](../pkg/debuglet/testdata/abi_v1) and checks installed guests. |
| Mixed dispatcher/executor releases, or v0.1.0 clients with v0.2.0 services | Not established by the same-build checks above. |

These are owned local fixtures, not validation of a particular remote
deployment. New candidate evidence belongs in its CI run; retain the exact
revision when comparing results.

## Independent version boundaries

| Surface | Compatibility rule |
| --- | --- |
| Package and CLI | Release tags identify the complete package. Use one reviewed version for all roles; arbitrary cross-version CLI or control compatibility is not promised. |
| HTTP API | `api_version` in `/version` and the `Debuglet-API-Version` header describe the wire contract. Compatible additions increase the minor version; a breaking wire change requires a new API major. See [the API reference](api.md). |
| Executor control protocol | `protocol_version` identifies the control message generation. Matching it does not authenticate an executor: enrollment, certificate identity, channel binding, and a live lease remain necessary. |
| Guest ABI | The manifest's `guest_abi` identifies host imports and their semantics. Changing an import name, signature, unit, or ownership rule requires a new ABI identifier and compatibility fixtures. |
| Persistent state | Schema and local-state versions are separate from the API. Reuse is supported only through the documented upgrade path for the selected release; interrupted runs are not resumed. |

## Deprecation and breaking changes

Deprecate an HTTP route or field in OpenAPI and its reference in a minor
version while it still works. Remove it only in a later API major, publishing
the replacement contract and migration instructions before removal. There is
no fixed time-based overlap window or backport promise for this alpha.
Record CLI, control protocol, guest ABI, and state changes explicitly in the
[changelog](../CHANGELOG.md); a package version does not replace those identities.

For example, an **illustrative future v0.3.0 release** that removes a deprecated
HTTP field would publish API **2.0**, not relabel the removal as an API 1.x
addition. Its release note would name the old and replacement fields, show how
to update clients, and identify the earlier 1.x deprecation notice. Before
upgrading, operators would update clients for API 2.0, back up state, follow the
release's [upgrade procedure](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades),
and validate a measurement with all roles on the new package. Any schema or ABI
change would need its own migration or guest rebuild instructions. This is a
release-note example, not a scheduled release or a claim that mixed versions
have been tested.
