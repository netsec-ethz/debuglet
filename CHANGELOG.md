# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Only `[Unreleased]` changes between tags. Release entries summarize user-visible
changes; the linked API and deployment documentation contains operational detail.

## [Unreleased]

### Changed
- Move the debuglet examples from `local/wasm_samples/` to `examples/debuglets/`,
  the local daemon configurations from `local/configs/` to `configs/`,
  `verify_pcap.py` to `tools/`, and the illustrative HTTP exchanges to
  `api/http-examples.json`. Update `make wasm SAMPLE_DIR=...` and `-config`
  paths accordingly.

### Removed
- Remove the unsupported JavaScript and Python debuglet samples and the Javy
  build path of `make wasm`.

## [0.2.0-rc.3] - 2026-09-26

### Changed
- Keep the HTTP API at `1.3`; the `rc.2` changelog incorrectly said `1.2`.
- Use tc `clsact` when TCX is unavailable. The pure-Go fallback now tags IPv4
  UDP and ICMP with SipHash-2-4 and `CAP_NET_RAW`; TCP, TLS, and SCION remain
  untagged in this mode.
- Require lowercase canonical run IDs in the API, CLI, and Go client.
- Configuration-only deployments now preserve the release recorded on each
  host and reject conflicting version overrides.

### Fixed
- Continue deploying other executors when one host becomes unreachable.
- Handle invalid SCION path indices and missing metadata without panicking.
- Reject expired or not-yet-valid executor client certificates at startup.
- Flush credentials, local state, and managed-service files before atomic
  replacement to prevent empty or truncated files after a crash.
- Use the selected environment's SSH `known_hosts` file in maintenance tasks.
- Release completed runs from the eBPF bandwidth-counter map.
- Enforce SQLite foreign keys, briefly wait for locks, and write payment intent
  data atomically. Database upgrades report existing invalid rows.

### Removed
- Remove unused verification scripts superseded by `dbl`, `pkg/client`, and
  `verify_pcap.py`.
- Drop big-endian eBPF artifacts and executor builds; supported Linux targets
  are little-endian.

### Known limitations
- SCION traffic is not attributed to runs.
- The web dashboard is not fully compatible with authenticated sessions; use
  `dbl` or `pkg/client` for complete workflows.
- Packages are Linux amd64 only. Local state is package-version-specific, and
  interrupted runs are not recovered.

## [0.2.0-rc.2] - 2026-09-25

### Added
- Add GitHub browser login with OAuth PKCE and deployment-specific credentials.
- Add backed-up database upgrades for deployed wallet-free TEST state. Before
  deploying, run `make deploy-upgrade-db DEPLOY_ENV=<env>`.

### Changed
- Advance the HTTP API to `1.3` for GitHub browser login routes.
- Reject request bodies over 32 MiB and invalid or duplicate payment batches.
- Make run submission idempotent and charge timeout prices by rounded-up
  milliseconds.
- Return stable cancellation errors, report unready services with exit code 4,
  and reject destination limits below admitted capacity.

### Fixed
- Do not refund refused resubmissions whose orders already have runs.
- Charge the full datagram size when the receiving buffer truncates it.

### Schema
- Allow populated dispatcher databases at schema 3 to upgrade through migration
  00004. Databases already past schema 4 are unchanged.

### Known limitations
- SCION traffic is not attributed to runs. The dashboard remains incompatible,
  packages are Linux amd64 only, local state is package-version-specific, and
  interrupted runs are not recovered.

## [0.2.0-rc.1] - 2026-09-25

### Added
- Add the `dbl` CLI, Go SDK, OpenAPI contract, and packaged local demo.
- Add managed dispatcher/executor services, drain and readiness operations, and
  verified Linux amd64 packages.
- Add accounts, expiring sessions, recovery, operator roles, executor
  enrollment, and per-owner authorization.
- Add reproducible CI and isolated, verified development/production deployment.

### Changed
- Replace UUID client identity with account keys and server-issued sessions.
- Version HTTP (`1.2`), binary, and executor-control compatibility separately.
- Bundle services, CLI, migrations, sample module, installer, manifest, and
  checksums in one release archive.
- Require fresh local state between versions and make production deployment an
  explicit operator action.

### Security
- Bind executor sessions to enrolled identities and short leases with mutual TLS.
- Enforce account authorization, destination policy, and traffic accounting.
- Harden installation, configuration, process ownership, credentials, errors,
  shutdown, and artifact verification.

### Fixed
- Bound executor registration handshakes, preserve completed work across
  restarts, and isolate unreachable hosts during deployment.
- Make versions, certificate identities, interpreters, and fallback packet
  counting explicit and verifiable.

### Known limitations
- The dashboard is incompatible; use `dbl` or `pkg/client`.
- Packages are Linux amd64 only. Database upgrades and interrupted-run recovery
  are not supported in this candidate.

## [0.1.0] - 2026-09-17

### Added
- Initial public release.

[Unreleased]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0-rc.3...HEAD
[0.2.0-rc.3]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0-rc.2...v0.2.0-rc.3
[0.2.0-rc.2]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0-rc.1...v0.2.0-rc.2
[0.2.0-rc.1]: https://github.com/netsec-ethz/debuglet/compare/v0.1.0...v0.2.0-rc.1
[0.1.0]: https://github.com/netsec-ethz/debuglet/releases/tag/v0.1.0
