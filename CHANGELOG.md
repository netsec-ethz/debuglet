# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-rc.1] - 2026-09-25

### Added
- Add the `dbl` CLI, Go client SDK, versioned OpenAPI contract, and packaged
  local demo for running Debuglet without a pre-existing deployment.
- Add independently managed dispatcher and executor roles, systemd service
  installation, drain operations, readiness reporting, and verified Linux
  amd64 release packages.
- Add authenticated accounts, expiring sessions, credential recovery, operator
  roles, executor enrollment, and ownership checks for runs and results.
- Add reproducible GitHub CI lanes for formatting, generation, tests, race
  detection, kernel integration, packaging, compatibility, and local operation.
- Add isolated development and production deployment profiles with pinned
  dependencies, SSH host identities, TLS certificates, preflight checks, and
  post-deployment verification.

### Changed
- Replace UUID-based client identity with account keys and server-issued
  sessions. Existing dashboard clients must migrate to the session API.
- Version the HTTP API independently from the binaries and executor control
  protocol; the initial documented HTTP contract is `1.2`.
- Package the dispatcher, executor, CLI, migrations, sample module, installer,
  manifest, and checksums as one versioned Linux amd64 release.
- Require a fresh state directory when moving between package versions; state
  upgrades are not supported by this release candidate.
- Make production deployment an explicit local operator action while retaining
  GitHub CI for build and validation.

### Security
- Bind executor control sessions to enrolled identities and short-lived leases,
  and verify mutual TLS identities across remote deployments.
- Enforce per-account authorization for runs, output, cancellation, payment
  status, and administrative operations.
- Apply destination policy and traffic accounting to outbound and accepted
  guest traffic, including a userspace counter for hosts without usable eBPF.
- Harden installation, generated configuration, process ownership, shutdown,
  credential storage, error redaction, and release artifact verification.

### Fixed
- Prevent a stalled executor handshake from blocking registration indefinitely.
- Preserve completed work and acknowledgements across executor restarts, and
  isolate unreachable executors during deployment.
- Make deployment versions, certificate identities, interpreter selection, and
  fallback packet counting explicit and verifiable.

### Known limitations
- The separately deployed web dashboard still uses the retired mock-login API
  and is not compatible with this release candidate. Its migration is tracked
  separately; use `dbl` or `pkg/client` in the meantime.
- Only Linux amd64 packages are published. Database upgrades between package
  versions and durable recovery of interrupted runs are not supported.

## [0.1.0] - 2026-09-17

### Added
- Initial public release.

[Unreleased]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0-rc.1...HEAD
[0.2.0-rc.1]: https://github.com/netsec-ethz/debuglet/compare/v0.1.0...v0.2.0-rc.1
[0.1.0]: https://github.com/netsec-ethz/debuglet/releases/tag/v0.1.0
