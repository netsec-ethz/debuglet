# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until the next tagged release, `[Unreleased]` is the only section that changes.
Each entry names a user-visible change and its compatibility consequence: whether
the CLI, the control protocol between dispatcher and executor or the database
schema changed, and what an operator does with an existing state directory.
Entries promise nothing across commits, since only the current commit of the
integration branch is supported.

## [Unreleased]

### Added
- Add browser login with GitHub OAuth, including PKCE, short-lived login state,
  and deployment-specific credentials stored outside version control. This adds
  dispatcher database migration 00009; run `make deploy-upgrade-db
  DEPLOY_ENV=<env>` before the full deployment. The target builds and installs
  the candidate payload before it applies that payload's migration.
- `debuglet-dispatcher -upgrade-database`, `debuglet-executor -upgrade-database`
  and `deploy/ansible/upgrade-database.yml` bring a deployed database forward to
  the packaged schema, with a backup taken by the playbook. The upgrade is
  supported for wallet-free TEST state only; local state directories still
  require a new directory per package version.

### Changed
- `GET /debuglet/{id}/state` and `/logs` accept only the lowercase canonical
  run ID that submission returns, as the control protocol does, and reject a
  nil, uppercase, braced, `urn:uuid:` or unhyphenated `{id}` with 400
  `invalid_request`. `dbl status`, `logs` and `cancel` and the `pkg/client`
  methods refuse an uppercase ID before sending it; pass the ID as printed.
- `make deploy-update-config` and `make deploy-update-addr` render the version
  of the release installed on each host, read from its deployment record,
  instead of `git describe` of the operator's checkout and `unknown`
  respectively. `DEPLOY_VERSION` is no longer read, and an explicit
  `-e deploy_version` that names another release is refused. A host without a
  deployment record needs a full deployment first.
- `PUT /payment/intent` prices a run by its timeout in milliseconds, rounded up,
  instead of whole seconds truncated. Sub-second runs are no longer free, and a
  client that computes prices itself must use the new formula.
- `DELETE /debuglet` answers an executor's refusal 400 `cancel_refused` whatever
  its gRPC code, and an Abort that may not have reached the executor 500
  `internal_error` ("cancellation not confirmed").
- `dbl service status` exits 4 when the role is not ready, where it exited 0.
- Setting a destination limit below the floors already admitted is refused with
  409 `capacity_exhausted`.

### Fixed
- The executor refuses to start with a client certificate outside its validity
  window, naming `credentials.client_cert`, as the dispatcher already does for
  its own certificate. Before, it started and every control connection was
  rejected. Renew the certificate if the executor now refuses to start.
- The CLI's saved connections and credentials, local role records, readiness
  records, and managed-service configuration, unit, record and maintenance
  files are flushed to disk before they replace the previous file, so a crash
  cannot leave one empty or truncated. No format or location changes.
- `make bootstrap-sudo`, `make deploy-update-addr` and `make deploy-update-config`
  verify SSH host keys against the selected environment's file. With
  `DEPLOY_ENV=dev` they used the production `known_hosts`, and so refused dev
  hosts missing from it. No change for `DEPLOY_ENV=prod`.
- The executor removes a run's executor-wide bandwidth limit from its packet
  counter when the run ends. The eBPF counter's map holds 10,000 entries, so
  an executor process previously refused every run after about 10,000 runs.
  No configuration, protocol or schema change.
- The dispatcher and executor daemons enforce the schema's foreign keys and
  cascades, and wait up to one second for a database lock held by another
  process instead of failing at once. `PUT /payment/intent` now creates the
  transaction before the orders that reference it. The schema is unchanged;
  an existing database may be checked for rows written without enforcement
  with `PRAGMA foreign_key_check`.
- A refused resubmission of a batch whose orders already have runs no longer
  refunds its transaction.
- A datagram read into a buffer shorter than the datagram is charged for the
  whole datagram.

### Schema
- Dispatcher migration 00004 gained `DEFAULT` clauses after v0.1.0, so that a
  populated database at version 3 can be upgraded. A database already past
  version 4 is unaffected and keeps the columns without defaults.

### Known limitations
- SCION sockets cannot be marked, so their packets are not attributed to the
  run by the eBPF tagger. The executor logs a warning once when it dials SCION.

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
