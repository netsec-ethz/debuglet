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

### Changed
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

## [0.1.0] - 2026-09-17

### Added
- Initial public release.

[Unreleased]: https://github.com/netsec-ethz/debuglet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/netsec-ethz/debuglet/releases/tag/v0.1.0
