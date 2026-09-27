# Local environment checks

The compatibility checker runs an installed Debuglet package on Linux with a temporary dispatcher, executor, loopback TCP target, and `/api` proxy. It verifies the package identity, one TEST submission, guest output, terminal state, and cleanup. It has no remote-deployment mode.

## Manifest

Start with [configs/canary.json](../configs/canary.json). Set a canonical nonzero lowercase executor UUID and an operator label of 1–64 ASCII letters, digits, spaces, underscores, dots, or hyphens, beginning with a letter or digit.

Every illustrated key is required. Leave the API/control addresses and deployment record empty: the checker allocates its own listeners and reads daemon readiness records. The environment is `local`, target host is `127.0.0.1`, and control protection is `owned-loopback`.

The manifest must be a regular file of at most 64 KiB. Symlinks and nonregular files are rejected, as are duplicate, unknown, aliased, null, or missing fields, trailing JSON, and invalid UTF-8. Durations are integer milliseconds: execution is 1–15,000; the attempt is at most 180,000 and exceeds execution by at least 20,000. Ceiling bandwidth is 64,000–1,000,000 bits per second. Manifest fields do not accept credentials or daemon arguments.

## Run the checker

Install a checksum-verified package first; see [installation](../README-install.md). From the matching source checkout:

```sh
mkdir -p .ci .cache
go build -mod=readonly -o .ci/local-compatibility ./internal/acceptance/canary
.ci/local-compatibility \
  -manifest configs/canary.json \
  -installed-root "$HOME/.local/lib/debuglet/VERSION" \
  -archive-sha256 ARCHIVE_SHA256 \
  -evidence-dir "$PWD/.cache/local-check-result" \
  -dry-run
```

Replace `VERSION` and `ARCHIVE_SHA256` with the version and lowercase SHA-256 from the matching verified archive. The archive digest cannot be reconstructed from installed files. The checker separately verifies the installed payload hashes and metadata. The evidence directory must not already exist; its parent must exist.

Dry-run validates local inputs and prints JSON without starting services or creating evidence/state directories. After reviewing it, omit `-dry-run` to perform the local check. Use a new evidence directory for each run.

The checker writes `result.json` as a mode 0600 file in its private mode 0700 directory after execution and cleanup, and emits the same JSON. It never overwrites a result. Unobserved facts remain null; an uncertain submission is not retried. Recorded registry ineligibility after shutdown can result from disconnection and does not by itself prove lease expiration.

Exit codes: 0 for valid dry-run or complete success, 2 for invalid input, 1 for operational failure, 124 for deadline, and 130 for interruption.

## CI

`make ci-compatibility` installs and checks the package produced by `make ci-package`; `make ci-local` additionally checks the installed combined environment and the independent dispatcher, executor and client roles. The lanes, their outputs and what a pass covers are in [CI setup](ci.md).

## Related pages

- [Configuration reference](configuration.md): daemon configuration, transport security and stored state.
- [Managed services](services.md): `dbl service` and `dbl drain`.
- [Deployment inputs](../deploy/README.md): container images, the Ansible roles and their checks.
