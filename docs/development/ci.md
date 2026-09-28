# Continuous integration

GitHub Actions validates pull requests and `main` on fresh Linux amd64 runners. It builds, tests, packages, and runs Debuglet locally; it does not deploy any environment.

## Run the common checks

```sh
make ci-fmt
make ci-test
make ci-vet
make ci-build
make ci-package
```

Use `make ci-race` for concurrency changes. `make ci-local` exercises an installed package with local dispatcher and executor roles. `make ci-kernel` needs an isolated Linux host with the required kernel capabilities.

CI checks generated code, formatting, tests, race-sensitive code, package installation, local roles, and kernel integration. A passing workflow validates the checked revision on its test platform; it does not establish production readiness or remote deployment compatibility.

The workflow uses GitHub-hosted runners, read-only permissions, and no deployment secrets. See [CI images](ci-images.md) when changing the build environment.

Installed lanes share `scripts/ci-install-candidate.sh`: verify the exact archive
and installer checksums before installing, then verify the installed payload.
`tools/check-evidence.py` checks both named acceptance tests and race packages;
missing selections, malformed events and failed tests cannot pass as coverage.

## Security and offline checks

The secret lane scans proposed commits and the produced archives using pinned
Gitleaks. Reports contain rule, path and line only; match values are discarded.
Credential-negative fixtures need exact reviewed exceptions, never a directory-wide
exclusion. The scanner runs a harmless failing control and fails if execution or reports
are unavailable.

The offline lane installs and verifies the candidate, then executes its local demo
inside the pinned compiler-free runtime image with networking disabled. It checks
process and state cleanup before removing the container. The witness never pulls
an absent image; image preparation is a separate workflow step.

## Scheduled lifecycle checks

`Scheduled lifecycle checks` runs daily and can be dispatched manually. Three
iterations select the existing reconnect, restore, channel-partition, output,
DNS-policy and key-boundary fixtures. Each selected test must pass without skips.
The tests run with no external network, four CPUs, 4 GiB memory and 512 process
slots; module downloads finish before that boundary starts. JSON results, commands,
source identity and container cleanup evidence are retained for 30 days, including
failed iterations. These selections do not claim coverage of faults for which no
fixture exists, such as arbitrary machine crashes or disk exhaustion.
