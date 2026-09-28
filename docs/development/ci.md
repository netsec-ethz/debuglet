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
