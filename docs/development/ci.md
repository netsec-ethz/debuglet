# Continuous integration

GitHub Actions validates pull requests, `main`, and protected version-tag pushes on fresh Linux amd64 runners. It builds, tests, packages, and runs Debuglet locally; it does not deploy any environment.

Version-tag pushes run the same complete validation workflow. Release versions
require a valid `vMAJOR.MINOR.PATCH` tag (optionally a dotted prerelease suffix),
a GitHub tag protection rule or ruleset reported as protected, and the fetched
tag resolving to the workflow checkout. An unprotected or mismatched tag fails;
manual dispatch cannot substitute for a protected tag push. Repository
administrators must configure that protection before creating a release tag.
The package job retains the existing full and role-specific archives, installers,
checksums and compatibility metadata as CI artifacts. The workflow does not
create tags, publish a GitHub release or upload release assets.

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

The required vulnerability lane pins govulncheck and rejects known vulnerabilities
reachable from native package symbols. It retains the tool/database versions and
call paths. Findings limited to an uncalled module are informational. Any temporary
exception in `tools/vulnerability-exceptions.json` must name one advisory and
module, a review URL, a reason, and an expiry no more than 30 days away. Expired
exceptions fail. This gate currently covers Go dependencies, not container OS
packages.

The secret lane scans proposed commits, every tracked file at `HEAD`, and the
produced archives using pinned Gitleaks with its default rules. Reports contain
rule, path and line only; match values are discarded. The scanner runs a harmless
failing control and fails if execution or reports are unavailable.

Credential-negative fixtures need exact reviewed exceptions, never a directory-wide
exclusion. Exceptions live in the root `.gitleaksignore`, one Gitleaks fingerprint
per line: `path:rule-id:line`, or `commit:path:rule-id:line` for a single commit.
`tools/scan-secrets.py` rejects any other form (wildcards, directories, missing
rule or line) and refuses scans that bring their own `.gitleaks.toml`, a different
`.gitleaksignore`, or config overrides. Inline `gitleaks:allow` comments are
ignored, because they bypass review of this file.

To add an exception, confirm the value is a deliberate invalid fixture, take the
path, rule and line that the failing secret job prints, and add that line to
`.gitleaksignore` with a comment naming the fixture. When a fixture moves, replace
its entry rather than adding another, and remove the entry with the fixture. The
control proves an exempted finding is skipped while the same value on another
line, in another file or under another rule is still rejected.

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
