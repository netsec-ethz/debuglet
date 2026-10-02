# CI images

CI uses a pinned Go container for reproducible Linux amd64 builds. The exact image reference and package pins are in [`deploy/ci/images.env`](../../deploy/ci/images.env) and [`deploy/ci/packages.txt`](../../deploy/ci/packages.txt).

Most checks run in the pinned `golang` image. The local-role and kernel checks use the `debuglet-ci-tools` image built from the same base image. GitHub Actions builds the tools image on its disposable runner; it is not a published project artifact.

## Reproduce locally

On a suitable Linux host:

```sh
. deploy/ci/images.env
docker pull "$DEBUGLET_CI_BASE_IMAGE@$DEBUGLET_CI_BASE_DIGEST"
docker build -t "$DEBUGLET_CI_TOOLS_IMAGE" -f deploy/ci/Dockerfile deploy/ci
bash scripts/ci-github.sh local
```

Use the regular `make ci-*` commands for normal development. Update the pinned image, Debian snapshot, packages, and assertions together in one pull request, then run the full workflow.

## Runtime image vulnerability checks

The `image-vulnerabilities` lane builds the full, CLI, dispatcher and executor
targets from the candidate's clean source revision. It saves each image, then
scans those archives in the ordinary CI container without a Docker socket.
Grype 0.119.0 is downloaded from its official release and verified against a
pinned SHA-256. Each run requires a valid database no more than five days old.
Scanner failures, unavailable databases, malformed reports and wrong image
identities fail the lane. A known vulnerable package identifier checks the
scanner and policy without fetching or running vulnerable code.

Reports include all severities, package versions and locations, vendor advisory
links and fix status. Unexcepted High/Critical matches fail, including findings
without an available vendor fix. These are image-inventory findings; the
separate Go vulnerability lane checks reachable application symbols.

The uploaded `.cache/ci/image-vulnerabilities` evidence records source and image
identities, archive checksums, scanner/database identity and the reports. Each
scan JSON is capped at 32 MiB; a truncated report fails. CI keeps this evidence
for 14 days and uploads no image archives, deployment secrets or credentials.

Prefer upgrading the affected runtime package or base image. Any temporary
exception in [`tools/image-vulnerability-exceptions.json`](../../tools/image-vulnerability-exceptions.json)
must name the exact role, advisory and versioned package URL, an HTTPS review,
a concrete reason and an expiry within 30 days. The default list is empty;
wildcards and expired exceptions do not pass.
