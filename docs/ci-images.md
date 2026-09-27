# CI images

CI uses a pinned Go container for reproducible Linux amd64 builds. The exact image reference and package pins are in [`deploy/ci/images.env`](../deploy/ci/images.env) and [`deploy/ci/packages.txt`](../deploy/ci/packages.txt).

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
