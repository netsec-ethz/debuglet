# CI images

Every lane in [the GitHub workflow](../.github/workflows/ci.yml) runs in a
pinned container image through `scripts/ci-github.sh`, on a fresh GitHub-hosted
`ubuntu-24.04` full VM. Compiler and package inputs are pinned; the VM's host
kernel is not. The workflow does not use `ubuntu-slim`.

| Lane | Image |
| --- | --- |
| `fmt`, `vet`, `generate`, `build`, `test`, `race`, `package`, `demo`, `compatibility` | `golang:1.25.11-bookworm` at a fixed manifest digest |
| `kernel`, `local` | `debuglet-ci-tools`, built from that same digest |

The launcher reads [deploy/ci/images.env](../deploy/ci/images.env). In GitHub
Actions it pulls the base by digest and builds the tools image from the
checked-out Dockerfile when needed. The child uses `--pull=never` and receives
the selected reference and inspected image ID. `verify-image.sh` checks that
reference, toolchain and package pins before the lane runs. The workflow does
not repeat image references.

## Pinned inputs

`debuglet-ci-tools` is built on the job's VM; it is not downloaded from a
registry. Its inputs are pinned instead:

- the base image by manifest digest;
- the Debian archive by the snapshot timestamp the base image was built from,
  so `apt` resolves a frozen package index;
- every added package by exact version, in
  [deploy/ci/packages.txt](../deploy/ci/packages.txt).

A pinned version the snapshot no longer offers fails the image build rather
than resolving to a different one. The image records installed versions and
the SHA-256 of the normalised pin list. `verify-image.sh` recomputes that digest
from the checkout and re-reads each installed package version. No lane installs
extra distribution packages after image preparation.

Image preparation needs network access to the base registry and
`snapshot.debian.org`. Other job steps may also download Go modules or pinned
generator tools. The named Go cache volumes are local to the disposable VM;
there is no cross-job image or Go cache.

## Local reproduction

Outside GitHub Actions the launcher reuses prepared local images. From the
revision carrying the pins, prepare them before invoking a lane:

```sh
. deploy/ci/images.env
docker pull "$DEBUGLET_CI_BASE_IMAGE@$DEBUGLET_CI_BASE_DIGEST"
docker build -t "$DEBUGLET_CI_TOOLS_IMAGE" -f deploy/ci/Dockerfile deploy/ci
docker image inspect "$DEBUGLET_CI_TOOLS_IMAGE" --format '{{.Id}}'
bash scripts/ci-github.sh local
```

The Dockerfile's build arguments default to the values in `images.env`; update
them together. Kernel reproduction requires a suitable isolated Linux host and
the capabilities described in [CI runners](../deploy/ci/README.md).

## Evidence

Every lane retains `.cache/ci/ci-image-evidence/<profile>-image.json` as an
artifact (`base`, `kernel` or `local`). It records the expected and actual image
references, inspected image ID, run, job, commit and runner, compiler and tool
versions, and the pinned package versions present in the image.

The kernel lane also regenerates the eBPF objects with the image's compiler
and reports whether they reproduce the committed bytes, in
`.cache/ci/ebpf-objects-{before,after}.sha256` and
`.cache/ci/ci-image-evidence/ebpf-objects-reproduced.txt`. Actual kernel load tests
must run without skips; image verification alone does not establish that they
passed on the hosted kernel.

## Update an image

1. In one pull request, change the package pins, image references and snapshot
   in `deploy/ci/packages.txt` and `deploy/ci/images.env`, the matching `ARG`
   defaults in `deploy/ci/Dockerfile`, and affected version assertions. Give the
   tools image a new tag.
2. Run the full workflow on that revision. The `local` and `kernel` jobs build
   the new image themselves; all ordinary, generated-code and installed checks
   remain required.
3. If regeneration changes the committed eBPF objects, include the regenerated
   objects and their kernel load results in the same pull request, or keep the
   previous image.

Pinning reproduces package versions and compiler inputs, not a bit-identical
image or host kernel. The tools image's local tag and recorded pin digest do not
protect against a compromised VM or image builder.
