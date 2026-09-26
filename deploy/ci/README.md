# CI runners

[The GitHub workflow](../../.github/workflows/ci.yml) runs eleven required lanes:
`fmt`, `vet`, `generate`, `build`, `test`, `race`, `package`, `demo`,
`compatibility`, `local` and `kernel`. The `required` check succeeds only if all
of them succeed. A pending, skipped or canceled lane is not a complete gate.

The workflow runs on pull requests to `main` and `dev`, pushes to `main` and
`dev`, and manual dispatches. Each job uses a fresh GitHub-hosted
`ubuntu-24.04` full virtual machine and checks out the event's exact commit
(the merge commit for a pull request). Do not replace this runner with
`ubuntu-slim`: the kernel lane needs a full VM with its own kernel boundary.

No runner registration, SSH access, custom labels or repository secrets are
needed. Workflow permissions are read-only, checkout does not persist its
credential, and pull requests use `pull_request`, not `pull_request_target`.
Requiring `CI / required` in branch protection is a recommended team setting;
branch protection is not a prerequisite for executing the checks. The workflow
does not publish releases or deploy services.

## Container boundary

`scripts/ci-github.sh` pulls the [pinned base image](../../docs/ci-images.md) and,
for `local` and `kernel`, builds the tools image from `deploy/ci/Dockerfile` on
that job's VM. It then launches a disposable Docker container for the lane.
GitHub job containers are not used. The child receives only the checkout, two
Go cache volumes, and an explicit allowlist of public build metadata. No Docker
socket, Actions token, runner installation, host home or deployment inventory
is passed into the child.

Ordinary lanes receive Docker's default capabilities. The kernel lane adds only
`BPF`, `NET_ADMIN`, `NET_RAW`, `PERFMON` and `SYS_RESOURCE`, with private process, mount and
network namespaces; it never uses `--privileged` or host networking. Its eBPF
attachments use loopback inside that network namespace. The Go volumes
`debuglet-ci-go-mod` and `debuglet-ci-go-build` last only for the job's VM. There
is no cross-job cache, so builds do not consume caches populated by another
pull request.

The build job uploads a tar containing the compiled output so Actions artifact
transport preserves executable modes. Package consumes those exact bytes once;
the three installed lanes download that run's same archive, installer and
checksums. Artifact names include the commit and producing run attempt.
Dependent jobs use the producer's recorded name, so retrying a failed lane can
reuse its successful upstream build without selecting unrelated artifacts.

## Kernel evidence

`kernel-isolation.py assert` enforces the following inside GitHub CI:

- The event and ref are supported by the workflow, the checkout matches the
  event's SHA, and a GitHub-hosted Linux X64 runner serves it.
- No credential-shaped environment variable, credential path, runner directory,
  deployment inventory or container socket is exposed. Names may be recorded;
  credential values are never recorded.
- The required kernel capabilities are present and capabilities that escape the
  boundary are absent; pid 1 is not the host init and forbidden mounts are absent.

`scripts/ci-kernel.sh` also snapshots processes and their BPF file descriptors
before and after tests. Missing snapshots or leaked processes/handles fail the
lane. `bpftool` inventories are supplementary: enumerating global BPF objects
requires `CAP_SYS_ADMIN`, which this lane does not hold. Both named kernel load
tests must pass and every skipped kernel test fails the lane. A workflow file
alone is not proof: inspect the actual run's kernel tests and isolation evidence.
The hosted VM's kernel is not pinned by our container image.

Outside GitHub CI the isolation script records its observations without failing,
so local reproduction remains possible. `DEBUGLET_CI_ISOLATION_ENFORCE=1` adds
enforcement; it cannot disable enforcement in CI. Without real platform metadata
that mode fails the platform checks. Local launcher runs reuse locally prepared
images; see [CI images](../../docs/ci-images.md).

Evidence lives in `.cache/ci/ci-image-evidence/` and lane-specific JSON/log files.
These checks inspect the job boundary. Kernel load results do not establish
production packet-policy enforcement or safety for untrusted deployed code.
