# Hosted workflow compilation

The dispatcher authenticates hosted Studio requests with the same account,
session and CSRF rules as the rest of the API. It forwards only the supported
catalog, validation and build operations to a local Unix socket. The separate
`dbl-studio worker` compiles WASI bundles; it never runs their output. Browser
requests use `/api/studio`, through the existing API proxy.
The proxy must allow a 4 MiB request body, a 32 MiB response and at least
370 seconds for a build response. The usual 60-second upstream read timeout
is too short for a cold experiment build.

The compiler is optional. An empty `[studio] socket_path` disables hosted
compilation. An unavailable worker produces a service-unavailable response;
existing saved bundles and ordinary dispatcher operations remain usable.
Local `dbl-studio serve` is still the local development mode.

## Build and verify a compiler bundle

Build on Linux amd64 from the exact clean committed source being deployed.
Use Go 1.26.9 and the existing pinned CI tools image from
`deploy/ci/images.env`; prepare the ordinary module cache before entering the
offline build boundary. The bundle builder refuses a dirty source tree,
another toolchain, missing cached dependencies or dynamically linked tools.

The following uses the existing CI caches and tools image. It downloads
nothing and requires a new output directory for each invocation:

```sh
. deploy/ci/images.env
docker run --rm --network none --pull=never \
  --mount "type=bind,source=$PWD,target=/workspace" \
  --mount type=volume,source=debuglet-ci-go-mod,target=/go/pkg/mod,readonly \
  --mount type=volume,source=debuglet-ci-go-build,target=/go/build-cache \
  --workdir /workspace --env GOMODCACHE=/go/pkg/mod \
  --env GOCACHE=/go/build-cache "$DEBUGLET_CI_TOOLS_IMAGE" \
  sh -ceu 'git config --global --add safe.directory /workspace
    python3 deploy/studio/package.py build --output .cache/ci/studio'
```

`studio-release.json` identifies the exact source, toolchain, archive size and
SHA256. The deterministic archive contains the static worker, matching guest
SDK source, required offline modules, Go toolchain, license notices and a
manifest of every file. The builder compiles a workflow and an experiment with
only those packaged inputs and a fresh build cache. It never executes guest
output. Rebuilding identical source and toolchain inputs produces identical
archive bytes; retain the tested archive for deployment.

There are two explicit artifact-verification paths:

- For an administrator-authorized source candidate, independently retain its
  exact source SHA and archive SHA256 from the reviewed build. Supply both to
  installation. A checksum read only from the downloaded bundle is not an
  independent check.
- For a signed compiler release, the approved release signer signs
  `studio-release.json` using OpenSSH namespace `debuglet-studio-release`.
  Verify against the existing independently provisioned public trust file and
  signer identity. Normal signing approval still applies. Packaging performs
  no signing, publication or change to the core release-signing workflow.

For example, verify an authorized exact candidate before installation:

```sh
python3 deploy/studio/install.py verify --directory .cache/ci/studio \
  --source "$REVIEWED_SOURCE_SHA" --archive-sha256 "$REVIEWED_ARCHIVE_SHA256"
```

For a signed bundle replace `--archive-sha256` with `--trust` and `--signer`;
keep `studio-release.json.sig` beside the subject and archive. Never supply
both trust paths. A rerun verifies the existing installation and refuses
modified files, extra files or links. It does not overwrite an existing
source directory.

## Install and enable

Use the normal pinned provisioner, inventory and SSH host verification
described in [the deployment guide](../../deploy/README.md). No compiler is
installed by ordinary dispatcher deployment. First install the matching
worker separately:

```sh
ansible-playbook -i hosts.yml -e @vars/prod.yml deploy-studio.yml \
  -e studio_release_directory=/verified/compiler-bundle \
  -e studio_source_sha="$REVIEWED_SOURCE_SHA" \
  -e studio_archive_sha256="$REVIEWED_ARCHIVE_SHA256"
```

For signed installation use `studio_trust_file` and `studio_signer` instead of
`studio_archive_sha256`. The playbook verifies locally before copying, then
verifies again on the target before installing to
`/opt/debuglet-studio/SOURCE_SHA`. It creates the dedicated `debuglet-studio`
account and socket group and installs `debuglet-studio.service`. The target
needs systemd, Python 3 and OpenSSH for the signed path; it installs no compiler
dependencies from the network.

Confirm the worker is healthy before enabling the dispatcher. Set these
inventory values and apply `update-config.yml --limit dispatcher`:

```yaml
dispatcher_studio_socket_path: /run/debuglet-studio/build.sock
dispatcher_studio_socket_group: debuglet-studio
```

The dispatcher unit gains only the compiler socket group. The worker does not
receive dispatcher credentials, session cookies or configuration. Keep the
existing public origin, OAuth registrations, providers, accounts, certificates
and data. Deploy the matching dispatcher/API version before the hosted console.
Existing database migrations remain a separate explicit operation.

## Resource and filesystem limits

The systemd unit starts inside the verified compiler bundle as its filesystem
root. It binds only its runtime socket directory and mounts private API
filesystems and a 512 MiB temporary filesystem for build work and cache.
Production configuration, databases, home directories and keys are absent.
The SDK, modules and compiler are read-only. No external network is available;
only Unix sockets are permitted. No capabilities or privilege escalation are
available to the worker.

Initial limits are one CPU, 1 GiB memory with no swap, 64 tasks, and 1,024 open
files. All compiler children share those limits. The worker also bounds input
and output, rejects excess concurrent work promptly, limits each participant
compilation to two minutes and limits the complete request to six minutes.
Service restart removes its runtime directory and private build/cache storage.
An out-of-memory kill or full temporary filesystem fails the build; retry only
after inspecting the cause. The operator may tune documented `studio_*`
resource variables for measured workloads.

Cold workflow and experiment builds must fit these settings on the deployment
host. A Docker rehearsal with matching resource limits checks compilation and
the bundle's minimal filesystem; it does not establish that the target's
systemd sandbox is active. Inspect the actual service properties, socket
ownership, compiler filesystem, network restriction and successful authenticated
build after installation. Use `systemd-analyze verify` before starting the unit.

## Recovery

Keep the previous bundle and unit configuration before switching source SHA.
To stop hosted builds, clear `dispatcher_studio_socket_path` and apply the
dispatcher configuration, then stop the worker. To restore a previous compiler,
deploy its independently verified bundle and select its exact source SHA;
use the matching dispatcher and console interfaces. Compiler rollback changes
no account or experiment data and is separate from database rollback.

Inspect `journalctl -u debuglet-studio` and the dispatcher logs for failures.
The unit restarts after worker failure and retains no build artifacts. Do not
delete a socket owned by a running service; stop the service so systemd removes
its runtime directory before restarting it. An archive alone does not prove
production acceptance: verify sign-in, catalog, validation, cancellation,
workflow/experiment build and ordinary run/share/re-run through the browser.
