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
Use Go 1.26.10 and the existing pinned CI tools image from
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
build after installation. Before starting the unit, run
`systemd-analyze --root <tree> --recursive-errors=no --man=no verify debuglet-studio.service`
against a temporary tree containing the exact unit under `etc/systemd/system`
and the packaged `bin/dbl-studio`.
The analyzer's executable lookup does not automatically follow the unit's
`RootDirectory`; this offline check does not replace checking the actual service.

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

## Optional experiment assistant

The assistant runs in the dispatcher and uses an operator-selected Chat
Completions endpoint with function calling, including OpenAI and compatible
providers such as GLM. The current adapter does not support the Responses API.
The compiler sandbox remains offline. The assistant proposes editable source;
custom Go is checked with the same hosted compiler before the proposal is returned.
The normal build and submission actions remain separate. No provider is
selected or enabled by default. Verify the endpoint and model supplied for your
provider account before enabling it.

For `api.openai.com`, complete proposals use a compact format and one required
function call. Each block carries typed input bindings and explicit control
successors; the server expands these into the ordinary editor's data and control
wires. Built-in names and input schemas come from the current catalog. Custom
nodes explicitly reference their workflow's typed definitions and visible Go
bodies. Arbitrary JSON literals and custom port defaults use encoded JSON strings.
Small edits retain the existing atomic node-and-edge operations. Neither format
changes saved experiments or executor behavior. Other compatible endpoints retain
the ordinary document tool format. Strict output
constrains the shape; it does not establish correct wiring or measurement
semantics. Every proposed graph passes validation and Go source generation,
including every participant in a coordinated experiment. Assistant proposals also
reject newly disconnected actions while preserving unrelated unfinished draft
blocks. This does not prove that the proposal fulfills the request. They
check whether action outputs are available along supported control paths, stopping
at loop boundaries; loop bodies, continuations and custom conditions still need review. For proposals containing
custom blocks or explicitly accepted Go functions, actual compilation errors also
feed the one correction attempt. Visual proposals are limited to ten immediate
cards at each level using nested groups; this affects presentation, not execution.
The compiler shares the normal per-account/global capacity limits, and a busy or
unavailable compiler leaves the draft unchanged. Built-in-only drafts do not
need the compiler at this stage. Compilation proves neither runtime success nor
network reachability. The check does not retain a bundle, so Build compiles the
accepted source again. A rejected graph gets at most one correction
within the same three-minute deadline; truncated output is rejected without another
provider call. For small changes, the model can return only changed nodes and
connections. The dispatcher applies these edits to the supplied snapshot and
validates the complete result before returning ordinary editor JSON. Structural
errors in full proposals request a complete corrected compact document. Scoped
edits and custom-code compilation failures can correct the rejected proposal
without generating the entire graph again.
Edits can replace experiment channels and update their sending/receiving nodes
atomically, including when correcting channel identifiers or directions.
Participant membership and visual group structure still use complete document
proposals. See [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling).

The assistant uses catalog defaults for optional settings and explains choices
such as a single IPv4 address and TCP port 443 for an unspecified web connection.
It still asks when a target or essential requirement is missing. Review the
proposed source before applying it. Provider authentication, rate limits,
truncation, invalid graphs and cancellation have distinct safe error reasons;
provider response bodies are never included in errors.

Provision a provider key in a regular file readable only by its owner and,
optionally, the dispatcher's group (mode `0600` or `0640`). Do not place the key
in the repository, console configuration or inventory. For OpenAI GPT-6 Sol:

```toml
[studio.assistant]
enabled = true
endpoint = "https://api.openai.com/v1/responses"
model = "gpt-6-sol"
api_key_file = "/etc/debuglet/assistant.key"
reasoning_effort = "high"
```

The `/v1/responses` endpoint selects the Responses API with strict function
calling and `store: false`. It supports reasoning with tools; higher reasoning
effort can take several minutes within the shared three-minute request deadline. Other endpoint paths retain the Chat Completions protocol
for compatible providers. GPT-6 Sol requires `reasoning_effort = "none"` when
using `/v1/chat/completions`. See the
[OpenAI model documentation](https://developers.openai.com/api/docs/models/gpt-6-sol).

If `api_key_file` is omitted, the dispatcher reads `DEBUGLET_ASSISTANT_API_KEY`
from its environment. The key file takes precedence. The enabled dispatcher
refuses missing or malformed credentials at startup. HTTPS is required by default,
except for literal loopback HTTP addresses used by local providers. For a trusted
HTTP-only model gateway, an operator can explicitly set `allow_insecure_http = true`
in `[studio.assistant]`. This sends the API key, prompts and experiment source
unencrypted on the dispatcher-to-provider connection; use it only on a network
you trust. It does not disable HTTPS certificate verification or permit redirects.
Credentials in URLs, query strings and fragments remain refused.

For models that support it, `reasoning_effort` accepts `none`, `low`, `high` or
`max`. An omitted or empty value leaves the provider default unchanged; it does
not select `none`. For interactive GLM-5.3-Flash authoring, use
`reasoning_effort = "low"` to keep reasoning within
the request deadline. This controls reasoning depth rather than disabling it.
Provider `reasoning_content` or opaque Responses reasoning items, when present,
are retained only for the single validation-repair call; they are not returned
to the browser or logged. Responses reasoning items are requested in encrypted
form and replayed with the tool result, without relying on stored response IDs.
The Responses connection streams real acceptance and function-output activity.
Only the provider's optional public reasoning summaries are shown in the editor;
raw and encrypted reasoning stay private. No partial proposal is applied.

The Ansible equivalents are `dispatcher_assistant_enabled`,
`dispatcher_assistant_endpoint`, `dispatcher_assistant_model` and
`dispatcher_assistant_api_key_file`; the optional HTTP exception is
`dispatcher_assistant_allow_insecure_http` (default `false`), and the reasoning setting
is `dispatcher_assistant_reasoning_effort` (default empty). Provision the private key file separately,
then apply the normal configuration update and restart the dispatcher. The
ordinary disabled deployment requires no key or additional service. Configure
the reverse proxy for at least 210 seconds on `/api/studio/assistant` and
`/api/studio/assistant/stream` to allow
the backend's three-minute deadline and response delivery.

The model receives the graph, including any custom source, the prompt and the
conversation history explicitly included by the client. It receives no session
cookies, account credentials or unrelated stored experiments. Review the
provider's data-handling policy before enabling this for users. Prompt contents
and upstream error bodies are not logged by the assistant.

The API bounds input, output, time and concurrency and limits the shared provider
to six user requests per minute with a burst of four. Each may make two provider
calls. Calls to `api.openai.com` use `max_completion_tokens = 16384`, which counts
visible output and any reasoning tokens; other endpoints use `max_tokens = 16384`.
See the [OpenAI Chat Completions reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).
These are resource limits, not a monetary budget: configure a hard spending
limit and alerts on the provider
account before enabling a shared key. Existing dispatcher account request limits
also apply. The assistant never initiates measurement spending.

Verify authenticated availability, one clarification and one proposed graph with
the actual provider, then validate/build that graph through the existing compiler.
A fake-provider test establishes the local contract only; it does not establish
compatibility with an unconfigured provider account. Set `enabled = false` and
restart to disable assistance without changing ordinary editing or compilation.
