# Signed releases and offline verification

Release signatures authenticate the installer and archive before either runs.
Checksums detect changed bytes but do not identify a trusted publisher. The
signature also binds the complete release inventory, provenance, build inputs,
gate results and notices to one version and source revision.

This workflow requires administrator setup before its first release. Existing
v0.2.0 assets are unsigned; they remain usable through the explicit legacy mode
below. Preparing a signed Actions artifact does not publish a GitHub release or
provide durable retention.

## Install with provisioned trust

Use Linux amd64 with a POSIX shell, GNU tar, coreutils, Python 3.11 or later, and
OpenSSH with `ssh-keygen -Y` support. Online installation also requires curl.
Obtain the bootstrap script from a trusted checkout and the release signer's
public key and identity through your administrator's authenticated channel.
Confirm the key fingerprint with that administrator; do not download a trust
file beside the release and accept it as its own proof.

The administrator-provided OpenSSH `allowed_signers` file contains a line like
this, with the actual signer identity and public key in place of the examples:

```text
releases@example.org namespaces="debuglet-release" ssh-ed25519 AAAA...public-key...
```

Set the exact published version, trust file and identity, then run the trusted
bootstrap from the checkout:

```sh
export DEBUGLET_VERSION=v1.2.3
export DEBUGLET_RELEASE_TRUST=/etc/debuglet/release-allowed-signers
export DEBUGLET_RELEASE_SIGNER=releases@example.org
export DEBUGLET_PREFIX="$HOME/.local"
sh scripts/bootstrap.sh
```

The version and identity above are examples, not a configured production signer.
Leave `DEBUGLET_COMPONENT` unset for the full bundle, or set it to `cli`,
`executor` or `dispatcher`. The bootstrap reports the verified signer, version
and source revision. Missing or invalid signatures fail before installer
execution; they never trigger an unsigned fallback.

For an offline install, copy `release.json`, `release.json.sig`, and the selected
archive, installer and checksum file into a local directory, then set
`DEBUGLET_RELEASE_DIR` to its absolute path. Keep the trust file separate. The
same command and signature checks run without downloading assets.

## Rotate a signer

Distribute the replacement public key and confirm its fingerprint through the
same independent channel. During an agreed transition, an `allowed_signers`
file may contain both keys for the same identity and `debuglet-release`
namespace. Remove the old key when its authority ends. A release signed only by
that old key then fails verification, including an old rollback package; retain
an explicitly approved trust file for rollback if your policy requires it.

For a compromised signer, remove its key immediately rather than retaining an
overlap. Never change verification to unsigned mode to bypass a bad signature.

## Explicit unsigned legacy or development install

For an unsigned package such as v0.2.0, unset both trust settings and opt in:

```sh
unset DEBUGLET_RELEASE_TRUST DEBUGLET_RELEASE_SIGNER DEBUGLET_RELEASE_DIR
DEBUGLET_VERSION=v0.2.0 DEBUGLET_ALLOW_UNSIGNED=1 sh scripts/bootstrap.sh
```

This prints an unsigned-installation warning and checks the downloaded hashes.
It does not authenticate a release signer. Local development packages can use
`DEBUGLET_RELEASE_DIR` with the same explicit opt-in. Unsigned mode rejects
configured trust settings rather than silently ignoring them.

## Prepare a release

An administrator must protect the intended semantic-version tags and create the
`release-signing` environment with required independent reviewers and
`prevent_self_review` enabled. Store `RELEASE_SIGNING_KEY` only as an environment
secret, never as a repository or organization fallback secret. Provision the
matching public trust material to operators separately. Ordinary CI and kernel
jobs must not receive that secret.

Run the ordinary CI workflow for the protected version tag. Every required lane
must succeed for that exact source, version and run attempt, including the
vulnerability gate. Then manually dispatch **Prepare signed release** on that
same tag and supply its completed CI run ID. Preparation checks the existing
environment protection and exact gate results, and uses the already-built
packages; it neither rebuilds nor executes their payloads.

After environment approval, a separate signing job receives only the prepared
files. It checks out no source and signs `release.json` with the OpenSSH
`debuglet-release` namespace. Download the resulting signed artifact before its
90-day Actions retention expires. There is no automated release publication or
pruning in this workflow; archive the complete bundle through your approved
release-storage procedure and retain an approved rollback version.

To independently audit a complete downloaded bundle using a trusted checkout:

```sh
python3 tools/release.py audit --directory /path/to/release \
  --version "$DEBUGLET_VERSION" \
  --trust "$DEBUGLET_RELEASE_TRUST" --signer "$DEBUGLET_RELEASE_SIGNER"
```

Optional `--source` and `--builder` arguments pin the expected commit and GitHub
CI run URL. The audit verifies all signed subjects and reconstructs the SBOM and
provenance bindings without executing the payload. It reports source, builder,
signer and file count. Its `published: false` result means local verification
does not establish durable publication, access control or retention.

The bootstrap verifies only the selected component's signed installation files;
use the audit for the complete bundle. The SBOM records native Go module build
information and same-source offline WASI dependency graphs. Runtime base-image
pins are not a complete operating-system package inventory, and recorded BPF
regeneration tools do not prove how inherited BPF objects were originally built.
