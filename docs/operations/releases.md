# Signed releases and offline verification

Release signatures authenticate the installer and archive before either runs.
Checksums detect changed bytes but do not identify a trusted publisher. The
signature also binds the complete release inventory, provenance, build inputs,
gate results and notices to one version and source revision.

This workflow requires administrator setup before its first release. Existing
v0.2.0 assets are unsigned; the existing installation command continues to check hashes and
prints an unsigned-installation warning. Signature verification is enabled when
trust settings or `DEBUGLET_REQUIRE_SIGNATURE=1` are supplied. It never falls
back to unsigned installation after a verification failure. Preparing a signed Actions artifact does not publish a GitHub release or
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
export DEBUGLET_REQUIRE_SIGNATURE=1
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

Until signing is provisioned, an invocation without trust settings preserves
the existing checksum-only installation policy. To make that choice explicit
for an unsigned package such as v0.2.0:

```sh
unset DEBUGLET_RELEASE_TRUST DEBUGLET_RELEASE_SIGNER DEBUGLET_RELEASE_DIR DEBUGLET_REQUIRE_SIGNATURE
DEBUGLET_VERSION=v0.2.0 DEBUGLET_ALLOW_UNSIGNED=1 sh scripts/bootstrap.sh
```

This prints an unsigned-installation warning and checks the downloaded hashes.
It does not authenticate a release signer. Local development packages can use
`DEBUGLET_RELEASE_DIR` with the same explicit opt-in. Unsigned mode rejects
configured trust settings or a signature requirement rather than ignoring them.
Set `DEBUGLET_REQUIRE_SIGNATURE=1` in managed installation environments to refuse
installation when trust has not yet been provisioned.

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
`debuglet-release` namespace. The signed bundle includes the original acceptance-evidence ZIPs and their
exact-run/attempt index. Missing or expired required evidence prevents preparation;
job links alone are insufficient. Download the resulting signed artifact before
its 90-day Actions retention expires, then use the explicit retention procedure
below. The signing workflow never publishes or prunes releases.

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


## Retain a complete release

Designate a private GitHub repository for complete bundles. The public product
repository is not a private archive. An administrator must enable immutable
Releases, create the intended version tag in the archive, and grant the publisher
Contents write and Administration read access (the latter checks immutability).
The archive's tag identifies its catalog commit; the signed manifest identifies
the separate product source commit. Provision signing trust independently as
above. Authenticate `gh` for github.com without putting credentials in URLs.

From a trusted checkout, explicitly promote a downloaded signed bundle:

```sh
umask 077
python3 tools/release.py promote --repository "$DEBUGLET_RELEASE_ARCHIVE" \
  --directory /path/to/release --version "$DEBUGLET_VERSION" \
  --trust "$DEBUGLET_RELEASE_TRUST" --signer "$DEBUGLET_RELEASE_SIGNER"
```

Promotion verifies every signed subject before creating a draft, uploads without
replacing assets, downloads and verifies the complete draft, then publishes it
and confirms its immutable asset identities. Existing exact immutable bundles
are verified without writes. An existing draft, mutable release or conflicting
bundle refuses; inspect an interrupted draft manually. A failure after publishing
can leave a retained release requiring inspection, but never changes which
versions are designated supported. No package is rebuilt or executed.

Retain promoted releases indefinitely. There is no release-deletion or pruning
command; failed/unpromoted CI evidence continues to expire after fourteen days.
Repository administrators can still delete entire releases or the archive, so
restrict that authority. Immutability does not replace administrative retention
policy or an independent backup.

After both versions are archived and verified, review a `retention.json` change
on the archive's protected default branch. The policy has `schema_version: 1`
and distinct `current` and `rollback` objects, each containing `version`,
`source_sha` and `manifest_sha256` from the verified promotion result. Promotion
never edits these pointers or GitHub's latest-release designation. A rollback
package still requires a compatible state backup and the documented restore
procedure; retaining bytes does not establish schema downgrade compatibility.

Audit the exact reviewed policy commit using a read-authorized identity:

```sh
umask 077
python3 tools/release.py retention-audit --repository "$DEBUGLET_RELEASE_ARCHIVE" \
  --policy-revision "$DEBUGLET_RETENTION_POLICY_REVISION" \
  --trust "$DEBUGLET_RELEASE_TRUST" --signer "$DEBUGLET_RELEASE_SIGNER" \
  > retention-audit.json
```

The policy revision must be the current protected default-branch commit. The
private JSON report lists each pinned source, release ID, verified file digests
and missing or invalid items; any gap exits nonzero. The tool checks that the
policy did not change during the audit. Release credentials and raw GitHub error
responses are not included. For installation from this private archive, use
`gh release download` with explicit repository and version, then pass the
verified download directory through `DEBUGLET_RELEASE_DIR`.

Local tests of this procedure do not prove that a real archive is provisioned.
Before relying on it, publish an authorized complete bundle, confirm authenticated
download and independent verification, and verify unauthenticated access is
refused. Repeat the download after the source Actions artifacts expire. Keep
this actual-channel evidence separately from local fixture results.
