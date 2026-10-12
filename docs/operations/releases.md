# Signed releases and offline verification

Release signatures authenticate the installer and archive before either runs.
Checksums detect changed bytes but do not identify a trusted publisher. The
signature also binds the complete release inventory, provenance, build inputs,
gate results and notices to one version and source revision.

This workflow requires administrator setup and an approved signing run before
its first signed release. A version tag and successful tag CI are not a published
release: confirm the downloadable assets on the release page. Existing
v0.2.0 assets are unsigned; the existing installation command continues to check hashes and
prints an unsigned-installation warning. Signature verification is enabled when
trust settings or `DEBUGLET_REQUIRE_SIGNATURE=1` are supplied. It never falls
back to unsigned installation after a verification failure. Preparing a signed Actions artifact does not publish a GitHub release or
provide durable retention.

## Production signer

The configured key for signing releases after v0.2.0 is:

| Field | Value |
| --- | --- |
| Identity | `releases@debuglet.netsec.ethz.ch` |
| Namespace | `debuglet-release` |
| Key | Ed25519, fingerprint `SHA256:vETQG+wE6uwMv4MBFfx7dxo8IWpvR8z6/Sw7MT2WwQo` |
| Trust file | [`configs/release-allowed-signers`](../../configs/release-allowed-signers) |

Use the trust file from a checkout you obtained independently of the release,
and confirm the fingerprint through a second channel, such as the Debuglet
website or the maintainers, before relying on it:

```sh
awk '{print $3, $4}' configs/release-allowed-signers | ssh-keygen -lf -
```

Install it with `install -m 0644 configs/release-allowed-signers
/etc/debuglet/release-allowed-signers` and use
`DEBUGLET_RELEASE_SIGNER=releases@debuglet.netsec.ethz.ch` in the commands
below. A rotation changes this file and this section in a reviewed commit, as
described in [Rotate a signer](#rotate-a-signer).

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

## Check an installed candidate

Use a clean Linux amd64 checkout with the pinned toolchain. Build once, then
run the installed acceptance checks against those package bytes:

```sh
make ci-build ci-package
make ci-demo ci-compatibility ci-local
```

The ordinary CI workflow also runs the compiler-free, network-disabled demo,
kernel, vulnerability and remaining required lanes. A local reproduction does
not replace that exact-source CI run. The installed checks establish:

| Check | Evidence |
| --- | --- |
| Full and component installation, identical rerun, installed version/source | `package-install.log`, `package-install.json`, `package-install-{cli,executor,dispatcher}.json` |
| Account-owned enrollment through the installed `dbl executor join`, TLS registration, completed hello, both daemon restarts, retained identity/session/output and fresh work | `role-tests.json`: `TestInstalledEnrollment` |
| Published v0.2.0 executor compatibility and a populated v0.2.0 upgrade, old-binary downgrade refusal and restoration of the saved old state | `role-tests.json`: `TestInstalledReleasedCompatibility`, `TestInstalledReleasedUpgrade` |
| Explicit backup/restore, graceful and terminated interrupted-work recovery, retained output without automatic replay | `role-tests.json`: `TestInstalledBackupRestore`, `TestInstalledRecovery`, `TestInstalledOutput` |

These are owned Linux fixtures. The enrolled-node check runs foreground daemons;
it does not establish a real systemd deployment, external provider login, ETH
connectivity or an independently operated node. Rehearse the
[managed-service procedure](services.md) on the intended authorized host before
claiming that service profile. The previous-release upgrade check uses the
published unsigned v0.2.0 bytes pinned by checksum; it is not a signed rollback
release in the private archive.

## Prepare a release

An administrator must protect the intended semantic-version tags and create the
`release-signing` environment with required independent reviewers and
`prevent_self_review` enabled. Store `RELEASE_SIGNING_KEY` only as an environment
secret, never as a repository or organization fallback secret. Provision the
matching public trust material to operators separately. Ordinary CI and kernel
jobs must not receive that secret.

Select the final reviewed source and a new version only after integration is
complete. A previously validated tag at a different commit cannot cover later
fixes. Keep development archives under their generated development versions;
renaming one to a release version does not establish the protected-tag build.

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

## Publish installation assets

Publication is a separate operator action after the complete signed bundle has
passed the audit above. Attach the original files from that bundle to the
release for the same protected tag, with release notes describing supported
platforms, compatibility, migration/restore instructions and remaining limits.
Do not rebuild, rename, replace or re-sign the prepared files during publication.

The installation asset set is:

- Full bundle: `debuglet-VERSION-linux-amd64.tar.gz`, `install.sh`, `SHA256SUMS`.
- Each of `cli`, `executor` and `dispatcher`:
  `debuglet-COMPONENT-VERSION-linux-amd64.tar.gz`, `install-COMPONENT.sh`,
  `SHA256SUMS-COMPONENT`.
- `compatibility.json`, `SHA256SUMS-compatibility`, `release.json` and
  `release.json.sig`.

That is sixteen files, with `VERSION` and `COMPONENT` replaced by their exact
values. The complete signed bundle additionally contains inventory, provenance,
notices and acceptance evidence; retain it in the approved private archive
below. Publishing the installation subset does not satisfy complete retention.

Download each component's files again from the published release and use the
trusted bootstrap with `DEBUGLET_REQUIRE_SIGNATURE=1` and independently
provisioned trust. Verify the version/source and each component's documented
smoke command; run `dbl demo` with the full bundle on a clean supported host
without a compiler or source checkout. Keep the downloaded digests, signer,
source and results. A successful local install before publication does not
establish that the published download works.

Before an external pilot, separately agree the reporting contact and incident
evidence-access policy in [abuse response](abuse-response.md), and obtain the
named release, host, operator, destinations and restore authorization in
[external pilot](external-pilot.md). Local registration/restart success does not
confirm resolution of a previously affected remote registration incident; the
affected operator must record that topology's registration and recovery result.


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
