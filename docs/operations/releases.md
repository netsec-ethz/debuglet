# Signed releases and offline verification

For installation, start with [Install Debuglet](../../README-install.md). This
page covers release trust, publication and retention for operators.

A signature authenticates the installer, packages and release metadata before
execution. Checksums alone detect changed bytes. A tag or signed Actions artifact
is not a published release: check the assets on the exact GitHub release page.
The existing v0.2.0 assets are unsigned.

## Production signer

| Field | Value |
| --- | --- |
| Identity | `releases@debuglet.netsec.ethz.ch` |
| Namespace | `debuglet-release` |
| Ed25519 fingerprint | `SHA256:vETQG+wE6uwMv4MBFfx7dxo8IWpvR8z6/Sw7MT2WwQo` |
| Trust file | [`configs/release-allowed-signers`](../../configs/release-allowed-signers) |

Obtain the trust file independently of the release download and confirm its
fingerprint through an authenticated second channel, such as the maintainers.
A key served beside an archive is not independent proof of its publisher.

```sh
awk '{print $3, $4}' configs/release-allowed-signers | ssh-keygen -lf -
sudo install -d -m 0755 /etc/debuglet
sudo install -m 0644 configs/release-allowed-signers /etc/debuglet/release-allowed-signers
```

The apt repository uses a separate OpenPGP key; see [apt setup](apt-repository.md).

## Install with provisioned trust

Use Linux amd64, a POSIX shell, GNU tar, coreutils, Python 3.11+ and OpenSSH with
`ssh-keygen -Y`. Online installation also needs curl. Obtain `bootstrap.sh`
from a trusted checkout, then select an exact published version:

```sh
export DEBUGLET_VERSION=VERSION_PROVIDED_BY_OPERATOR
export DEBUGLET_REQUIRE_SIGNATURE=1
export DEBUGLET_RELEASE_TRUST=/etc/debuglet/release-allowed-signers
export DEBUGLET_RELEASE_SIGNER=releases@debuglet.netsec.ethz.ch
export DEBUGLET_PREFIX="$HOME/.local"
sh scripts/bootstrap.sh
```

Leave `DEBUGLET_COMPONENT` unset for the full bundle, or select `cli`, `executor`
or `dispatcher`. Missing or invalid signatures fail before installer execution;
there is no unsigned fallback. The bootstrap reports the verified signer,
version and source.

For offline installation, copy `release.json`, `release.json.sig` and the chosen
archive, installer and checksum file into a directory, and set
`DEBUGLET_RELEASE_DIR` to its absolute path. Keep the independently provisioned
trust file separate. Verification is otherwise unchanged.

## Rotate a signer

Distribute a new public key through the same independent channel. A reviewed
`allowed_signers` file may temporarily contain both keys for the same identity
and namespace. Remove the old key when its authority ends. An old rollback
package then needs an explicitly retained, approved trust file.

For a compromised signer, remove its key immediately. Do not bypass signature
verification to keep installations working. Update the repository trust file
and documented fingerprint together in a reviewed change.

## Explicit unsigned legacy or development install

For the older v0.2.0 demo, explicitly accept checksum-only installation:

```sh
unset DEBUGLET_RELEASE_TRUST DEBUGLET_RELEASE_SIGNER DEBUGLET_RELEASE_DIR DEBUGLET_REQUIRE_SIGNATURE DEBUGLET_COMPONENT
DEBUGLET_VERSION=v0.2.0 DEBUGLET_ALLOW_UNSIGNED=1 sh scripts/bootstrap.sh
```

This warns that the installation is unsigned. Local development candidates also
need `DEBUGLET_RELEASE_DIR` and their exact development version. Unsigned mode
cannot override configured trust or `DEBUGLET_REQUIRE_SIGNATURE=1`.

## Check an installed candidate

Build and test on Linux amd64 using the pinned toolchain:

```sh
make ci-build ci-package
# Ubuntu 24.04 amd64 Docker host:
make ci-debian
make ci-demo ci-compatibility ci-local
```

| Check | Main evidence |
| --- | --- |
| Signed apt metadata, package lifecycle and tamper rejection using disposable keys | `debian-prepare.jsonl`, `debian-check.jsonl`, `debian-image.txt` |
| Full/component installation and exact version/source | `package-install.log`, `package-install*.json` |
| Enrollment, restart and retained identity/output | `role-tests.json`: `TestInstalledEnrollment` |
| Published v0.2.0 compatibility, populated upgrade and old-state restoration | `TestInstalledReleasedCompatibility`, `TestInstalledReleasedUpgrade` |
| Backup/restore and interrupted-work recovery without replay | `TestInstalledBackupRestore`, `TestInstalledRecovery`, `TestInstalledOutput` |

These owned fixtures supplement the exact-source CI run, including kernel and
vulnerability checks. They do not establish a production deployment, external
identity-provider login or independent node acceptance. Rehearse
[managed services](services.md) on the intended host separately. The old v0.2.0
package is checksum-pinned unsigned history, not an archived signed rollback.

## Prepare a release

1. **Set up trust.** Protect version tags. Configure `release-signing` for those
   tags with required independent reviewers and `prevent_self_review` enabled.
   Store `RELEASE_SIGNING_KEY` only in that environment, with no repository or
   organization fallback. Distribute the public trust separately.
2. **Freeze the candidate.** Select a reviewed source and new version. Pin the
   compatible console commit in `configs/release-compatibility.json`. Never move
   an existing version tag or relabel development packages.
3. **Create the protected tag.** Its push starts ordinary CI. All 16 required
   jobs must pass on that tag, source and run attempt. Do not manually dispatch
   ordinary CI on a tag: the CI entrypoint accepts release tags only on push.
4. **Prepare and sign.** Dispatch **Prepare signed release** on that tag with
   the completed CI run ID. Preparation checks the gates and existing packages
   without rebuilding or executing them. An independent environment reviewer
   approves the separate signing job, which signs `release.json` without a
   source checkout. CI input artifacts expire after 14 days; collect them before
   expiry or rerun the complete tag CI attempt.
5. **Audit the original bundle.** Download the complete signing artifact before
   its 90-day expiry. Audit against the expected version, source, builder and
   independently provisioned trust:

```sh
python3 tools/release.py audit --directory /path/to/release \
  --version "$DEBUGLET_VERSION" --source "$DEBUGLET_SOURCE_SHA" \
  --builder "$DEBUGLET_CI_RUN_URL" \
  --trust "$DEBUGLET_RELEASE_TRUST" --signer "$DEBUGLET_RELEASE_SIGNER"
```

The audit checks every signed file, acceptance-evidence ZIP, inventory and
provenance binding without running payloads. Its `published: false` result
means only local verification. The installer verifies its selected component;
this audit verifies the complete release.

For a release candidate, use a new tag such as `v1.0.0-rc.1` and publish it as a
GitHub **prerelease**, without making it latest. Rehearse that candidate before
creating the final version tag. Final-tag CI must build and sign the final
version; do not rename the RC's files. Keep RC packages off the public `stable`
apt channel, which has no separate prerelease suite.

## Publish installation assets

Publish **every original file** from the audited bundle on the GitHub release
for the same protected tag. Include release notes describing platforms,
compatibility, migration/restore and remaining limits. Do not rebuild, rename,
replace or re-sign assets during publication.

The bundle contains full and component tar packages, installers and checksums;
compatibility metadata; the two Debian packages and their inventory/checksums;
`release.json` and its signature; SBOM, provenance, build/gate records, notices
and original acceptance evidence. A partial installation-only upload cannot
feed the apt publisher or establish complete retention.

Download all published assets again, compare their digests with the audited
bundle, and repeat the full audit. On a clean supported host, install the actual
public files, confirm version/source, run the full bundle's `dbl demo`, and
check each component's documented command. No compiler or checkout should be
needed on that host. Then publish and verify the [apt channel](apt-repository.md).

The SBOM records Go modules and same-source offline WASI dependency graphs.
Runtime image pins are not a complete OS-package inventory, and recorded BPF
tool versions do not establish how inherited BPF objects were built.
For independent pilot deployments, agree [abuse response](abuse-response.md) and
[operator acceptance](external-pilot.md) with the affected operator.

## Retain a complete release

Use a private GitHub archive with immutable Releases enabled. Its administrator
creates the version tag and grants the publisher Contents write and
Administration read. The archive tag identifies its catalog commit; the signed
manifest identifies the product source. Authentication belongs in `gh`, never
in a URL.

Promote the audited bundle from a trusted checkout:

```sh
umask 077
python3 tools/release.py promote --repository "$DEBUGLET_RELEASE_ARCHIVE" \
  --directory /path/to/release --version "$DEBUGLET_VERSION" \
  --trust "$DEBUGLET_RELEASE_TRUST" --signer "$DEBUGLET_RELEASE_SIGNER"
```

Promotion verifies, uploads a draft without replacing files, redownloads and
audits it, then publishes and confirms immutability. An existing identical
immutable release is verified without writes; drafts, mutable releases and
conflicting bytes require inspection. Promotion never changes supported-version
pointers, builds packages or prunes history. Retain releases indefinitely, with
an independent backup; administrators can still delete a repository or release.

After two distinct signed versions are retained, review `retention.json` on the
archive's protected default branch. It contains `schema_version: 1`, `current`
and `rollback`; each entry pins `version`, `source_sha` and `manifest_sha256`
from verified promotion. Retained bytes alone do not guarantee schema downgrade
compatibility: rollback also needs compatible state and trusted backups.

```sh
python3 tools/release.py retention-audit --repository "$DEBUGLET_RELEASE_ARCHIVE" \
  --policy-revision "$DEBUGLET_RETENTION_POLICY_REVISION" \
  --trust "$DEBUGLET_RELEASE_TRUST" --signer "$DEBUGLET_RELEASE_SIGNER" \
  > retention-audit.json
```

The revision must be the current protected policy commit. The report records
both releases and file digests; missing, changed or unauthenticated content
fails. Verify authenticated download and anonymous-access refusal on the real
archive, then repeat retrieval after Actions artifacts expire. Actions retention
and a local fixture are not durable-archive evidence.
