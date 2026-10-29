# Signed apt repository

This channel installs the CLI, executor, dispatcher and samples on **Ubuntu
24.04 amd64**. Enrollment and service activation are separate steps. For package
upgrades, see [the Debian lifecycle](debian.md).

The official channel is not published yet. Follow the client instructions only
after the operator provides a verified URL, fingerprint and published version.
Website onboarding must use values confirmed by an actual public installation.

## Configure a client

Obtain the repository URL, independently confirmed OpenPGP fingerprint and exact
Debian version from your operator. Install `curl` and `gnupg` if absent. Replace
the placeholders below; they are not production trust values.

```sh
export DEBUGLET_APT_URL=https://YOUR-APPROVED-HOST/YOUR-REPOSITORY-PATH
export DEBUGLET_APT_FINGERPRINT=YOUR_INDEPENDENTLY_CONFIRMED_FULL_FINGERPRINT
export DEBUGLET_DEBIAN_VERSION=1.0.0-1

curl --fail --silent --show-error --proto '=https' --proto-redir '=https' \
  --location "$DEBUGLET_APT_URL/debuglet-archive-keyring.asc" -o /tmp/debuglet-key.asc
actual=$(gpg --batch --show-keys --with-colons --fingerprint /tmp/debuglet-key.asc |
  awk -F: '$1=="pub" {want=1; next} $1=="fpr" && want {print $10; want=0}')
test "$actual" = "$DEBUGLET_APT_FINGERPRINT" || exit 1
gpg --batch --yes --dearmor --output /tmp/debuglet-key.gpg /tmp/debuglet-key.asc
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 /tmp/debuglet-key.gpg /etc/apt/keyrings/debuglet.gpg
printf 'Types: deb\nURIs: %s\nSuites: stable\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/debuglet.gpg\n' \
  "$DEBUGLET_APT_URL" | sudo tee /etc/apt/sources.list.d/debuglet.sources >/dev/null
sudo apt-get update
sudo apt-get install "debuglet=$DEBUGLET_DEBIAN_VERSION"
/usr/bin/dbl --output json version
/usr/bin/dbl demo
```

`Signed-By` limits the key to this repository. Do not use `apt-key`, `trusted=yes`
or an unauthenticated fallback. A later `apt-get install debuglet=EXACT_VERSION`
stages that payload; it does not drain, migrate, enroll or restart services.
Follow the [service upgrade procedure](debian.md) before activation.

## Trust and layout

The repository has suite `stable`, component `main`, architecture `amd64`, and
serves its public key at `debuglet-archive-keyring.asc`. Confirm the full primary
fingerprint through an independent authenticated channel.

`InRelease` authenticates the Release metadata, which hashes `Packages` and
`Packages.gz`; each entry hashes its exact `.deb`. `Release.gpg` provides a
second form of the same metadata signature. The OpenPGP apt key is separate
from the [OpenSSH release key](releases.md#production-signer), which authenticates
the input bundle. Preparation and signing never execute packages.

Every publication retains prior packages under `pool/main/d/debuglet/` and
refuses changed bytes or a new selector older than the newest retained selector.
`Acquire-By-Hash` retains the preceding index generation for clients updating
during publication. Package retention does not guarantee state downgrade
compatibility.

Metadata expires after **90 days**. Republish the current approved final release
before expiry to refresh the signed dates while retaining packages. Preparation
may verify expired previous metadata only to carry those packages into a fresh
signed publication; clients must not disable expiry checks.

## Administrator setup

| Configuration | Requirement |
| --- | --- |
| Release tags | Protected semantic-version tags on reviewed source |
| `release-signing` environment | Approved tags, required independent reviewers, prevent-self-review enabled |
| Environment secrets | `RELEASE_SIGNING_KEY` for SSH releases; separate `APT_SIGNING_KEY` for apt |
| Repository variables | `APT_REPOSITORY_URL`, `APT_PUBLIC_KEY`, `APT_KEY_FINGERPRINT` |
| Pages | GitHub Actions source, HTTPS enforced, exact repository URL |
| `github-pages` environment | Approved release tags, no signing keys |

Provision keys through the team's key-management process, with protected backups
and revocation material. The apt private-key export must work without an
interactive passphrase. Keep keys only in the signing environment; ordinary CI
and Pages deployment receive no signing key. Do not generate production keys
in CI or replace existing trust during a new release.

The URL variable must match Pages' `html_url`. The fingerprint is the full
uppercase primary-key fingerprint of the single ASCII-armored `APT_PUBLIC_KEY`.
This workflow owns the entire Pages site; do not share it with another publisher.

## Publish and verify

1. Complete the [signed-release procedure](releases.md#prepare-a-release): fresh
   protected-tag CI, independent signing approval, complete audit and publication
   of every original release asset. Expiring Actions artifacts or partial uploads
   are not publication inputs.
2. Dispatch **Publish signed apt repository** on that same protected tag. The
   `stable` channel accepts only final releases; both prerelease tags and releases
   marked as prereleases are refused. Rehearse RC packages separately.
3. For the **first publication only**, select `bootstrap=true`. It requires no
   previous `github-pages` deployments and an HTTP 404 for InRelease. Inspect a
   failed first deployment before retrying; never remove history to force this
   condition. Later publications verify and retain the existing signed channel.
4. Have an independent reviewer approve the apt signing job. The separate Pages
   job deploys the signed files. Publications are serialized.
5. Download and verify the actual public repository with independently supplied
   trust, then run a fresh install, enrollment and retained-service upgrade:

```sh
python3 tools/apt_repository.py fetch \
  --url "$DEBUGLET_APT_URL" --out /tmp/debuglet-apt-downloaded \
  --key /path/to/independently-provisioned-key.asc \
  --fingerprint "$DEBUGLET_APT_FINGERPRINT"
```

Use a fresh output directory. This verifies the remote metadata and every
package without executing them. A successful upload or local fixture does not
establish public install/upgrade success.

The workflow verifies the input release's complete SSH-signed inventory and its
source against the protected tag. Its signing job performs no checkout and runs
only GnuPG over prepared metadata; key material is removed before upload. The
Pages job receives Pages/OIDC permissions, not the private key. No blocked tag
or environment protection should be weakened to make publication pass.

Retain an independent backup of each signed site and complete release bundle;
the 90-day Actions artifact is not a durable archive. Move to suitable hosting
before Pages capacity is exhausted, without silently pruning retained packages.

## Local rehearsal and key rotation

For an isolated repository test, use the unsigned builder:

```sh
python3 tools/apt_repository.py build --packages /path/to/debian-artifacts \
  --out /tmp/apt-test-site
```

Sign `dists/stable/Release` with disposable test trust to produce `InRelease` and
`Release.gpg`, then run `verify --directory /tmp/apt-test-site --key TEST.asc
--fingerprint TEST_FINGERPRINT`. `build --previous VERIFIED_DIRECTORY` retains
that snapshot's packages. Production uses `prepare`, which additionally verifies
the signed release. HTTP is allowed only with explicit `--allow-local-http` for
loopback fixtures. `make ci-debian` rehearses the installed package lifecycle
and tamper rejection; never reuse its disposable keys for production.

For rotation, verify and retain the whole old repository using its existing
trust, distribute the new key independently, then authorize a new signature over
those retained bytes. Update clients before ending the overlap. Changing the
configured key alone makes the old snapshot unverifiable to the publisher; the
single-key workflow does not infer rotation trust. In a compromise, use an
independently authenticated retained snapshot and revoke the old key.

Format references: [APT authentication](https://manpages.debian.org/stable/apt/apt-secure.8.en.html),
[apt-ftparchive](https://manpages.debian.org/stable/apt-utils/apt-ftparchive.1.en.html),
and [GitHub Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
