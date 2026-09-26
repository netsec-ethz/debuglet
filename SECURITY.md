# Security policy

Debuglet is an alpha for trusted local Linux environments. Its supported profile,
trust boundaries and known limits are described in [docs/SECURITY.md](docs/SECURITY.md).

## Supported versions

This policy covers the `v0.2.0` release candidates and validated commits on
`main` (currently `v0.2.0-rc.3`). Record the exact package version and source
revision. There is no backport branch; the existing `v0.1.0` tag predates this
package format.

To pick up a fix, build and install a validated revision as described in the
[installation guide](README-install.md). Checksums establish identity against the
supplied checksum file, which must come from a trusted source; they are not
release signatures. A state directory is tied to the package version that
created it, and [docs/environments.md](docs/environments.md#stored-state) states
what a build does with a database of another version.

Only the latest release candidate and the current validated commit of `main`
are supported; fixes are not backported to earlier candidates. Across commits there
is no compatibility promise for the `dbl` command
line, the control protocol between dispatcher and executor, or the database
schema: two commits are not promised to interoperate, and a state directory
created by one commit is not promised to be readable by another. The HTTP API is
versioned separately, as [docs/API.md](docs/API.md#supported-revisions)
describes, and that versioning still applies.

## Reporting a vulnerability

This repository is public, and GitHub private vulnerability reporting is not
currently enabled. Do not put vulnerability details, credentials or exploit
material in a public issue or pull request.

If you already have contact with a project maintainer, ask them for a private
reporting channel. Otherwise, open an [issue](https://github.com/netsec-ethz/debuglet/issues/new)
titled **Security reporting contact request**, without technical details, and ask
a maintainer how to report privately. A contact-request issue is public; it is
not itself the vulnerability report. No dedicated private channel or response
time is promised by this policy.

Once a private channel has been agreed, include:

- the affected commit or package version (`dbl version`, or `version` and
  `source_sha` in `share/debuglet/manifest.json`);
- the operating system, architecture and configuration mode, including TLS,
  payments and listener addresses;
- a minimal reproduction and the observed and expected behavior;
- the impact and the trust boundary in [docs/SECURITY.md](docs/SECURITY.md) involved.

Reproduce only against hosts and services you own. Remove credentials, private
keys and unrelated personal data from any attachments.

## Triage and scope

Reports should be evaluated against the supported profile, reproduced where
possible, and addressed with a focused fix and regression coverage. A documented
limit can still need a clearer explanation; reporting it does not establish
support for operation beyond that profile. Coordinate disclosure with the
maintainers before publishing a vulnerability or its fix.

This policy covers the dispatcher, executor, CLI, client and guest SDKs, guest
ABI, and packaging and installation scripts in this repository. Report dependency
defects upstream as well as to the maintainers when Debuglet may be affected.
Deployment-specific credentials, host administration and infrastructure outside
this repository remain the operator's responsibility.
