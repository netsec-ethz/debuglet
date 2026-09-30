# Security policy

Debuglet is an alpha intended for trusted environments. The versioned [threat model](docs/security.md) describes actors, trust boundaries and current limitations. The [Security and supported scope Wiki page](https://github.com/netsec-ethz/debuglet/wiki/Security-and-supported-scope) contains operator guidance.

## Supported versions

The latest release and the current validated `main` commit are supported. Security fixes are not backported. Record the package version and source revision when reporting an issue.

See [Versions and compatibility](docs/versions.md) for the tested combinations
and how protocol, API, guest ABI, and state versions differ.

## Report a vulnerability

Do not disclose vulnerability details, credentials, private keys, or exploit material in a public issue or pull request.

Use [GitHub private vulnerability reporting](https://github.com/netsec-ethz/debuglet/security/advisories/new) when it is available. Otherwise, open a public issue titled **Security reporting contact request** without technical details and ask a maintainer for a private reporting channel.

A useful private report includes the affected version, deployment profile, minimal reproduction, impact, and expected behavior. Remove credentials and other sensitive data before sharing logs or attachments.
