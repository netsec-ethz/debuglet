# Browser accounts and CLI access

The console supports configured GitHub and CILogon sign-in. Both identify one
Debuglet account by an immutable provider issuer and subject; a display name or
email never joins accounts. Existing account IDs, executors and measurements stay
with their owners. UUIDs are identifiers, never login credentials.

In **Sign-in methods**, sign in again if asked, connect the other provider, check
which identity was returned and explicitly confirm it. A provider identity already
owned by another account cannot be transferred. Removing a method requires another
enabled method or an existing account/recovery credential. Linking or removing a
method revokes the account's sessions and API credentials and replaces the current
browser session. Rotation preserves the original authentication time; it does not
extend the ten-minute window for sensitive changes.

The dispatcher stores the issuer, immutable subject, display login and creation/
last-login dates. Display claims refresh at login; upstream account deletion and
recreation with a different subject creates a different identity. Provider access
and refresh tokens are used only during the exchange and are not retained. Logs
record the account ID, provider and action, without provider claims or credentials.

## Configure a dispatcher

Keep provider registration separate for development, staging and production.
Register the exact HTTPS callback URLs below with each provider. CILogon activation
requires its approval; configuring a client does not establish that approval or
prove real-provider acceptance. The automated suite uses a signed local provider,
including key rotation and rejected issuer, audience, signature, expiry and nonce.

```toml
[server]
behind_tls_terminator = true # only when this deployment actually terminates TLS

[authentication]
public_url = "https://dispatcher.example/api"
device_verification_url = "https://dispatcher.example/console/device"

[github_oauth]
enabled = true
callback_url = "https://dispatcher.example/api/auth/github/callback"
success_url = "https://dispatcher.example/console/"

[cilogon_oidc]
enabled = true
issuer = "https://cilogon.org"
callback_url = "https://dispatcher.example/api/auth/cilogon/callback"
success_url = "https://dispatcher.example/console/"
```

Supply `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `CILOGON_CLIENT_ID`
and `CILOGON_CLIENT_SECRET` from the service's private environment/secret store.
Never place secrets in the console bundle, configuration repository or command
arguments. CILogon requests only `openid profile`; email and institutional
entitlement claims are not required or used to grant privileges. Staging may use
`https://test.cilogon.org` with its own approved client. Changing an issuer does
not reuse identities from the previous issuer.

The callback, console and API audience must use the configured HTTPS origin.
Forwarded scheme and host headers cannot choose that origin or cookie security.
Both `[authentication]` URLs may be omitted to leave browser-assisted credential
issuance disabled. Existing browser and account-key login remain available as
configured. Upgrade the dispatcher database deliberately to the packaged schema
before running this version; identity migrations preserve existing accounts and
sessions. Older schemas are refused with the explicit upgrade command.

CILogon discovery refreshes hourly; signing keys refresh when an unknown key is
encountered. Failed discovery, exchange or verification cannot create a session.
The console distinguishes cancellation, expired sign-in and temporary provider
failure. Restart the dispatcher after rotating client secrets; verify sign-in in
staging before enabling production. [Provider registrations](#provider-registrations-ownership-renewal-and-callback-changes)
describes rotation with the deployment playbooks. Disabling a provider prevents new sign-ins
through it but does not by itself revoke existing Debuglet sessions: revoke them
explicitly during an incident. Preserve another enabled sign-in or recovery path
before disabling the last provider.

## Provider registrations: ownership, renewal and callback changes

The deployment's operator holds the GitHub OAuth app and the CILogon client
registration of each environment and records each client ID and registered
callback with the deployment's private configuration. Register exactly
`https://<dispatcher_base_url>/api/auth/<provider>/callback`, with `github` or
`cilogon` as the provider: `deploy/ansible/group_vars/dispatcher.yml` renders
these as `dispatcher_github_oauth_callback_url` and
`dispatcher_cilogon_oidc_callback_url`, and the dispatcher sends the configured
value as the redirect URI. `dispatcher_cilogon_oidc_issuer` must be
`https://cilogon.org` or `https://test.cilogon.org`; a client approved on
`cilogon.org` does not work against `test.cilogon.org`.

To change a callback, register the new URL with the provider first, deploy the
configuration with `make deploy-update-config DEPLOY_ENV=<env>`, verify sign-in
through that provider, then remove the old URL. If the provider accepts only one
callback URL, sign-in through it can fail until the registration and the
deployed configuration match. Each callback must share its origin with its
success URL and, when it is set, with `authentication.public_url`.

To renew or re-register a client, write the new values into the owner-only
`secrets/<env>/github-oauth.env` or `secrets/<env>/cilogon_oidc.env` beside the
playbooks, created from `github-oauth.env.example` or
`cilogon_oidc.env.example`. The dispatcher reads `GITHUB_OAUTH_CLIENT_ID`,
`GITHUB_OAUTH_CLIENT_SECRET`, `CILOGON_CLIENT_ID` and `CILOGON_CLIENT_SECRET`
only when it starts. `make deploy-update-config` installs a changed credential
file with mode `0600`, refreshes the service unit's list of environment files
and restarts the dispatcher, which then reads the new values. Verify sign-in,
then revoke the old secret at the provider. A GitHub identity is the GitHub
account's numeric ID, so a new GitHub OAuth app keeps existing identities.

## Approve a CLI or headless host

```sh
dbl connect https://dispatcher.example/api --name research
dbl --dispatcher research login
# On a shell-only machine:
dbl --dispatcher research login --no-browser
```

Open the printed URL on a browser, sign in and enter the displayed code. Check the
account, dispatcher, device label and requested permissions, then approve. Do not
approve a code supplied by somebody else. No browser callback listener or provider
secret is needed on the CLI host. A request expires after ten minutes; cancellation,
denial and reused approval cannot issue another credential.

The resulting API credential expires after twelve hours with no refresh. It is
bound to the exact dispatcher API URL and grants only the approved scopes:
`account:read`, `measurements:read`, `measurements:write`, `executors:read`, and
`executors:write`. There is no dispatcher administration or credential-management
scope. Measurements and executors still enforce account ownership. Include
`executors:write` when a CLI needs to register or enroll owned machines:

```sh
dbl --dispatcher research login --no-browser --scopes account:read,executors:read,executors:write
dbl --dispatcher research whoami --credential
dbl --dispatcher research logout
```

The CLI defaults to Linux Secret Service when `secret-tool` and a desktop D-Bus
session are available, otherwise to an owner-only `0600` file. Use
`--credential-store system` to require the keyring or `--credential-store file`
on headless hosts. A failing or locked keyring never silently downgrades to file
storage. See [credential storage](../cli.md#choose-credential-storage) and the
[upgrade guide](auth-migration.md) for existing dispatchers.

The console's **Credentials** page shows
active browser/API credentials and can revoke one or all of them immediately.
Manually created API secrets are shown once. If an approved polling response is
lost, revoke the resulting entry in the console and start again; approval is
consumed once, not replayed to recover a secret.

## Respond to a copied credential

From an uncompromised browser session, open **Credentials** and revoke the
affected entry. If the exposed credential is unknown, revoke all credentials,
sign in again and issue only the permissions each client needs. Confirm that
the old credential is refused; never paste its value into an incident report.

If a provider account is compromised, recover it through that provider and use
an uncompromised linked method where available. Disabling a provider does not
revoke existing Debuglet credentials. For an exposed legacy account key, follow
[account recovery](../cli.md#recover-a-lost-account-key); recovery replaces the
key and recovery code and revokes existing sessions.

Record the account, credential identifier, times, actions and observed outcome
in the deployment's private incident records. Revocation prevents future
authenticated requests; it does not cancel already admitted measurements.
Handle active work separately and verify its observed outcome before claiming
traffic has stopped.

## Provider-side incidents

**Leaked client secret.** Create a new secret at the provider, revoke the old
one and install the new value as described in
[provider registrations](#provider-registrations-ownership-renewal-and-callback-changes),
then verify sign-in. Debuglet sessions do not record the provider that created
them, so they cannot be revoked by provider. Revocation is per account: each
affected account holder revokes all credentials on the **Credentials** page or,
where the account has one, uses its recovery code, which revokes every session
of the account. Otherwise
sessions and API credentials expire twelve hours after issue.

**Compromised or rotated CILogon signing key.** The dispatcher fetches new
signing keys when a token names an unknown key and refreshes discovery hourly,
so a routine rotation needs no action. If every CILogon sign-in fails
validation, no session is created; check the configured issuer and that the
dispatcher reaches the provider. A restart discards cached discovery metadata.
If the provider reports a key compromise, set
`dispatcher_cilogon_oidc_enabled: false`, deploy the configuration and revoke
the affected accounts' credentials as above. GitHub sign-in does not verify a signed token: the dispatcher reads the
account from GitHub's API over HTTPS with the exchanged access token.

**Provider outage.** Existing Debuglet sessions keep working, while new sign-ins
through that provider fail without creating a session; see
[configure a dispatcher](#configure-a-dispatcher).

**Compromised provider account.** Follow
[respond to a copied credential](#respond-to-a-copied-credential).

## Authentication request limits

Authentication issuance and polling have bounded per-client rate limits and a
maximum of 4,096 pending device transactions. These limits complement reverse
proxy resource limits; they are not a general denial-of-service defense. If a
reverse proxy fronts the dispatcher, configure its exact trusted address prefixes
in `attribution.trusted_proxies`; the same verified forwarding chain identifies
clients for authentication issuance. Never trust arbitrary forwarding headers.
