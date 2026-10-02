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
configured. Upgrade the dispatcher database deliberately before running this
version, which requires dispatcher schema 18; migrations preserve existing accounts
and sessions. Older schemas are refused with the explicit upgrade command.

CILogon discovery refreshes hourly; signing keys refresh when an unknown key is
encountered. Failed discovery, exchange or verification cannot create a session.
The console distinguishes cancellation, expired sign-in and temporary provider
failure. Restart the dispatcher after rotating client secrets; verify sign-in in
staging before enabling production. Disabling a provider prevents new sign-ins
through it but does not by itself revoke existing Debuglet sessions: revoke them
explicitly during an incident. Preserve another enabled sign-in or recovery path
before disabling the last provider.

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

The CLI stores the credential in the existing owner-only `0600` profile file; OS
keychain integration is not implemented. The console's **Credentials** page shows
active browser/API credentials and can revoke one or all of them immediately.
Manually created API secrets are shown once. If an approved polling response is
lost, revoke the resulting entry in the console and start again; approval is
consumed once, not replayed to recover a secret.

Authentication issuance and polling have bounded per-client rate limits and a
maximum of 4,096 pending device transactions. These limits complement reverse
proxy resource limits; they are not a general denial-of-service defense. If a
reverse proxy fronts the dispatcher, configure its exact trusted address prefixes
in `attribution.trusted_proxies`; the same verified forwarding chain identifies
clients for authentication issuance. Never trust arbitrary forwarding headers.
