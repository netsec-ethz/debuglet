# Authentication cutover for an existing dispatcher

Current Debuglet rejects UUID cookies and UUID bearer tokens. There is no
transitional mode that accepts them alongside real credentials. A UUID or matching
email/display name cannot claim an account, executor or measurement. Keep
`server.local_development = false` on staging and production, including a dispatcher
behind a reverse proxy. The explicit loopback development profile is not a hosted
authentication mode.

Use [browser accounts and CLI access](authentication.md) for provider setup and
ordinary sign-in. This procedure concerns existing state; it does not establish
that a particular deployment has completed the cutover.

| Existing state | Result after upgrade |
| --- | --- |
| Account with a GitHub identity | The same provider subject reaches the same canonical account and its resources. |
| Account with an account key or recovery code | Its existing credential remains the login/recovery path; successful provider linking preserves its account ID. |
| User row from UUID-only authentication, with no verified identity or credential | The row and recorded ownership remain; access is withheld. A new provider login creates a separate account. |
| Run without recorded ownership | No account adopts it automatically. |
| Old UUID cookie | Refused; the user must sign in using a supported method. |
| Valid server-issued session | Preserved by the identity schema upgrade, subject to its original expiry and revocation state. |

## Back up and rehearse offline

Select a verified package with the current authentication checks. Retain its
version, checksum, configuration and an auth-enforcing rollback package. Do not
use a historical UUID-authentication binary as the rollback target. Read the
[database upgrade rules](configuration.md#upgrading-a-database) first: dispatcher
schemas below 3 require a destructive migration and need a separate export and
operator decision. Do not add `-accept-data-loss` to this procedure.

Run the following on the dispatcher host. Substitute the actual service account,
group, configuration and state paths; the backup root must be private. These commands
assume the managed service is the only database writer. Stop other writers too.

```sh
sudo systemctl stop debuglet-dispatcher
sudo systemctl is-active debuglet-dispatcher # must report inactive
sudo install -d -m 700 -o debuglet -g debuglet /srv/debuglet-backups
sudo -u debuglet sh
set -eu
umask 077
state_dir=/var/lib/debuglet/dispatcher
config_file=/etc/debuglet/dispatcher/dispatcher.toml
snapshot=/srv/debuglet-backups/before-auth-cutover
test ! -e "$snapshot"
mkdir -m 700 "$snapshot"
cp -a "$state_dir" "$snapshot/state"
cp "$config_file" "$snapshot/dispatcher.toml"
```

Back up referenced TLS material and provider secrets through the deployment's
secret-backup procedure too. Copy the complete stopped database directory,
including any SQLite companions. `dbl backup` covers its documented foreground
TEST layouts, not a complete hosted OAuth deployment.

Create a separate rehearsal copy, leaving the snapshot untouched:

```sh
rehearsal=/srv/debuglet-backups/auth-rehearsal
test ! -e "$rehearsal"
mkdir -m 700 "$rehearsal"
cp -a "$snapshot/state" "$rehearsal/state"
cp "$snapshot/dispatcher.toml" "$rehearsal/dispatcher.toml"
```

Edit the rehearsal configuration's `database.path` to name the copied database.
Verify that it does not name the live file. As the database owner, run the selected
new package's commands below; neither command starts a listener:

```sh
if debuglet-dispatcher -config "$rehearsal/dispatcher.toml" -check-database; then
  : # Already current.
else
  test "$?" -eq 3 # Only the non-destructive upgrade-required status may proceed.
fi
debuglet-dispatcher -config "$rehearsal/dispatcher.toml" -upgrade-database
debuglet-dispatcher -config "$rehearsal/dispatcher.toml" -check-database
```

Using a read-only SQLite connection, compare user IDs, UUIDs and `debuglet_users`
ownership against the untouched snapshot. For schema 6 or later, also compare
`transaction_users`; for schema 13 or later, compare recorded executor ownership.
For schema 9 or later, check that each existing GitHub subject still maps to its
original user. Record accounts lacking either credentials or a provider mapping;
an unchanged row count alone does not prove that they can sign in. Keep this
inventory private.

## Cut over and verify

Keep the service stopped and public ingress in maintenance while installing the
tested package/configuration. Upgrade the live database explicitly, then start
the service:

```sh
debuglet-dispatcher -config "$config_file" -upgrade-database
debuglet-dispatcher -config "$config_file" -check-database
exit
sudo systemctl start debuglet-dispatcher
sudo systemctl is-active debuglet-dispatcher
```

Tell users that old UUID cookies no longer authenticate and that new browser/CLI
sign-in is required. There is no legacy session table to migrate from UUID-only
authentication; do not turn UUIDs into session secrets. Existing genuine sessions
are different and need not be invalidated merely because the schema changed.

Before reopening public ingress, use two designated test accounts to check that
each sees its original account ID, executors and measurements, and cannot read
the other's private resources. Confirm unauthenticated requests to protected
routes fail and the local bootstrap login is unavailable. Verify the configured
provider callback and a CLI browser-approved login. A new blank account with a
similar display name is not a successful migration.

## Unmapped accounts and recovery

Keep unmapped accounts and their ownership records intact. Ask the operator to
independently verify ownership through the deployment's support process; a UUID,
email address or knowledge of a measurement is not proof. A trusted administrator
with access to the dispatcher host can restore access to an existing account
that has **neither credentials nor a linked provider identity**. This does not
merge accounts, transfer resources or adopt unowned runs. Until the independent
verification is complete, access stays withheld.

Record the requester, the independent evidence and the approving administrator
in a private support case. The command records that case's reference and its
effective operating-system UID; it cannot decide whether the evidence proves
ownership. If several administrators use the same service account, the support
case must identify the person approving the recovery. Do not put personal
evidence or credentials in the case reference, shell arguments or logs.

After taking the backup above, keep the dispatcher stopped and issue a code as
the database owner. Replace the example UUID and reference with the verified
account and a unique case reference:

```sh
sudo install -d -m 700 -o debuglet -g debuglet /srv/debuglet-recovery
sudo -u debuglet debuglet-dispatcher \
  -config /etc/debuglet/dispatcher/dispatcher.toml \
  -recover-unmapped-account 01234567-89ab-cdef-0123-456789abcdef \
  -recovery-case SUPPORT-2026-42 \
  -recovery-output /srv/debuglet-recovery/SUPPORT-2026-42.txt
```

The output path must be absent and its real parent directory must be owned by
the invoking user with mode 0700. Use a trusted directory tree and keep it under
the administrator's exclusive control during the command. The complete code is
published in a mode-0600 file before the database transaction commits. It is never printed. Output
failure rolls the transaction back. If a commit cannot confirm success, the
command reports the uncertainty and retains the private file; inspect the audit
and explicitly revoke any pending grant before retrying.

Issuance records the account, case reference, effective UID, issue time and expiry
in `account_recovery_audit`, and revokes every existing session of the account.
That also invalidates outstanding device approvals and pending identity links
bound to those sessions. The database contains only the code's verifier digest.
The code expires after 24 hours and works once through the existing
[`POST /auth/recover` procedure](../cli.md#recover-a-lost-account-key). Share the
file only with the independently verified requester through the deployment's
confidential support channel, then start the dispatcher. Successful recovery
records consumption and replaces the code with ordinary account credentials,
preserving the account's original UUID, role and resource ownership. The user can
then sign in and explicitly link an available provider identity. If that identity
already belongs to a different Debuglet account, linking is refused; continue
using the recovered account key and resolve the separate account conflict through
support. This command never moves provider identities between accounts.

For a lost, expired or incorrectly delivered **unused** code, stop the service
and revoke it on the host:

```sh
sudo -u debuglet debuglet-dispatcher \
  -config /etc/debuglet/dispatcher/dispatcher.toml \
  -revoke-account-recovery 01234567-89ab-cdef-0123-456789abcdef \
  -recovery-case SUPPORT-2026-42-REVOKE
```

Revocation records its time, UID and reference and removes only that pending
recovery credential. A replacement requires a new unique case reference and a
new absent output path. A consumed grant cannot be revoked or reused; the normal
account recovery rules apply after credentials have been issued. Inspect the
audit through a read-only database connection and retain the associated private
support record. Host administrators can modify the database, so this audit is an
operational record, not tamper-proof evidence against a compromised host.

There is no public administrator recovery endpoint. Do not rewrite ownership
rows, merge accounts by display name, or enable the local development bypass.

For an account that already has a recovery code, use the separate
[account recovery procedure](../cli.md#recover-a-lost-account-key). It preserves
that account's ownership while replacing its credentials and revoking sessions.
Knowledge of the account UUID cannot substitute for a genuine recovery code.

## Rollback without restoring UUID authentication

Stop the service and keep ingress closed. Preserve the failed state for diagnosis;
restore the untouched snapshot into a fresh private directory using
`cp -a "$snapshot/state" /path/to/fresh-rollback-state`. Point a copied configuration
at that directory. With the chosen auth-enforcing rollback package, run
`debuglet-dispatcher -config /path/to/rollback.toml -check-database`; if it requires
an upgrade, rehearse its documented explicit upgrade on another snapshot copy.
Never run an older binary against an unsupported newer schema.

Restart only after the same account-isolation and sign-in checks pass. If the only
binary compatible with the old snapshot accepts UUID authentication, leave the
service in maintenance and restore forward using an auth-enforcing package.
Retain the snapshot, package identities and verification results until recovery is
confirmed. Do not reopen an insecure historical version to restore availability.
