# Abuse reports and destination opt-outs

Before operating a deployment, name an accountable reporting contact, a private
intake channel and the people allowed to read incident evidence. Agree who can
approve destination denials, revoke credentials and escalate an unresolved
report. The public issue tracker is suitable for requesting that contact, not
for packet captures, addresses, credentials or personal information. This
procedure does not designate a reporting contact or establish that the team has
agreed an evidence-access policy.

## Intake and approval

Open a private incident record with a time, incident identifier, report source,
claimed destination, requested action, reviewer and access list. Verify control
of the destination through the deployment's agreed private channel. An account
login by itself proves neither destination ownership nor authority to approve
an opt-out. Record the approval and the basis for that decision before changing
policy. Use the existing [security reporting policy](../../SECURITY.md) for a
suspected vulnerability.

## Apply and verify a destination denial

An authenticated operator submits `PATCH /destination` with the destination,
`"denied": true` and a concise reason, then reads `GET /destinations`. Preserve
the returned actor, revision, reason, timestamps, recipient count and delivery
state in the incident record. Keep sensitive evidence outside the reason field.
The denial persists across dispatcher restarts and refuses new work. A bandwidth
limit of zero is not a substitute for a denial.

HTTP 204 confirms delivery to the relevant executor recipients. A recorded but
unconfirmed change remains an incident action requiring observation; it does not
prove traffic stopped. A peer that cannot receive the denial is retired after
the bounded delivery attempt, and a lost control lease stops its active work.
Allow the delivery bound and the configured lease to expire before classifying
that recovery path. Read the recorded delivery result again after reconnect.

Verify the destination's actual receiver observations separately from the
acknowledgment. For owned fixtures, establish nonzero TCP and UDP traffic before
the denial, record the approval and delivery times, then record TCP termination
and a bounded quiet interval after queued UDP datagrams drain. Record those
durations and packet/byte counts, not an unqualified claim that all traffic
stopped forever. An attachment-presence observation, a closed socket or a quiet
interval alone does not validate every protocol, network path or packet counter.

Escalate persistent traffic or unconfirmed delivery to the named operator. Stop
the affected executor or revoke its enrollment under the deployment's approved
incident procedure if the denial cannot be established. Preserve the original
record and record further actions and observations; do not overwrite a failed
attempt with a later success.

## Copied credentials

Follow [Respond to a copied credential](authentication.md#respond-to-a-copied-credential).
From an uncompromised browser session, identify and revoke the affected
credential, or all account credentials if its identity is uncertain. Verify
that a formerly successful authenticated request with the old credential is now
refused. Record only its identifier, never the secret. When the legacy account
key is exposed, use the separately retained recovery code, confirm the old key
and old sessions are refused, and sign in with the replacement key. Account
recovery does not establish recovery of an external identity provider.

Credential revocation prevents subsequent authenticated requests. It does not
cancel admitted measurements: handle active work and observe the receiver
separately. Preserve the account identifier, credential identifier, times,
actions, observed results, reviewer and record-access policy privately.

## Owned local rehearsal

On supported Linux, the existing control-path fixture and credential drill run
without an outside host, identity provider or chain:

```sh
go test -race ./internal/executor \
  -run 'TestDestinationDenyControlPathAndReconnect|TestCredentialCompromiseDrill' \
  -count=1 -v
```

The destination fixture uses real local SQLite, HTTP authentication and role
checks, dispatcher/executor control channels, and loopback TCP/UDP receivers. It
exercises acknowledged delivery and lost policy delivery while ordinary control
probes still succeed. Its runtime adapter sends through admitted and registered
sockets; it is not an independently operated deployment or an arbitrary guest
validation. The credential drill exercises the real API's issue, use, revoke,
refuse and recover transitions with a local account. Neither drill uses the
local authentication bypass. The log records identifiers and observations, not
tokens, account keys, recovery codes or packet contents.

Keep the exact source revision, command, complete result, observed traffic
counts and timing in the private incident record. This technical rehearsal does
not replace a rehearsal with the actual reporting contact and agreed handling
and evidence-access policy.
