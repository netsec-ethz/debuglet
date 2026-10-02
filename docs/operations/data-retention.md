# Data retention, export and deletion

The dispatcher operator is the deployment's retention-policy owner. Measurement
payloads have **no automatic expiry by default**. The operator may configure
`[retention].payload_max_age_seconds` to a positive period; zero disables expiry.
The period starts when executor retirement is confirmed. Expiry also requires a
terminal run and final output; it never erases active, quarantined or uncertain
ownership to recover capacity. A bounded maintenance pass removes at most 100
eligible payloads at a time, so expiry is not an exact deletion deadline.

The [state reference](configuration.md#stored-state) inventories the
stored data. Account/session records, saved profiles, transaction/order records,
run IDs, ownership and original control bindings are independent of measurement
payload expiry. Queued work and executor output retain their own cleanup rules.
The configured period applies to the dispatcher's measurement payload, not
exports, packet captures, backups, journals or another daemon's retained state.

## Access, export and deletion

In authenticated deployments, owners and operators can read results and output;
other accounts cannot export them. Only the owning account may call
`DELETE /debuglet/{id}/payload`. Operator read privileges do not grant deletion
of another account's data. Ownerless runs can be deleted in the explicit local
TEST profile, which is not an account privacy boundary. Cookie requests require
the existing CSRF token, as other mutations do.

`dbl export RUN_ID`, the Go client's `Export`, and
`GET /debuglet/{id}/result` copy retained inputs and output without deleting the
server's copy. Export before deleting if a local copy is needed. Exports retain
unknown/truncated evidence and do not establish packet verification; see
[portable results](../results.md).

Deletion requires confirmed executor retirement and final output. A successful
response is HTTP 204; repeating it is harmless. HTTP 409 `payload_not_deletable`
means cleanup or output is incomplete. Deletion removes logs, destinations,
arguments, full provenance and the original requested-policy document. It
preserves minimal run/order/transaction/ownership references, terminal outcome,
observed execution times, retry bindings, output final cursor and immutable
workload/certificate digest references in a deletion tombstone. Output byte and
frame charges are released exactly once. Late duplicate output learns the
retained final receipt without recreating payload or its charge.

After deletion, result/log/detail retrieval returns HTTP 410 `payload_deleted`;
state and control records keep their original run identity and outcome. Missing
payload is never represented as a verified empty result. `dbl cancel` and
`DELETE /debuglet` request cancellation and do not erase payload. Default service
uninstall preserves state; explicit `--purge` removes a role's managed state
only after shutdown, as described in [service removal](services.md#remove-a-role-or-inactive-package).
Deleting rows or files is not secure erasure: protect SQLite/WAL files and backups
and apply the deployment's physical-storage policy separately.

## Diagnostic fields and ceilings

Routine logs contain fixed event/classification text, bounded request/run/session
identifiers, status, timing and resource counts. They must not contain request
bodies, credentials, arbitrary terminal text or private runtime stacks. Detailed
runtime/SQL causes use explicitly enabled private Debug diagnostics and existing
operator-controlled logs; startup/configuration failures remain actionable.
Known request/control credentials are redacted there too. Debug logs can still
contain addresses and dependency details, so restrict access and review exports.
See [diagnostic access](error-diagnostics.md).

Foreground role log defaults are three files of 10 MiB each and seven days.
Configuration permits at most 16 files, 100 MiB per file and 30 days; combined
age/size rotation preserves the live writer and reports write failures. These
ceilings do not cover measurement output or the system journal. The dispatcher
output defaults are 8 MiB/16,384 frames per run, 64 MiB per account and 512 MiB
per node, including logical overhead. A full store refuses new payload instead
of deleting old results. Local TEST can explicitly disable aggregate output
caps; shared deployments require positive caps.

Executor execution rows disappear only after successful owned cleanup.
Acknowledged output payloads are released while finality metadata remains.
Unacknowledged reports and prior-binding work remain inspectable without replay.
Sessions expire after 12 hours; issuing a session prunes expired session rows
older than a further 12 hours. Session expiry does not delete accounts or runs.
