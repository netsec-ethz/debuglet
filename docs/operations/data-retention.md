# Data retention, export and deletion

Debuglet has no age-based expiry or individual deletion operation for dispatcher
run records, admitted destinations and arguments, provenance, cancellation
records or retained measurement output. The [state reference](configuration.md)
describes what each component stores; [output limits](configuration.md#executor-output-limits)
bound retained output capacity, not its age. A full store does not automatically
delete old results to make space.

## Access and export

In an authenticated deployment, a run's owner and operators can read its result
and output. Other accounts cannot export it. Host administrators can read the
plaintext databases, configuration and daemon logs. The explicit local TEST
profile permits credential-free access and should not be treated as an account
privacy boundary. Protect state directories and their backups accordingly.

`dbl export RUN_ID`, the Go client's `Export`, and
`GET /debuglet/{id}/result` copy the retained result, including admitted inputs,
identity references and output. They do not delete the server's copy. Exports
preserve unknown and truncated output states; they do not establish packet
verification or recover missing history. See [portable results](../results.md)
for format and size limits. Exported JSON and separately collected packet
captures remain under their holder's control, outside daemon log rotation.

## Cleanup that exists today

- [Foreground daemon diagnostics](services.md#foreground-daemon-logs) have
  configurable size, count and file-age limits. Defaults are three files of
  10 MiB each and seven days per role. These limits do not apply to measurement
  output, exported files, backups or the system journal.
- Executor execution rows are removed by normal completed-run cleanup.
  Acknowledged terminal reports and acknowledged output payloads are released;
  output finality metadata remains. Unacknowledged or rejected terminal reports
  and interrupted prior-binding work may remain for
  [recovery inspection](recovery-inspection.md). Restart does not authorize
  replay or age-based deletion of that evidence.
- Sessions expire after 12 hours. Issuing another session prunes rows whose
  expiry is more than 12 hours old; there is no background session cleanup.
  Session expiry does not delete the account or its runs.

`dbl cancel` and `DELETE /debuglet` request cancellation; they do not erase the
run or its output. Default managed-service uninstall preserves state.
Explicit `dbl service uninstall --purge` removes the selected role's entire
managed state after confirmed shutdown, as described in
[service removal](services.md#remove-a-role-or-inactive-package). It is not a
per-account or per-run erasure operation. It does not remove copies in the
other daemon, backups, exports, captures or the system journal. Deleting files
or rows is not a secure-erasure guarantee.

## Policy decisions still required

Automatic measurement expiry and selective deletion remain unsupported. A
deployment needs an accountable policy owner to agree allowed diagnostic
fields, retention periods and ceilings, export handling, and which integrity
or attribution references must survive payload removal. The existing log
limits are storage controls; they do not establish those policy decisions.
Daemon diagnostics can contain addresses, identifiers and detailed dependency
errors, so rotation alone does not make them suitable for public sharing.
There is no blanket credential-redaction guarantee for historical logs.
