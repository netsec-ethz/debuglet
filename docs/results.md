# Portable results

Save a retained run without keeping access to its dispatcher:

```sh
dbl export RUN_ID > result.json
```

`export` always writes JSON. It does not wait for the workload or output to
finish: pending, truncated and legacy output remain visible in the saved record.
Use `dbl logs --follow RUN_ID` first when complete output is required. A successful
export means the record was saved, not that the workload succeeded.

The Go client offers the same record online and offline:

```go
result, err := c.Export(ctx, runID)
// Save result with encoding/json, then read it later without credentials:
result, err = client.ReadResult(file)
```

`GET /debuglet/{id}/result` is available from HTTP API 1.8. Access follows the
same ownership rules as logs. The standalone file identifies itself with
`"format":"debuglet-result"` and `"version":"1.1"`; this file version is
independent of the HTTP API version. The reader accepts versions 1.0 and 1.1 and
rejects other versions, malformed records and inconsistent run, node or attempt
identities. Version 1.1 adds `provenance.vantage_point` and nothing else; a 1.0
file that carries one is rejected, so a 1.0 file keeps its original meaning. The
retained `v1.0.json` and `v1.1.json` fixtures are the compatibility baseline.
Readers from before 1.1 reject 1.1 exports as an unsupported version.

## What the record means

- `run_id`, `executor_id` and `attempt` identify the run and its original control
  session. An attempt has the original dispatcher incarnation and session UUID;
  it is not a retry counter. Legacy runs may lack that binding.
- `provenance` is an immutable admission snapshot: the exact WASM SHA-256,
  argument array, admitted policy, executor-reported software version, dispatcher
  build information and enrolled credential fingerprint when available. It is
  written with admission in the same database transaction. Current node metadata
  never replaces these facts. Runs admitted before this record existed have
  `provenance: null`.
- `provenance.vantage_point` (format 1.1) records where the run was to execute,
  as the dispatcher knew it at admission: the executor's last validated
  capability report (protocols, enforcement mode, its schema version), the
  dispatcher's receipt time of that report as `observed_at`, and `stale: true`
  when the report had outlived its 90 s lifetime; the source IP of the control
  connection; and the executor's configured `public_host`. It is `null` for runs
  admitted before 1.1. The object has its own `schema_version` (1); later facts
  such as ASN, geolocation or reachability are added as new fields.
- Within schema 1, `vantage_point` also records `scion_isd_as`, the executor's
  last reported SCION ISD-AS with `observed_at` and `stale` like capabilities,
  and `display`, the operator's `display_name`, `city`, `country` and `network`
  for that executor. 1.1 files written before these fields omit them; readers
  treat an omitted field as `null`, and readers without them ignore it, so every
  1.1 file stays valid.
- Each vantage-point value names its `source`: `operator`,
  `executor-reported` or `dispatcher-observed` (`database:<name>@<version>` is
  reserved for later lookups). Capabilities, `scion_isd_as` and `public_host`
  are `executor-reported`; `display` values are `operator`. `source_ip` is `dispatcher-observed` when taken from the
  connection, and `executor-reported` when the dispatcher fell back to the
  address in the executor's hello. No label means verified: an executor claim
  remains a claim. A value that was not recorded is `null` together with its
  source; it is never guessed or filled from current node metadata.
- `admitted_policy` is the accepted request. `host_policy: "unknown"` explicitly
  says actual host enforcement was not measured. An enrolled identity does not
  establish that a measurement is true.
- `outcome` preserves the stored workload state and bounded error classification.
  `exit_code` is always null in formats 1.0 and 1.1, which do not record it. An exited workload
  must not be interpreted as exit code zero.
- `timing.scheduled_start` and `reserved_until` are the reserved window, not
  measured execution times. Actual start, finish and clock uncertainty are always
  null in formats 1.0 and 1.1; the reader rejects a file that sets them. `observed_at` is the dispatcher time of the export snapshot;
  nanosecond timestamp representation is not a clock accuracy claim.
- `output.entries` contains every retained entry, in ID order, with exact bytes
  encoded as base64. `output.status` distinguishes `unknown`, `pending`,
  `complete` and `truncated`, independently of the workload state. Only
  `complete` establishes complete output. A truncated record retains the prefix
  and its fixed loss reason. Unknown future states remain incomplete.
- `verification` distinguishes unknown, unenrolled and enrolled-at-admission
  attribution. Packet evidence and measurement truth remain `unverified`.

Run state, provenance and output are read in one database snapshot. Two exports
may differ while a run is still receiving output. The export is not signed, and
the offline reader checks structure and consistency rather than authenticity.
Treat a file received from another party as that party's account of a run.

## Bounds and retention

Exports are limited to 32 MiB of encoded JSON and 65,536 retained entries. The
normal 8 MiB output allowance fits, including base64 encoding. Larger configured
allowances may exceed the export bound. The API returns `413 payload_too_large`
instead of silently dropping entries; use paginated logs for an oversized run.
The offline reader applies the same 32 MiB bound. Ordinary SDK response limits
remain unchanged.

An export contains retained data, not a backup of deleted history. Unknown
historical facts are never reconstructed from current executor settings. Keep
saved files according to your own retention requirements.
