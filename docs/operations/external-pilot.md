# External executor pilot

This procedure describes a bounded pilot in which a researcher outside the
project installs and enrolls an executor on a Linux amd64 machine they
administer, using only the published documents, and reports what they observe.
A container or host operated by the project does not qualify.

The pilot starts only after the project names the exact signed release, the
dispatcher, the volunteer and host, and the measurement destinations. Agree the
measurement limits, stop condition, private support channel and restore procedure
before connecting. The volunteer's machine connects to no dispatcher or
destination before that.

## What the pilot establishes

The pilot records, as observed on the volunteer's machine rather than inferred
from the project's own tests: installation from the published package without a
Go compiler or source checkout; enrollment of the executor with the named
dispatcher; one controlled measurement; an actual restore from a stopped-state
backup; and the versions, proxy topology and capabilities observed on that path
(including TLS and SCION, where present). Restarting the original state directory
does not demonstrate restoration from a backup.

## Prerequisites for the volunteer

- A Linux amd64 machine, the supported platform in the
  [installation guide](../../README-install.md#supported-platforms), with a
  POSIX shell, GNU tar and coreutils.
- From the named signed release: the full archive, `install.sh`, `SHA256SUMS`,
  `release.json` and `release.json.sig`. The full package supplies both the CLI
  and the bundled measurement; it must provide `dbl executor join`.
- Verify the signed manifest and selected installation files before execution as
  described in [signed releases](releases.md), with the signer's public key
  confirmed through the project's authenticated channel. Record the exact source
  revision and archive digest. A checksum-only installation is insufficient for
  this pilot; v0.2.0 is unsigned and lacks `dbl executor join`.
- Network: the executor connects outward to the dispatcher's HTTPS API and
  control listeners and needs no public inbound control port
  ([topology](remote-deployment.md#required-topology)).
- Never share with support: private keys, the executor state directory, setup
  tokens, account keys, recovery files, session tokens or backups, which contain
  plaintext secrets.

## Steps

For every step, record the start time, the time of the first result, the exact
commands, the output or error text, and any deviation from the documents.

1. **Install.** Follow the [installation guide](../../README-install.md), or the
   [persistent setup](executor-onboarding.md#run-persistently-on-linux) for a
   system service. Run `dbl version` and record the module, version and
   revision it prints.
2. **Enroll.** Follow [Add your executor](executor-onboarding.md). The project
   supplies the dispatcher URL, the compatible package and, if the API uses a
   private CA, its public certificate. The setup token is issued to the account
   that owns the executor and expires after 24 hours; keep it off command
   arguments and out of any message. Record when the executor first appears as
   **Ready**.
3. **Connect and observe versions and capabilities.** Enrollment saves no CLI
   connection or session. Save the API URL from step 2, then sign in as the
   account that owns the executor:

   ```sh
   dbl connect DISPATCHER_URL --name NAME
   dbl --dispatcher NAME login
   ```

   Approve the printed code in a browser, adding `--no-browser` on a shell-only
   machine ([CLI access](authentication.md#approve-a-cli-or-headless-host)), or
   use the [account-key login](../cli.md#use-an-account-key-connection) if the
   project names it. For a private CA, set `SSL_CERT_FILE` to its certificate
   first; `connect` has no certificate option
   ([client trust](remote-deployment.md#client-trust-and-account-access)). Run
   `dbl --dispatcher NAME version --server` and
   `dbl --dispatcher NAME --output json nodes`, and record the server version
   and the executor's reported protocols (`tcp`, `tls`, `udp`, `icmp`, `scion`),
   packet counter and SCION ISD-AS ([executor discovery](executor-discovery.md)).
   Unknown or absent values are recorded as unknown.
   Record the API URL and any path prefix, the direct gRPC address and the
   reverse-control address separately. For each path, record whether it is
   direct, forwarded unchanged or terminated by a proxy, the observed TLS
   peer/certificate identity, and any routing or timeout deviation. Successful
   browser/API access alone does not demonstrate either control channel or the
   executor certificate binding. Preserve native executor authentication as
   described in [native TLS](remote-deployment.md#native-tls-and-executor-enrollment);
   if a proxy prevents registration, record the failure instead of disabling
   certificate verification. A reported SCION capability without a controlled
   SCION measurement remains unvalidated.
4. **Run one controlled measurement.** With the full package, run the bundled
   sample against your executor:

   ```sh
   dbl --dispatcher NAME run --executor ID --sample hello --wait --allow-remote-test
   ```

   Record the run ID, `dbl --dispatcher NAME status ID` and
   `dbl --dispatcher NAME logs ID`
   ([CLI reference](../cli.md)). Use only destinations agreed beforehand.
5. **Back up, then restore.** Complete the stopped-state restore below. Start
   only the restored copy, with the same package, configuration, certificate,
   private key and executor ID; no new setup token is needed while that
   certificate binding remains valid. Record whether that identity returns to
   **Ready** and a newly submitted measurement completes with output. Keep
   ordinary restart observations separate from the restore result.
6. **Shut down.** Stop a foreground executor normally. For a system service, use
   `dbl drain` and then `dbl service uninstall`, which keeps the identity and
   database ([managed services](services.md)).

## Restore an enrolled executor

The volunteer and deployment operator agree and validate a filesystem
backup/restore method appropriate to the deployment before the pilot. `dbl backup`
and `dbl restore` support only [foreground TEST state](backup-restore.md); they
refuse enrolled TLS or managed-service state. A separate local TEST drill does
not establish that this external executor can be restored.

This drill restores a fresh snapshot while the original executor stays stopped
for the entire backup-to-restore interval: no newer executor lifetime, signing
keys or work may be issued after the snapshot. It does not establish historical
backup rollback or rollback of TESLA signing state. If the source executor has
resumed since the snapshot, stop and review recovery with the operator rather
than reuse potentially stale signing state.

1. Stop the executor cleanly and confirm its process has exited. For managed
   services, stop the selected unit and prevent automatic restart during the
   restore. Record the package/source identity, executor ID, canonical state
   path and service account. Preserve the full private state directory and any
   configuration, TLS files or other runtime dependencies referenced outside it.
   Preserve ownership and permissions, and retain a private inventory and hashes
   with the backup. Keep the backup off the public tracker.
2. Keep the original stopped state separately for recovery. Restore the saved
   files into a new private staging directory using the agreed backup method;
   check the complete inventory, hashes, ownership and permissions before use.
   An incomplete copy, missing key or incompatible package stops the drill.
3. With all writers still stopped, place the verified restored files at the
   original configured paths, retaining the original files separately. Managed
   services require their canonical state directory; do not point them at an
   arbitrary copy or silently rewrite enrollment configuration. Restore any
   external dependencies to the paths the unchanged configuration names. Never
   start the original and restored identities together.
4. Start the restored executor with the same signed package. Inspect registration
   and the saved executor ID, then submit a fresh measurement explicitly and
   verify its output. Do not replay retained work or infer that an interrupted
   run completed. Record any expired certificate or changed dispatcher binding
   as a recovery failure requiring the operator's decision, rather than enrolling
   a new identity and counting it as a successful restore.

Record the backup time, stop time, restore start/end, restored readiness and fresh
output time. A restored executor does not roll back the dispatcher's stored
results or prove recovery of historical packet-attribution keys. Keep those
limits explicit. If the host has no complete, agreed restore method, this part
of the pilot remains pending.

## What the project records

- Time to first result: from the start of installation to the first completed
  measurement.
- Support effort: every contact, with its time, question, answer and the minutes
  spent.
- Recovery behaviour after starting the restored backup in step 5, including
  the observed backup age, restore duration, preserved identity and time to fresh
  output. Report restart-only evidence separately.
- Deviations from the documents and documentation defects.

The project keeps the pilot record privately with the deployment's
configuration. Each documentation defect becomes a public issue without
hostnames, addresses or secrets.

## Support instructions

- The project names one support contact by role for the pilot and responds as
  soon as possible on working days.
- Confidential material never goes to the public tracker. The project agrees a
  private channel with the volunteer before the pilot; suspected vulnerabilities
  follow the [security policy](../../SECURITY.md).
- Support may ask for `dbl` output, `dbl version` output, and logs with secrets
  removed. Support never asks for credentials, tokens, private keys, backups or
  remote access to the volunteer's machine.
- When a step fails, the volunteer stops and reports it. The project reproduces
  the failure on its own fixture and fixes the documentation or package before
  asking for a retry. The [troubleshooting guide](troubleshooting.md) lists the
  first checks.

## Scope limits

The pilot is not a performance or security assessment of the volunteer's network
or machine. Measurement destinations are agreed beforehand. A successful pilot
does not establish production readiness of the hosted dispatcher, and the
executor's states and reports are observations, not certification of location,
results or uptime.
