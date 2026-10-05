# External executor pilot

This procedure describes a bounded pilot in which a researcher outside the
project installs and enrolls an executor on a Linux amd64 machine they
administer, using only the published documents, and reports what they observe.
A container or host operated by the project does not qualify.

The pilot starts only after the project names the release, the dispatcher, the
volunteer and the measurement destinations. The volunteer's machine connects to
no dispatcher or destination before that.

## What the pilot establishes

The pilot records, as observed on the volunteer's machine rather than inferred
from the project's own tests: installation from the published package without a
Go compiler or source checkout; enrollment of the executor with the named
dispatcher; one controlled measurement; a backup and restart from preserved
state; and the versions and capabilities the executor reports (including TLS and
SCION, where present).

## Prerequisites for the volunteer

- A Linux amd64 machine, the supported platform in the
  [installation guide](../../README-install.md#supported-platforms), with a
  POSIX shell, GNU tar and coreutils.
- From the named release: the full archive, `install.sh` and `SHA256SUMS`. The
  release must provide `dbl executor join`; v0.2.0 does not.
- Verification: the installer checks the archive against `SHA256SUMS`, which
  detects changed bytes but does not identify the publisher. When the named
  release is signed, verify it first as described in
  [signed releases](releases.md), with the signer's public key confirmed through
  the project's authenticated channel. Release signing requires administrator
  setup before its first use; v0.2.0 is unsigned.
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
3. **Observe versions and capabilities.** Run
   `dbl --dispatcher NAME version --server` and
   `dbl --dispatcher NAME nodes --output json`, and record the server version
   and the executor's reported protocols (`tcp`, `tls`, `udp`, `icmp`, `scion`),
   packet counter and SCION ISD-AS ([executor discovery](executor-discovery.md)).
   Unknown or absent values are recorded as unknown.
4. **Run one controlled measurement.** With the full package, run the bundled
   sample against your executor:

   ```sh
   dbl --dispatcher NAME run --executor ID --sample hello --wait --allow-remote-test
   ```

   Record the run ID, `dbl status ID` and `dbl logs ID`
   ([CLI reference](../cli.md)). Use only destinations agreed beforehand.
5. **Back up and restart.** Stop the executor cleanly, preserve its entire
   private state directory, then start it again from that same directory with
   the same configuration; no new setup token is needed
   ([restart and recovery](executor-onboarding.md#restart-and-recovery)). Never
   run two copies of one identity. The `dbl backup` and `dbl restore` commands
   cover foreground TEST state only; to exercise them, follow
   [backup and restore](backup-restore.md) with a local `dbl up` pair. Record
   whether the executor returns to **Ready** and a new measurement succeeds.
6. **Shut down.** Stop a foreground executor normally. For a system service, use
   `dbl drain` and then `dbl service uninstall`, which keeps the identity and
   database ([managed services](services.md)).

## What the project records

- Time to first result: from the start of installation to the first completed
  measurement.
- Support effort: every contact, with its time, question, answer and the minutes
  spent.
- Recovery behaviour after the restart in step 5.
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
