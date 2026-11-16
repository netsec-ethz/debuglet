# Run a measurement from GitHub Actions

The [example workflow](../../examples/github-actions/measurement.yml) runs three
TCP connections from one executor to an IP address you control. Each connection
has a 1.5-second timeout; the entire guest has a 10-second host budget. It exports
the retained JSON and fails CI unless all three connections succeed within your
chosen threshold. It measures connection establishment, not bandwidth or HTTP
availability. The CLI submits **TEST-funded single-program runs**; the selected
dispatcher must permit them and the account must have sufficient allowance.

**Version requirement:** this workflow needs the release containing
`dbl login --token-file`. The published `v1.0.0-rc.1` does not have that command.
Until the new signed release is published, this is a development example, not an
RC1 quickstart. It targets Ubuntu 24.04 / Linux amd64. It uses the existing CLI,
not a separately installed GitHub Action or an MCP submission tool.

## Configure once

1. In the dispatcher's **Credentials** page, create an API credential with
   `account:read`, `executors:read`, `measurements:read`, and `measurements:write`.
   `account:read` permits the CLI to verify the imported credential. Save its token
   as the GitHub repository secret `DEBUGLET_TOKEN`. Do not use an account root
   key. Credentials expire; replace the secret after issuing a new credential,
   and revoke retired credentials on that page.
2. Set these repository **Actions variables**:

   | Variable | Value |
   | --- | --- |
   | `DEBUGLET_VERSION` | Exact signed release tag containing this example; never `latest`. |
   | `DEBUGLET_SOURCE_COMMIT` | That release's full 40-character source commit. CLI metadata must match it. |
   | `DEBUGLET_RELEASE_ALLOWED_SIGNERS` | Independently verified release `allowed_signers` public trust line. Follow [release trust](releases.md#production-signer); do not obtain trust solely from the downloaded archive. |
   | `DEBUGLET_ENDPOINT` | Exact issuing API URL, for example `https://debuglet.netsec.ethz.ch/api`. |
   | `DEBUGLET_CONSOLE_URL` | Website console URL, for example `https://debuglet.netsec.ethz.ch/console`. |
   | `DEBUGLET_EXECUTOR` | Ready executor UUID from `dbl nodes` or the website. |
   | `DEBUGLET_TARGET` | Your reachable server's numeric IP and TCP port, such as `203.0.113.10:443` (replace this documentation address). IPv6 uses `[address]:port`. |

3. Copy [measurement.yml](../../examples/github-actions/measurement.yml) into
   `.github/workflows/debuglet.yml` in your repository and run it from **Actions**.
   The workflow checks out the pinned Debuglet SDK, verifies the signed CLI,
   compiles the small [guest](../../examples/github-actions/tcp-check/main.go),
   and calls the existing `run --wait`, `export`, and `cancel` commands. Review
   the workflow before adding other triggers; do not expose its secret to
   untrusted pull-request code.

The **debuglet-results** artifact contains the receipt, complete exported result,
run link and diagnostic stderr, including when an assertion fails. The website
link uses your normal Debuglet account permissions; downloading a CI artifact
follows your repository's permissions. No credential file is uploaded.

## Check the failure path

Run once with a generous `max_connect_ms`, then repeat with `0`. Real connection
times should make the second run fail the measurement assertion while retaining
its results. A network refusal or timeout also fails the assertion even though
the guest deliberately records it and exits normally. Missing output, truncation
and unsuccessful guest execution cannot pass. Historical or current exports may
leave `exit_code` null; a recorded nonzero code is rejected, while a missing code
is never used as evidence that the measurement passed.

The runner attempts cancellation on failure or interruption when it has a run
ID. A force-killed runner cannot execute cleanup; the 10-second host runtime
budget still bounds admitted work. Client waiting is separately limited to 45
seconds. The script briefly waits for final output delivery before asserting.
It removes its temporary local credential store, without calling `logout`:
logging out would revoke the shared repository credential for subsequent jobs.

For agents, [MCP](../development/workflow-authoring.md#connect-an-mcp-client)
authors, validates and builds workflows; use the CLI to submit them explicitly.
