# Back up and restore foreground TEST state

The full installed package provides `dbl backup` and `dbl restore` for state
created by `dbl up`, `dbl dispatcher up`, or `dbl executor up`. Stop those
foreground commands normally and wait for them to exit before backing up. For a
dispatcher and its executors, stop the executors first, then the dispatcher.

This procedure supports the generated local TEST configuration. It does not
support direct daemon or systemd service state, external TLS credentials, SCION
configuration, OAuth configuration, or Sui payments. It refuses those inputs;
copying their database alone is not a complete recovery procedure.

## Create a backup

Use the same full installed package that created the state. The state directory
must contain a clean shutdown record written by a package with backup support.
Older state without that record cannot be adopted by a newer package merely to
create a backup: its package identity remains pinned.

Create a private directory for versioned backups, then choose a destination that
does not exist:

```sh
mkdir -m 700 "$HOME/debuglet-backups"
dbl backup --state-dir "$HOME/debuglet-executor" \
  --destination "$HOME/debuglet-backups/executor-before-maintenance" --offline
```

`--offline` confirms that no unmanaged process writes the state. The command
also requires the recorded clean shutdown, no remaining readiness records and
an exclusive state lock. It copies the stopped SQLite database and any WAL or
rollback journal, then checks and checkpoints the private copy. It does not
modify the original database or perform a schema upgrade.

Each backup contains a manifest with its observation time, schema versions,
package/source identity, role identity, file sizes and SHA-256 digests. Create a
new destination for every backup. A failed copy or validation never replaces a
previous backup. Cancellation removes its own unpublished staging directory;
an abrupt process kill can leave an incomplete private staging directory.

**Backups contain plaintext secrets.** Database account, credential and session
records and inline configuration are included. Directories are mode `0700` and
files are mode `0600`; this is access control, not encryption. Protect any
external storage or transfer separately. CLI profiles, external keys, binaries
and process logs are excluded.

## Restore into separate state

Keep the original instance stopped. Use the same full package version/source as
the backup, and choose a new state directory under a private existing parent:

```sh
mkdir -m 700 "$HOME/debuglet-recovery"
dbl restore --backup "$HOME/debuglet-backups/executor-before-maintenance" \
  --state-dir "$HOME/debuglet-recovery/executor"
```

Restore checks the fixed file inventory, hashes, schemas, package and identities
before publishing the new directory. Corrupt, incomplete or incompatible input
is refused. An existing destination is never overwritten. Restore does not
start a service or submit measurements.

For independent roles, back up and restore both role directories separately.
Start the restored dispatcher first and use its reported URL to start the
restored executor:

```sh
# In one terminal, after restoring its separate dispatcher backup:
dbl dispatcher up --name recovered \
  --state-dir "$HOME/debuglet-recovery/dispatcher" --port 0 --grpc-port 0

# In another terminal, replace the example URL with the one just reported:
dbl executor up --name recovered \
  --state-dir "$HOME/debuglet-recovery/executor" \
  --dispatcher http://127.0.0.1:DISPATCHER_PORT
```

For a combined `dbl up` state directory, restore its one backup and pass the new
directory to `dbl up --state-dir DIR` instead. Never run original and restored
copies simultaneously: they retain the same persistent identities and secrets.

| State | Recovery behavior |
| --- | --- |
| Persistent role identity, account/session records and completed results | Retained; credentials are not automatically revoked |
| Generated role configuration | Retained with the database path rebound; foreground startup applies its normal generated configuration and selected endpoint |
| Queued/started rows and retained terminal results | Kept under their original control binding; not automatically replayed under a new session |
| Dispatcher incarnation, executor control session and current TESLA chain | Created anew at startup |
| Historical schedule descriptors | Retained for inspection; historical private keys and external effects are not reconstructed |

After startup, connect the CLI to the restored dispatcher and explicitly submit
a new TEST measurement to verify recovery. Retained records do not prove whether
an interrupted measurement completed external effects, and this procedure does
not reconcile payment settlement or historical attribution.
