# Managed services

This page is the reference for `dbl service` and `dbl drain`. For the
installation commands, see [Run the roles as services](../README-install.md#run-the-roles-as-services).


`dbl service install --role dispatcher|executor` installs one verified role as a
service the host's service manager supervises. It is opt-in and sits beside the
unprivileged foreground commands, which are unchanged. It needs administrator
privileges and an existing unprivileged account; it never creates, changes or
removes one. The reference units are in [deploy/systemd](../deploy/systemd), and
the generator produces them byte for byte.

| | |
| --- | --- |
| Unit | `debuglet-dispatcher-<name>.service`, `debuglet-executor-<name>.service` |
| Account | `debuglet:debuglet` by default, existing, unprivileged |
| Payload | `<prefix>/lib/debuglet/<version>/bin/debuglet-{dispatcher,executor}`, system prefix |
| Persistent state | `/var/lib/debuglet/<role>s/<name>`, mode 0700, owned by the account |
| Administration | `/etc/debuglet/services/<role>-<name>.json` and `.maintenance`, mode 0644, owned by root |
| Runtime state | `/run/debuglet/<role>s/<name>`, created and removed by the manager |
| Readiness signal | `/run/debuglet/<role>s/<name>/ready.json`, written by the daemon |
| Shutdown budget | `TimeoutStopSec=45`, SIGTERM to the daemon alone |

The persistent directory holds only what the daemon itself serves: the role's
SQLite database, its `role-state.json` identity and the generated `service.toml`.
The installing administrator creates the directory, bootstraps the database and
hands the whole tree to the service account as the last step, so the bootstrap
never runs in a directory another account can already write to. Files are mode
0600 and the directory is mode 0700. Ownership is applied to each entry itself,
never through a symbolic link, and an installation refuses to take ownership of
anything in that directory that is not a regular file or a directory.

What is *not* in the persistent directory is the record of the installation and
a dispatcher's maintenance switch. Both live in `/etc/debuglet/services`, where
only an administrator can write them and every account can read them. That
separation is the point: the service account owns its state directory and can
therefore replace anything inside it, so nothing there may tell a later
privileged command where to act. Every path a later `start`, `stop`, `status`,
`drain` or `uninstall` uses is derived from the root, the role and the name the
operator named, and the record is used at all only when it agrees with those
derived paths; a record that names a different directory, unit or database is
refused and nothing is done. A dispatcher likewise reads its maintenance switch
and cannot remove or rewrite it, so it cannot take itself out of maintenance. The unit adds no privileges, grants
no capabilities, sees no home directory and can write only to that directory.
A package installed under `$HOME/.local`, the default of the package installer,
can therefore not be run as a managed service, and installing one is refused
with that reason; install the package under a system prefix such as
`/usr/local` instead. Because the service is confined to its state directory,
the generated configuration uses userspace packet accounting and disables
wallet and SCION integration. A managed dispatcher is a boot-time service that
every account on its host can reach, so its generated configuration also leaves
`server.local_development` off explicitly rather than inheriting whatever the
shared generator writes for a foreground environment: it authenticates every
request that is not public, and a client obtains a session for it with
`dbl login --register NAME`. A managed executor also denies loopback and the
internal ranges to the debuglets it runs: it serves submitters it does not
trust, on a host that has other services on it, so the local profile's
`network.policy.local_targets` is switched off for it. Transport security is disabled in this profile,
so a managed executor accepts only a literal-loopback dispatcher address on the
same host.

A restart keeps the directory, so it keeps the databases, the stored results and
a managed executor's identity. A copy of the state directory carries the identity
with it: an executor started from the copy presents the original's identity, and
running the original and the copy at the same time presents one executor from two
processes, each connection replacing the other's control session.
Installing is repeatable and changes nothing the
second time; installing a different package version over an existing state
directory is refused, because startup never migrates a database. The
[explicit database upgrade](configuration.md#stored-state) changes SQLite schemas
only; it does not make a local or managed state directory reusable by a different
package version. A reinstall
never restarts a running daemon: it reports that a restart is required and leaves
that decision to the operator.

`Type=exec` means the manager reports a unit started once the daemon has been
executed, which is process creation and not readiness. The daemon publishes its
readiness record when it has actually reached its ready point, and `dbl service
install`, `start` and `status` report ready only after reading that record and
finding that it names the unit's main process and, for an executor, its retained
identity. Stopping sends SIGTERM to the daemon alone (`KillMode=mixed`), which
leaves the teardown of anything it started to the daemon, and gives it the full
45-second budget. A stop is waited for rather longer than that budget, so a
daemon that uses all of it is not reported as a failure. The restart policy is the
deployment's and differs by role: a dispatcher is restarted after a failure
(`Restart=on-failure`), an executor after any exit at all (`Restart=always`),
because an executor that ends for any reason should come back. Neither undoes a
stop an operator asked for, which is what a drain relies on; a dropped control
stream needs no restart either, because the executor reconnects by itself.

The readiness record proves nothing about a stop: it lives in the unit's runtime
directory, which the manager removes whenever the unit stops, whether the daemon
finished or was killed. What proves that local ownership was released is how the
daemon left. An inactive unit whose recorded result is success and whose exit
status is zero is a daemon that ran its whole shutdown path: it revoked
admission, joined its own work and closed its database before exiting, and a
failure in any of those steps is a nonzero exit instead. A unit that was killed
at its stop timeout, or that exited nonzero, is `failed` with a result that says
which, and its state may still be owned by a process that never finished. Such a
unit stays failed until it is started and stopped again.

`dbl service uninstall` stops and removes the unit and keeps every byte of state;
removing a unit and disabling it touch no state, so they are allowed even after a
daemon ended badly. `--purge` also deletes the database, the identity, all
retained results and the installation record, and it is refused unless the last
shutdown actually finished. A refused purge undoes nothing at all, so the
instance stays installed and inspectable.

## Staging an installation

`--root DIR` writes the same files below another directory so they can be read
before anything is installed for real. A staged tree is files and nothing else:
the host has exactly one service manager, a unit of the same name there is the
production instance, and a unit's runtime directory is the real `/run` whatever
a staged unit says. A staged tree therefore drives no service manager at all,
and `start`, `stop`, `uninstall`, `drain` and `--start`/`--enable` are refused
together with `--root` rather than pointed at the production instance of that
name. A staged instance is always reported `stopped`, so `service status --root`
exits 4.

## The generated unit

The reference units in [deploy/systemd](../deploy/systemd) are what the
generator writes for a version `0.0.0-reference` package under `/usr/local`, and
a test compares the generator's output against them byte for byte. Beyond the
profile above:

- `Type=exec` needs systemd 240 or newer. The Ansible units use `Type=simple`,
  which reports a start before the daemon even runs.
- The unit grants no capabilities, because the generated configuration accounts
  traffic in userspace (`network.packet_counter = "fallback"`). The Ansible
  executor role can use the kernel counter instead and is then given
  `CAP_NET_ADMIN` and `CAP_BPF`. A managed executor therefore reports the same
  measurements as a foreground one and none of the eBPF tagger's.
- `RuntimeDirectoryPreserve` is left at its default on purpose: the daemon
  publishes its readiness record by creating a file that must not already
  exist, so a record preserved from the previous run would fail the next start.
- A dispatcher unit sets `DEBUGLET_MAINTENANCE_FILE`, the switch
  [draining](#draining-a-managed-role) publishes.
- Nothing here provisions the account, opens a firewall, rotates credentials or
  configures SCION.

The Ansible roles in `deploy/ansible` keep their own templates and are untouched
by managed services; a host can use either, as long as one host does not use
both for the same role.

## Draining a managed role

`dbl drain --role executor` stops one managed executor and disables its unit. The
stop is the drain: it is what revokes the executor's control eligibility, signals
its running work and joins its own local cleanup, and this workflow adds no
second lifecycle controller beside it. Other executors are untouched and keep
serving. The wait-versus-cancel policy is the daemon's own: queued work is
waited for only in the sense that admission is closed and nothing new starts,
running work is signaled and joined inside the stop budget, and nothing beyond
that is cancelled.

Once the join is proven, the command reports the disposition of what the node
still holds, read from its database read-only:

- **Queued.** Rows that were accepted and persisted but never started stay in the
  database. Nothing replays them; this build quarantines every stored control
  binding on the next start, so they stay inspectable instead of being re-run.
- **Started.** Rows that carry a start marker are never re-run either: a
  restarted executor refuses work it already started.
- **Quarantined.** Every retained row, for the reason above.
- **Terminal results.** Successfully persisted results whose acknowledgement
  this executor never observed stay retained, including those it never managed
  to send and those the dispatcher refused permanently. A storage write failure
  can leave no retained result; this build does not guarantee recovery from
  that failure. A retained result is evidence that this node selected an
  outcome; it is not evidence about what the dispatcher recorded.

Rows and results are counted exactly, however many there are. The one bounded
part of the report is the number of distinct control sessions the retained rows
came from: at most a thousand are distinguished, and a node holding work from
more says so, so that number is a lower bound and every other number is not.

A drain that does not join inside its budget is reported as incomplete. That report
authorizes nothing: no deletion, no upgrade and no database closure, because the
process may still own the database. `dbl drain --resume` enables and starts the
executor again; it replays nothing, and the retained rows stay quarantined.

`dbl drain --role dispatcher` does not stop the dispatcher. It publishes a
maintenance switch, a mode-0644 file in `/etc/debuglet/services` that the
generated unit names in `DEBUGLET_MAINTENANCE_FILE`, and the dispatcher refuses
new submissions while it is there. A refused submission is answered `503` with
the operator's reason, and nothing is admitted, scheduled or inserted. The
payment intent route is refused the same way, so no new order is priced while
a dispatcher is paused; an order that was already paid before the pause is
refunded by the refusal itself, which spends it: the same batch is refused from
then on, so no batch is ever run for a payment that has been given back. The
refund itself is at least once against the chain, not exactly once. The order
rows and the transaction move together in one database transaction, but the
transfer is not part of it: a transfer that was executed and then reported an
error, or one followed by a commit that failed, leaves the transaction paid and
is attempted again on the next submission. When the refund cannot be performed
at all the answer says the order is still paid and the batch can be submitted
again once admission resumes. It adds no route, needs no credential
and survives a restart, so maintenance is not undone by the restart it was
declared for; it is read for each submission, so `--resume` takes effect at once
without a restart. It stops exactly one thing: accepted debuglets keep their
persistence and schedule, executors keep their control sessions, and results and
queries are unaffected. `GET /readyz` follows the switch on its next evaluation;
probes reuse a completed report for one second, and evaluation time adds to
that delay. Submissions read the switch directly and are refused or admitted
at once. A switch file that exists but cannot be read or
understood also stops admission; an operator removes the file to serve again.
