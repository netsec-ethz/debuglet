# Managed role services

`dbl service install` writes a unit like the two in this directory, one per
installed role instance, and then owns exactly that unit. The files here are
reference copies for a version `0.0.0-reference` package installed under
`/usr/local`: the renderer in `internal/demo/service` produces them byte for
byte, and a test in that package compares its output against these files, so a
change to the generated unit cannot land without updating this reference.

They are not deployed by anything. The Ansible roles in `deploy/ansible` keep
their own templates and are untouched by managed services; a host can use
either, as long as one host does not use both for the same role.

## Profile

| | |
| --- | --- |
| Unit | `debuglet-dispatcher-<name>.service`, `debuglet-executor-<name>.service` |
| Account | `debuglet:debuglet` by default, an existing account, never created here |
| Payload | `<prefix>/lib/debuglet/<version>/bin/debuglet-{dispatcher,executor}`, verified before installation, under a system prefix |
| Persistent state | `/var/lib/debuglet/<role>s/<name>`, mode 0700, owned by the service account |
| Administration | `/etc/debuglet/services/<role>-<name>.json`, mode 0644, owned by root |
| Runtime state | `/run/debuglet/<role>s/<name>`, created and removed by the service manager |
| Readiness | `/run/debuglet/<role>s/<name>/ready.json`, written by the daemon itself |
| Shutdown budget | `TimeoutStopSec=45`, SIGTERM to the daemon alone (`KillMode=mixed`) |

The persistent directory holds the role's SQLite database, its `role-state.json`
identity and the generated `service.toml`. A restart keeps all three, so a
managed executor keeps its executor UUID and both roles keep their results.

The record of the installation, and a dispatcher's maintenance switch, are kept
in `/etc/debuglet/services` instead, readable by everyone and writable only by an
administrator. The service account owns its state directory and can replace
anything in it, so nothing there is allowed to tell a later privileged command
which directory, unit or database to act on.

## What the unit states

- `Type=exec` means the manager reports *started* once the daemon has been
  executed, and a payload that cannot be executed fails the start instead of
  being reported as started. It needs systemd 240 or newer; the Ansible units
  use `Type=simple`, which reports a start before the daemon even runs. That is
  process creation, not readiness. The daemon publishes
  `ready.json` when it has actually reached its ready point, and `dbl service
  install|start|status` reports ready only after reading that record and finding
  it names the unit's main process.
- Stopping sends `SIGTERM` to the daemon and to nothing else, and gives it the
  whole 45-second budget. The daemon uses it to revoke control eligibility,
  signal running work and join its own cleanup, and it exits zero only when all
  of that succeeded. That exit is the proof: the manager records the result and
  the exit status, and only `inactive` with result `success` and status 0 means
  the daemon released what it owned. `ready.json` proves nothing here, because
  the runtime directory is removed on every stop, killed or not.
- The restart policy differs by role: the dispatcher is restarted after a
  failure (`Restart=on-failure`), the executor after any exit at all
  (`Restart=always`), because an executor that ends for any reason should come
  back. Neither undoes a stop an operator asked for, which is what a drain
  relies on. The executor reconnects to a lost control stream by itself, so a
  dropped connection needs no restart at all.
- The unit grants no capabilities and needs none: the generated configuration
  accounts traffic in userspace (`network.packet_counter = "fallback"`), where
  the Ansible executor role can instead use the kernel counter and is then
  given `CAP_NET_ADMIN` and `CAP_BPF` in its unit. A managed executor therefore
  reports the same measurements as a foreground one and none of the eBPF
  tagger's.
- The runtime directory is not preserved across a stop (`RuntimeDirectoryPreserve`
  is left at its default). That is deliberate: the daemon publishes its readiness
  record by creating a file that must not already exist, so a preserved record
  from the previous run would fail the next start. It also means the record's
  absence says nothing about how a daemon stopped, which is why the stop is
  judged by the result the manager records instead.
- The unit adds no privileges, can write only to its
  own state directory, and sees no home directory at all. A package installed
  under `$HOME/.local`, which is the default of the package installer, can
  therefore not be run as a managed service: install it under a system prefix
  such as `/usr/local`. `dbl service install` refuses a home payload outright.
  The generated configuration uses userspace packet accounting accordingly, and
  disables wallet and SCION integration.
- A dispatcher unit also sets `DEBUGLET_MAINTENANCE_FILE`. Creating that file
  stops the admission of new submissions without stopping the dispatcher; see
  `dbl drain --role dispatcher` and [docs/environments.md](../../docs/environments.md).

## Not covered

Transport security is disabled in this profile, so the control plane stays on
one host's loopback interface: a managed executor accepts only a literal
loopback dispatcher address. Nothing here provisions the account, opens a
firewall, rotates credentials or configures SCION.
