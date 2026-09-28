# Managed services

`dbl service` installs a dispatcher or executor as a system service. Use it only for a host-local, managed profile. Networked production deployments use the [Ansible deployment](../../deploy/ansible) and the [operator Wiki](https://github.com/netsec-ethz/debuglet/wiki).

## Basic workflow

Install the package under a system prefix, create an unprivileged service account, then install and inspect each role:

```sh
sudo dbl service install --role dispatcher
sudo dbl service install --role executor --dispatcher 127.0.0.1:9001
sudo dbl service status --role dispatcher
sudo dbl service status --role executor
```

Use `dbl drain --role executor` before planned maintenance and `dbl drain --role executor --resume` when it is ready again. Service commands need administrator privileges.

The service owns its role-specific SQLite state and retains it across restart. A database is not automatically migrated or safe to reuse across arbitrary package versions. Back up state and follow the [Deployment and Upgrades guide](https://github.com/netsec-ethz/debuglet/wiki/Deployment-and-Upgrades) before upgrading.

Reference unit files live in [`deploy/systemd`](../../deploy/systemd).

## Remove a role or inactive package

```sh
sudo dbl service uninstall --role executor --name worker
```

This stops and removes only the selected managed unit. Its database, identity
and configuration remain in the reported state directory; its administrative
installation record is also kept. Reinstalling the same package version can
reuse that state. `--purge` explicitly deletes the retained state and record,
and requires confirmed daemon shutdown.
A replaced unit, unit override or aliased state directory is refused.

Package removal is separate:

```sh
sudo dbl service prune --prefix /usr/local --version v0.1.0 --dry-run
sudo dbl service prune --prefix /usr/local --version v0.1.0
```

Pruning supports full bundles in administrator-owned system prefixes only. It refuses unverified
packages and versions referenced by the active CLI link, retained managed-role
records or running executables. Default uninstall therefore also keeps the
package available for recovery. Stop foreground roles and do not launch the
version being pruned. User-owned prefixes and component-package layouts are unsupported; an unreadable process
or concurrent installer prevents pruning.

## Foreground daemon logs

`dbl up`, `dbl dispatcher up` and `dbl executor up` retain daemon diagnostics in
their state directory. Each role defaults to three files, including the active
file, of at most 10 MiB each, with a seven-day file-age limit:

```sh
dbl up --log-max-bytes 10485760 --log-files 3 --log-max-age 168h
```

The limits can be configured up to 100 MiB per file, 16 files and 720 hours.
Age checks run when opening or writing logs, using file timestamps on restart;
there is no background deletion while a role is stopped. Lowering a byte limit
keeps the newest bytes of the active log and discards archives outside the new
limits. New files are private (mode `0600`). A write failure is reported and stops
the local operation through its normal child shutdown.

These limits cover daemon diagnostics, not stored measurement output. Managed
system services send diagnostics to the journal; configure its retention through
the host's journal settings.
