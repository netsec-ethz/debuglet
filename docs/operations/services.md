# Managed services

`dbl service` installs a dispatcher or executor as a system service. By default
it creates a host-local managed profile. An executor enrolled through My nodes
can instead preserve its TLS identity with `--enrolled-state`; follow the
[persistent executor setup](executor-onboarding.md#run-persistently-on-linux).
Other networked production deployments use the [Ansible deployment guide](../../deploy/README.md).

## Basic workflow

Install the package under a system prefix, create an unprivileged service account, then install and inspect each role:

```sh
sudo dbl service install --role dispatcher
sudo dbl service install --role executor --dispatcher 127.0.0.1:9001
sudo dbl service status --role dispatcher
sudo dbl service status --role executor
```

Use `dbl drain --role executor` before planned maintenance and `dbl drain --role executor --resume` when it is ready again. Service commands need administrator privileges.

The service owns its role-specific SQLite state and retains it across restart. A database is not automatically migrated or safe to reuse across arbitrary package versions. Back up state and follow the [database upgrade procedure](../../deploy/README.md#upgrading-a-database) before upgrading.

For an enrolled executor, supply `--enrolled-state` on every install or reinstall.
Its configuration supplies the dispatcher addresses, so endpoint override flags
are refused. The state must already be at the selected instance's canonical
managed path. An existing foreground daemon must be stopped before adoption;
do not launch one concurrently with installation. Use the managed unit to start
and stop it afterward. The daemon runs under the same unprivileged service
account and unit restrictions as the local managed profile.

Reference unit files live in [`deploy/systemd`](../../deploy/systemd).

## Tested managed profile

The installed TEST flow was exercised with this one Linux amd64 combination.
It is an observed profile, not a minimum-kernel or general distribution-support claim.

| Property | Tested value |
| --- | --- |
| Package | `v0.0.0-dev.902d027f1d61`, source `902d027f1d61f7c06f1b2a5a906de2caa8c529f4` |
| Full archive SHA-256 | `ce16b2326e9f9d732e6328d1e58fec1b9b0f13eb6218f3a2a99dcd6e417f5b62` |
| Container userland | Ubuntu 24.04.4 LTS, amd64 |
| Host kernel | `7.0.0-30-generic` |
| Service manager / cgroups | systemd 255 (`255.4-1ubuntu8.17`), cgroup v2 |
| Debuglet services | `debuglet` UID/GID 997, zero effective capabilities, `NoNewPrivileges=1` |
| Network / counter | Private loopback-only fixture; userspace fallback |

Both roles reached readiness and a TEST measurement completed. Restarting the
executor preserved its identity and left completed output readable. It drained
and preserved state through executor-only uninstall/reinstall. `doctor` ran
with the service's identity and sandbox: a read-only database caused both a permission failure and startup
failure. With BTF hidden and no capabilities, `auto` reached readiness through
the fallback counter while doctor left privileged enforcement unverified.

Follow the [disposable systemd fixture procedure](../../deploy/systemd/README.md#repeat-the-installed-profile-check)
to repeat these checks against an exact full package. Docker's systemd-hosting
privileges are separate from the unprivileged Debuglet services. This does not
verify a clean VM boot, reboot behavior, privileged eBPF enforcement, or another
host platform.

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
# Select a component package instead of the default full bundle:
sudo dbl service prune --prefix /usr/local --version v0.1.0 --component executor --dry-run
```

Pruning supports administrator-owned system prefixes. `--component` selects
`full` (the default), `cli`, `dispatcher` or `executor`. Only that package's
version directory is removed; other components, links and state remain.
It refuses unverified or aliased packages and anything referenced by a command
link, retained managed-role record or running executable. Default uninstall
therefore also keeps the package available for recovery. Stop foreground roles
and do not launch the version being pruned. User-owned prefixes remain
unsupported; an unreadable process or concurrent installer prevents pruning.

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
