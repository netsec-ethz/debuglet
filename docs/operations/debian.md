# Debian packages

The initial apt target is **Ubuntu 24.04 amd64**. Install the `debuglet` package
from a reviewed signed repository following [repository setup](apt-repository.md).
Use the independently supplied OpenPGP fingerprint and a dedicated `Signed-By`
keyring; an archive checksum alone does not establish trust. No official live
repository URL is assumed by these instructions.

`debuglet` selects the commands `/usr/bin/dbl`, `/usr/bin/debuglet-executor` and
`/usr/bin/debuglet-dispatcher`. Its exact dependency is a separately named
`debuglet-payload-<manifest hash prefix>` package. That package preserves every
file of the existing full tar payload at
`/usr/lib/debuglet/debian/<full manifest SHA-256>/`, including its original
manifest, license, samples and all three binaries. Every release gets a separate
payload directory. Apt does not overwrite an older release during an upgrade.

Installation creates a missing `debuglet` system account and group, with no login
shell. Existing accounts and groups are retained. Missing `/var/lib/debuglet`
and `/var/lib/debuglet/executors` directories are created with mode `0755`; the
new executors parent belongs to the `debuglet` account and its primary group.
Existing ownership and modes are preserved. No package script enrolls an
executor, creates a per-executor identity, starts or restarts a service, changes
trust or configuration, or migrates a database. Python 3 is required for the
read-only removal guard; it adds no background process.

## Enrollment and activation

Use `/usr/bin/dbl` explicitly if an older tar-installed command appears earlier
on `PATH`. Follow [executor onboarding](executor-onboarding.md) to register,
establish trust and join using the service account. Joining creates the named
executor's state directory under `/var/lib/debuglet/executors`. Install and
activate that enrolled executor explicitly with the documented service command.
Dispatcher and local demo setup remain explicit as described in
[services](services.md).

## Updates and rollback

An apt update stages a new full payload and switches the three command links.
It leaves running and stopped managed services on their previously recorded
absolute payload paths. Even `apt upgrade` does not restart, enroll, migrate or
replace a managed service. Inspect the selected payload with:

```sh
dpkg-query -W -f='${Version}\n' debuglet
candidate=$(dirname "$(dirname "$(readlink -f /usr/bin/dbl)")")
printf '%s\n' "$candidate"
```

For an enrolled executor, follow the [release rollout](release-rollout.md):
drain it, create and verify an offline backup of its complete identity, keys,
trust, configuration, database, outputs and service records, then use the
verified replacement command while the unit is stopped and disabled:

```sh
sudo /usr/bin/dbl service install --role executor --name worker \
  --enrolled-state /var/lib/debuglet/executors/worker \
  --replace-package "$candidate" --start=false --enable=false
```

Use the recorded instance name instead of `worker`. Replacement preserves its
service account, state paths and identity. Check compatibility and explicitly
resume using the rollout procedure. Rollback selects a retained older payload
with the same replacement command and is subject to database compatibility;
an apt downgrade alone does not roll back a service or a database. Existing
dispatcher replacement limits are unchanged; see the rollout documentation.

Release `v1.2.3` has Debian version `1.2.3-1`; prerelease `v1.2.3-rc.1` becomes
`1.2.3~rc.1-1`, which sorts before the final release. Development versions such
as `v0.0.0-dev.abcdef012345` become `0.0.0~dev.abcdef012345-1`. Commit hashes do
not sort chronologically. Development candidates must be selected by their
exact Debian version; use apt's explicit downgrade option only when intentionally
selecting a version that sorts lower.

## Removal and repair

Removing or purging `debuglet` removes its command links and documentation.
It does not stop a service or delete state, identities, accounts or outputs.
The payload package's removal guard refuses removal whenever a retained
managed-service record references it, a command link in `/usr/bin` or
`/usr/local/bin` selects it, or a process is executing it. Unknown process state
and malformed or unreadable service records also refuse removal. No service
manager call is required for these checks. Run package maintenance separately
from enrollment, service replacement and foreground role startup so a new
reference cannot be created during dpkg's removal operation.

Apt may mark old payload dependencies as eligible for `autoremove`. The guard
still protects referenced payloads; refusal makes that cleanup command fail
with actionable guidance and leaves the protected payload in place. Use
`apt-mark manual <payload-package>` to keep a known recovery version out of
automatic cleanup. When a payload is no longer selected, executing or referenced,
remove its exact package with apt. An uninstalled service's retained record
still protects its payload. `dbl service uninstall --purge` also deletes that
role's data; do not use it merely to free software disk space. Preserve the
record and payload when recovery is still needed.

Same-version `apt-get --reinstall install <payload-package>=<debian-version>`
restores the exact signed package bytes and does not restart services or alter
state. It also supports retry after interrupted unpack, followed by
`dpkg --configure -a`. A directory replaced by a symlink is refused; investigate
and restore the real directory before retrying. Different payload content uses
a different package name and directory; never republish changed content under
an existing package identity/version. A forced dpkg removal that skips guards,
manual file deletion or custom unmanaged unit references is outside this
managed lifecycle.

Tar installations remain supported under their existing prefix, normally
`/usr/local`. Their version paths differ from Debian's content-addressed paths.
`dbl service prune` accepts only a valid version at `PREFIX/lib/debuglet/VERSION`
(or a known component subdirectory), so it cannot target a Debian payload.
The tar installer also refuses to replace the differently shaped Debian command
link at `/usr/bin/dbl`. Use apt for Debian-owned files and tar pruning for tar
versions.

## Build and inspect

After the normal clean-source full tar build, on Linux amd64 with Python 3 and
`dpkg-deb` installed:

```sh
scripts/package-deb.sh --package-dir .cache/ci/packages
```

The default output is `.cache/ci/packages/debian`. `--out DIR` chooses another
empty directory. Explicit inputs use `--archive FILE --checksums FILE --out DIR`
with the matching generated `install.sh` beside the archive. The existing
installer verifies archive hashes, exact payload members, modes and bytes before
assembly. The output contains `debuglet-VERSION-linux-amd64.deb`,
`debuglet-payload-VERSION-linux-amd64.deb`, `deb-packages.json` and
`SHA256SUMS-debian`. Both packages must be published and indexed together.
The JSON binds the source revision, archive, manifest digest, Debian version,
payload identity and package checksums. Release verification additionally checks
the `.deb` file contents and maintainer scripts against the reviewed source.

Run focused assembly and guard tests with
`python3 -m unittest discover -s deploy/debian -p 'test_*.py'`.
Use the Debian acceptance job for actual apt installation, upgrade, repair,
retained-service behavior and signed repository trust tests.
