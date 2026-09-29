# Deployment inputs

This directory holds everything used to install Debuglet on machines you
control: the container images, the Ansible roles that install the two daemons
as systemd services, and the scripts around them. None of it is needed to
install or run the package locally — see [README-install.md](../README-install.md)
for that.

CI performs no remote deployment. It builds,
packages and checks the release payload; the paths below consume that payload.
Nothing here deploys from CI, and no variable reaches a playbook from it.

## Two profiles

The examples in this repository belong to one of two profiles. They are not
interchangeable, and neither is derived from the other.

**Local TEST.** The compose rig in [docker-compose.yml](../docker-compose.yml)
with the configuration files in [docker/configs/](docker/configs). It runs the
two daemons on one machine with TEST payments, no wallet, no certificates, no
packet counter and no external network; the executor reaches the dispatcher
over loopback in the dispatcher's own network namespace, and the API is
published on a loopback address only. Everything it needs it creates itself. It is a
fixture for trying the daemons out, and the same shape the product writes for
itself when `dbl up` runs a local service.

**Authenticated deployment.** The Ansible roles in [ansible/](ansible), which
install the daemons as systemd services on machines in an inventory. They
render their configuration from the templates in `ansible/roles/*/templates`
and need operator-supplied input: an inventory, pinned SSH host identities, a
dispatcher address, an API origin, a UUID per executor and, while the control
channel uses TLS, certificates. The API enforces authentication, so a client
obtains a session with `dbl login --register`; the one credential-free profile
is `server.local_development`, which `dbl up` and `dbl demo` use and which the
daemon refuses on anything but a loopback listener.

TLS material belongs to the deployment profile, where the dispatcher serves
its own listeners and every executor verifies them; the local rig keeps its
control channel on loopback and needs none. Optional mutual TLS and
self-service enrollment are described under
[Transport security](#transport-security).

## Container images

[`docker/debuglet.Dockerfile`](docker/debuglet.Dockerfile) builds both role
images from a single payload stage:

```sh
docker build --platform linux/amd64 -f deploy/docker/debuglet.Dockerfile \
    --target dispatcher -t debuglet-dispatcher .
docker build --platform linux/amd64 -f deploy/docker/debuglet.Dockerfile \
    --target executor -t debuglet-executor .
```

The payload is Linux amd64 only, so `--platform` is required wherever the
Docker daemon defaults to another architecture. Both base images are pinned by
digest; the builder digest is the one the pipeline images use and the two move
together.

The build context is the repository root and must be a clean committed
checkout including `.git`. The payload stage runs the same two steps as the
build and package jobs — `internal/packaging build` with the pinned Go
1.25.11 toolchain, then `scripts/ci-package.sh` — and installs the resulting
candidate with the package's own installer. Both steps refuse a modified or
unidentified checkout, so there is no separate image build, no separate
version stamping, and nothing to keep in step with the package contract by
hand.

Each image therefore contains the complete installed package under
`/opt/debuglet`, with `dbl`, `debuglet-dispatcher` and `debuglet-executor` on
`PATH`. `dbl version` inside an image reports the packaged version and the
source revision the payload was built from:

```sh
docker run --rm --network none --entrypoint /opt/debuglet/bin/dbl \
    debuglet-dispatcher --output json version
```

The dispatcher image's entry point is `debuglet-dispatcher` and the executor
image's is `debuglet-executor`, both defaulting to `--config
/etc/debuglet/<role>/<role>.toml`. Mount a configuration file there, or pass
`--config` explicitly. The runtime layer is `debian:bookworm-slim` with CA
certificates; the images run as root so the executor can hold the capabilities
its egress tagger needs, so give a container only the privileges that role
actually requires.

### The local TEST rig

[`docker-compose.yml`](../docker-compose.yml) builds the same two targets into
a self-contained local rig. Each service mounts its configuration read-only
from [`docker/configs/`](docker/configs) and keeps its database on its own
named volume at `/var/lib/debuglet`. The dispatcher's HTTP API is published on
`127.0.0.1:9000`; set `DEBUGLET_LOCAL_HTTP` to another loopback address and
port to run a second rig beside it.

A daemon opens the database its configuration names and never creates the
schema, so the databases have to exist before the first start. The `seed`
service invokes each packaged daemon with `-init-database PATH` directly in
its private volume directory. No service, migration tool, Go toolchain or
network is involved:

```sh
docker compose build
docker compose --profile seed run --rm seed
docker compose up -d
```

Each database holds only the packaged schema and its migration record.
Initialization starts no listeners and records no accounts, runs or executor
registrations.
Repeating the seed step is safe: a database that already exists is kept, so a
rebuild or a restart never discards recorded runs. `docker compose down -v`
removes the volumes and starts the rig from nothing.

[`docker/compose-smoke.sh`](docker/compose-smoke.sh) is the end-to-end check
for the rig. It builds the images, seeds the databases, starts the services,
waits until the dispatcher's published API reports a ready executor,
registers an account with the packaged CLI, submits one TEST sample from
inside the rig and waits for it, restarts both services, reads the same run
back from the restarted dispatcher, and removes the containers, the volumes,
the network and the two images it built:

```sh
deploy/docker/compose-smoke.sh [PROJECT]
```

`PROJECT` is the compose project name, so parallel checkouts do not collide.
What it removes is what it created under that name: the base images the build
pulled and the builder's layer cache stay on the machine, as they do after any
build here. A pass says that the rig builds, seeds, registers an executor,
accepts an account the CLI registered, runs one TEST sample under that
credential and keeps its result across a restart. It says nothing about remote
topology, SCION operation, traffic policy or production readiness.

The executor shares the dispatcher's network namespace, so it reaches the
dispatcher over loopback on the same machine. That also fixes the order a
restart takes: stop the executor, restart the dispatcher, start the executor
again, or take the whole rig down and up. Restarting both at once leaves the
executor trying to join a namespace that is gone; its restart policy recovers
from that, and `docker/compose-smoke.sh` uses the ordered form. That is why the rig needs no
transport security and no certificates at all: there is no name to verify and
nothing leaves the machine. An executor that reaches a dispatcher over a
network is the deployment profile, where the dispatcher serves TLS and the
executor verifies it.

The rig has one optional profile, `tls-edge`, which puts nginx in front of the
dispatcher to try a TLS-terminating proxy out. It terminates TLS for API
clients only: it asks for no client certificate, and the executor does not go
through it. It is provisional — the daemons' own transport security is being
reworked and the rig will follow it.

`deploy/docker/nginx/certs` is not created by any target, so issue a
certificate for the names a client uses to reach the proxy and put the keypair
there. `./deploy/scripts/generate-certs.sh` writes a CA and a leaf with the
subjectAltName entries you give it:

```sh
CERTS_DIR=deploy/certs/local-test \
    DISPATCHER_SANS="DNS:nginx,DNS:localhost,IP:127.0.0.1" \
    ./deploy/scripts/generate-certs.sh
mkdir -p deploy/docker/nginx/certs
cp deploy/certs/local-test/dispatcher/server.crt \
   deploy/certs/local-test/dispatcher/server.key deploy/docker/nginx/certs/
docker compose --profile tls-edge up -d
```

`DNS:nginx` is the name the rig's own network uses, and the two loopback
entries are the names a client on the host uses. A client still has to trust
`deploy/certs/local-test/ca.crt`, which is a private CA: nothing else will.

The rig is a fixture, not a deployment. The Ansible roles below are the
supported way to install the daemons on a machine.

### Checking the images

[`docker/smoke-test.sh`](docker/smoke-test.sh) builds both targets, compares
the version and revision reported by each image with the checkout it was built
from, checks the payload manifest's toolchain, and then starts each image on a
loopback-only network with an explicit temporary configuration until its
daemon publishes a readiness record. The executor image is registered against
the dispatcher image started by the same run. Every container and temporary
file is removed afterwards; on failure the build and container logs are
retained and their directory is printed.

```sh
deploy/docker/smoke-test.sh
```

It publishes no ports and joins the executor containers to the dispatcher
container's network namespace, so nothing it starts is reachable from outside
the host. A successful run says that both images build, identify their source
and start; it says nothing about remote topology, SCION operation, traffic
policy or production readiness.

## The release package a deployment installs

A managed host installs the same verified package an operator installs by
hand. Nothing is compiled, downloaded or bootstrapped there: no Go toolchain,
no package manager, no version manager.
[`scripts/build-linux.sh`](scripts/build-linux.sh) copies the package out of
the same payload stage the images are built from, verifies it, and records
what it is:

```sh
./deploy/scripts/build-linux.sh
```

It writes to `deploy/dist/`: the release archive, its `SHA256SUMS`, the
candidate's own `install.sh`, the payload `manifest.json`, and `release.json`
— the version, source revision, toolchain and the digests of the archive and
the installer. The Ansible `payload` role copies the first three to the host,
checks them against the digests in `release.json` before anything runs, and
lets the candidate's own installer place the payload under
`/opt/debuglet/<env>`, where `<env>` is `prod` or `dev`. Each environment has
its own activation links, so updating dev cannot switch prod's executable.
Redeploying the same release installs nothing again.

`make deploy-seed-db` writes the schema-only SQLite databases the roles
install alongside them. It runs the already-built payload's daemon commands
with `-init-database PATH`, after checking its installed manifest matches the
release in `deploy/dist`. Run `make deploy-build` first; an image from another
release is refused. Neither `deploy/dist/` nor `deploy/certs/` is committed.

## The provisioner

Deployment runs from a provisioner built only from pinned inputs, so the tools
that change a host are as identified as the payload they install.
[`provisioner.env`](provisioner.env) pins them: the base image by digest, the
Ansible version, the collections with the digest of each artifact, and the
digest of each dependency manifest. Database initialization and upgrades use
the packaged daemons, so the provisioner needs no separate migration tool.
[`ansible/requirements.txt`](ansible/requirements.txt) is the complete
resolved Python set, installed with hash checking;
[`ansible/requirements.yml`](ansible/requirements.yml) pins the collections.
[`docker/provisioner.Dockerfile`](docker/provisioner.Dockerfile) builds the
image from exactly those and stamps them into a record inside it.

[`scripts/provisioner.sh`](scripts/provisioner.sh) runs one command in that
image, building it when it is absent. The repository is mounted at
`/repository`, the working directory is `deploy/ansible`, and an SSH agent
socket and `~/.ssh` are passed through read-only when they exist, so the
deployment commands are the documented ones:

```sh
deploy/scripts/provisioner.sh ansible-playbook -i hosts.yml -e @vars/prod.yml site.yml \
    -e dispatcher_addr=dispatcher.example.com \
    -e dispatcher_base_url=debuglet.example.com
```

The `make deploy*` targets go through the same wrapper.

[`ansible/preflight-provisioner.yml`](ansible/preflight-provisioner.yml) runs
before every deployment. It compares the running provisioner with the pinned
values — the Ansible version, the installed collections, the digest of each
dependency manifest and the record the image was built with — and stops the
deployment when any of them differs, before a task has changed a host. A
provisioner that was never built from these inputs has no record and is
refused outright.

That record is an attestation, not a verification: it is a file the image
build writes, read back from the machine that is running Ansible. It catches
a provisioner built from other inputs, a manifest edited after the image was
built, and a deployment run from an unpinned machine. It does not prove that
the installed dependencies are the bytes the digests name — `pip install
--require-hashes` does that, when the image is built — and someone who can
write inside that machine can write the record too.

Each environment records `/etc/debuglet/deployment-<env>.json`: what is installed
(version, source revision, toolchain and the archive and installer digests)
and what installed it (the provisioner's base image digest, Ansible version
and dependency manifest digests). The two identities are recorded separately,
and neither is inferred from the other. It carries no timestamp, so an
unchanged deployment rewrites nothing.

### Checking the provisioner

[`test/provisioner-check.sh`](test/provisioner-check.sh) builds the
provisioner from the pinned inputs and checks it in isolation: the checks on
the image itself — that it carries the pinned Ansible and collections, that
its record matches `provisioner.env`, that the preflight accepts it, and that
a changed dependency digest and a provisioner without a record each stop a
deployment — and then the checks of `test/ansible-render.sh` inside it.
It needs a release package, reads the repository read-only, and contacts no
host:

```sh
./deploy/scripts/build-linux.sh
deploy/test/provisioner-check.sh
```

## Deployment variables

Select the environment explicitly. The deployment command maps `dev` to
`hosts.dev.yml`, `known_hosts.dev` and `vars/dev.yml`, and maps `prod` to the
corresponding unsuffixed inventory and host-key file plus `vars/prod.yml`.
There is no production default. CI deploys nowhere.

GitHub browser login is enabled for the managed profiles. Create one ignored,
owner-only credential file per environment before preflight:

```sh
mkdir -p ansible/secrets/prod ansible/secrets/dev
cp ansible/github-oauth.env.example ansible/secrets/prod/github-oauth.env
cp ansible/github-oauth.env.example ansible/secrets/dev/github-oauth.env
chmod 600 ansible/secrets/{prod,dev}/github-oauth.env
```

Fill each file from its matching GitHub OAuth application. Configure the OAuth
applications' callback URLs as
`https://debuglet.netsec.ethz.ch/api/auth/github/callback` and
`https://dev.debuglet.netsec.ethz.ch/api/auth/github/callback`. Ansible copies
the selected file to the dispatcher with mode 0600 and systemd reads it as an
environment file; neither the secret nor the real file belongs in Git.

The selected vars file supplies the official public API origin. Set these
inputs for any other deployment:

- `dispatcher_addr` — the dispatcher as executors reach it, a bare host name
  or IP address with no scheme or port. Executors dial
  `dispatcher_addr:dispatcher_grpc_port` and
  `dispatcher_addr:dispatcher_http_port`.
- `dispatcher_base_url` — the bare domain the HTTP API is served from. It is
  the one origin allowed to send credentials to the API.
- `executor_id` — one lowercase UUID per executor host, the identity form the
  CLI generates and the dispatcher records. It is not derived from the host
  name, so a rebuilt machine keeps its identity, and the secure profile uses
  it as the certificate common name.

Put `dispatcher_addr` under `all.vars` in the selected inventory and assign a
UUID `executor_id` to every executor. Then build, issue or reuse certificates,
deploy, and verify the active services with one command:

```sh
./deploy/debuglet-deploy dev
```

Use `dispatcher` or `executors` as the second argument for a partial deploy,
and `--limit HOST` to select one inventory host. `preflight` performs only the
local safety checks. The equivalent Make target is `make deploy DEPLOY_ENV=dev`.

Set dispatcher_addr and each executor_id in the inventory. Override the
selected origin on the command line for a different deployment:

```sh
cd deploy/ansible && ansible-playbook -i hosts.yml -e @vars/prod.yml site.yml \
    -e dispatcher_addr=dispatcher.example.com \
    -e dispatcher_base_url=debuglet.example.com
```

[`ansible/preflight.yml`](ansible/preflight.yml) runs before every deployment
playbook. It checks the pinned host identities and then the variables — a
missing or malformed address, a wildcard credentialed origin, colliding
listener ports, a non-UUID executor identity, a database directory inside the
read-only configuration directory — and names the one that is wrong. It runs
locally, connects to nothing and changes nothing, so a deployment that cannot
succeed stops before it has changed a host. Run it on its own at any time:

```sh
cd deploy/ansible && ansible-playbook -i hosts.yml -e @vars/prod.yml preflight.yml
```

Each daemon keeps its database under `state_dir` (`/var/lib/debuglet` by
default), in a private directory owned by the service account, while
`config_dir` stays read-only for it. The rendered configuration carries the
TESLA seed, so the role keeps it out of task output and installs it mode 0640.
Executors on a shared host use separate `debuglet-prod`/`debuglet-dev` users,
`/etc/debuglet/executor-<env>` configuration,
`/var/lib/debuglet/executor-<env>` state and
`debuglet-executor-<env>.service` units. Package staging and deployment records
are also separate. Prod and dev dispatchers remain on separate hosts.

A daemon never creates its database. When a host has none yet, the roles
install the schema-only seed that `make deploy-seed-db` wrote, which is the
step a daemon's absent-database refusal names.
The roles never overwrite a nonempty database with a seed, and they never
upgrade one. A zero-byte executor database can be replaced with the seed. If a
previous installation has nonempty state and the selected environment has no
database yet, deployment stops and preserves that state and its legacy unit.
Back the database up, place it in the selected state directory, deploy again
and then upgrade it as described below. The same refusal protects a dispatcher database previously kept under
`config_dir/dispatcher`. An unsuffixed executor unit may belong to another
environment, so retirement requires an explicit
`executor_retire_legacy_install=true` after checking ownership and state. The
role then stops and disables it, retaining its unit file. Issue
new credentials for the selected environment instead of copying an old
executor's identity.

### Upgrading a database

A deployed daemon refuses a database whose schema is older than its release
supports and keeps refusing it until the database is upgraded. This procedure is
supported for wallet-free TEST deployments. It does not restore usable paid
state: migration 4 leaves existing earnings with an empty payout wallet that
executor re-registration does not repair. Keep chain payments disabled and
preserve paid databases and their backups for verified operator reconciliation
before enabling payments, as [Stored state](../docs/operations/configuration.md)
describes. Keep payments disabled when restarting upgraded paid-state
deployments until that reconciliation is complete.

Before fully deploying a release to a TEST deployment, build and install its
candidate payload and upgrade the databases with:

```bash
make deploy-upgrade-db DEPLOY_ENV=prod
# or one executor
make deploy-upgrade-db DEPLOY_ENV=prod LIMIT=executor.example.com
# or directly
make deploy-build
cd deploy/ansible && ansible-playbook -i hosts.yml -e @vars/prod.yml upgrade-database.yml
```

`DEPLOY_ENV` selects the inventory, variables and pinned SSH host identities
(`known_hosts` or `known_hosts.dev`) as `deploy/debuglet-deploy` does. Run
directly, a dev upgrade also needs
`-e known_hosts_file="{{ playbook_dir }}/known_hosts.dev"`.

The Make target builds the candidate package first. `upgrade-database.yml`
runs the same preflight as a deployment, then handles
the dispatcher and then the executors, one executor at a time. On each host it:

1. stops, before reading the database, when `debuglet_manage_services` is
   false and `upgrade_confirm_stopped` is not set: the playbook then cannot
   stop the daemon itself;
2. stops when the database (`state_dir/dispatcher/dispatcher.db` or
   `state_dir/executor-<env>/executor.db`) does not exist, as a deployment
   seeds a new one;
3. stages the verified candidate without changing command links or the
   deployment record;
4. runs the candidate daemon with `-check-database` as the service user
   through `runuser`. This mode only reads the database, so the service keeps
   serving it, and it answers with the candidate's own schema policy. A
   database that is already current ends the play on that host: the service
   is not restarted and no backup is taken;
5. stops when the upgrade would drop the recorded runs and their logs
   (dispatcher databases below schema version 3, executor databases below
   version 2) and `upgrade_accept_data_loss` is not set; the message names
   the database, its version and the tables concerned;
6. stops unless the database's filesystem has at least twice the size of the
   database and its `-wal` and `-shm` files free, one copy for the backup and
   one for the migration's own journal; the message gives both numbers;
7. stops the service;
8. copies the database and, when present, its `-wal` and `-shm` files into a
   new `backup-<UTC timestamp>` directory next to it, owned by the service user
   with mode 0700 and the files 0600;
9. runs the candidate daemon with `-upgrade-database` (and
   `-accept-data-loss` when `upgrade_accept_data_loss=true`) as the service
   user through `runuser`, so the database keeps its owner; the daemon names
   the database it upgrades, applies the release's migrations to it and checks
   the result as a start does;
10. activates only the upgraded daemon's candidate link and starts that
    service again. Run the normal deployment command afterward to activate
    the CLI, record the complete deployment, install the candidate
    configuration and verify the deployment.

Two extra variables change this, both `false` unless given with `-e`:

| Variable | Meaning |
|---|---|
| `upgrade_confirm_stopped=true` | With `debuglet_manage_services=false`, the operator has stopped the daemon on every selected host. Without it such a run fails at step 1. |
| `upgrade_accept_data_loss=true` | Apply an upgrade that drops the recorded runs and their logs. Without it such a run fails at step 5. |

A run that stops at steps 1 to 6 leaves the database and the service as they
were, including their restart targets and the deployment record. The candidate
may be staged in its version directory, but preflight and migration invoke
that exact executable without activating it. Running the playbook a second time
after a successful upgrade reports each database as current and neither
restarts a service nor takes another backup.

When step 9 fails the play stops on that host: the service stays stopped, the
backup and previous daemon link stay in place, the remaining executors are left
untouched, and the database is at the last migration that completed. Running the playbook again
continues from there; restoring the backup files returns to the previous state.
[Stored state](../docs/operations/configuration.md) lists the versions whose
upgrade loses recorded runs. No deployment playbook and no role imports
`upgrade-database.yml`, and `site.yml` never runs it.

#### Backup retention

The playbooks never remove a backup, so every upgrade that ran leaves one
`backup-<UTC timestamp>` directory next to the database. Once the upgraded
service has been verified, remove older backups with an explicit command run
as root on the host, for example keeping the two most recent dispatcher
backups:

```bash
find /var/lib/debuglet/dispatcher -maxdepth 1 -type d -name 'backup-*' | sort | head -n -2 | xargs -r rm -r
```

Use `/var/lib/debuglet/executor-<env>` for an executor. Keep every backup of a
database that holds paid state until the operator reconciliation described
above is complete.

### Transport security

Nothing proxies the executor path. An executor connects to `dispatcher_addr`
on the dispatcher's own two ports, the dispatcher serves TLS there
(`dispatcher_disable_tls: false`), and the executor verifies what it is given
against the deployment CA it pins in `credentials.ca_cert` and against the
name it dialled. A certificate that does not chain to that CA, or that does
not carry that name in its subjectAltName, ends the connection; nothing is
skipped and nothing is trusted on first use.

That makes the subjectAltName list an input rather than a detail, so
`scripts/generate-certs.sh` requires it:

```sh
DISPATCHER_SANS="DNS:dispatcher.example.com,IP:203.0.113.10" \
    ./deploy/scripts/generate-certs.sh 5fe02882-0410-416c-9935-235090bcba0d
```

It writes to `deploy/certs/`: a CA, a dispatcher leaf carrying exactly those
names with `serverAuth` extended key usage, and one client certificate per
executor UUID with `clientAuth`, each a leaf with `CA:FALSE` and a key usage
of `digitalSignature, keyEncipherment`. Changing the name list reissues the
dispatcher certificate rather than leaving one that no executor can connect
to. `make deploy-certs DISPATCHER_SANS=...` runs it for every executor in the
inventory and then installs the result with `ansible/deploy-certs.yml`: the
server keypair and the CA on the dispatcher, the CA and that host's client
certificate on each executor.

Four properties are checked before a deployment touches a host, because each
of them is refused at startup rather than tolerated: every named file must
exist, the root certificate in `ca.crt` must not have expired, each leaf must
chain to it, and each leaf must carry the extended key usage for the side it
is used on. Every certificate this script issues comes directly from that CA,
so a leaf file is a complete chain on its own; material from another authority
must follow the chain rules in
[Provisioning](../docs/operations/configuration.md).

Certificates therefore come first: issue and install them, then deploy. `make
deploy-certs` does both halves in that order, and a deployment that verifies
TLS refuses to start while the material is missing, expired or incomplete.

Two variables cover the cases where the default is not enough:

- `executor_tls_server_name` — the name to verify against when it is not the
  address dialled, for instance `dispatcher_addr` holding an IP while the
  certificate names the host. Rendered only when set.
- `dispatcher_require_client_cert` — makes the dispatcher require a client
  certificate from the deployment CA on its own listeners. Off by default,
  because turning it on refuses every executor that has not been given one
  yet. Rendered only when on, together with the `ca_file` it is checked
  against.

The daemons accept both keys. The templates emit them only when they are
set, so a deployment that needs neither renders neither.

A cleartext control channel is supported for one shape only: a dispatcher the
executor reaches over loopback on the same machine, which is what the local
TEST rig does. The preflight refuses `executor_disable_tls` for any other
`dispatcher_addr`, and refuses an executor that verifies TLS while the
dispatcher serves none.

### Self-service executor enrollment

Enrollment through the console is disabled by default. It requires a release
with API 1.10, an explicitly upgraded dispatcher database, native TLS on both
control endpoints, and certificates for every existing executor before enabling
`dispatcher_require_client_cert`. The browser API may have its own HTTPS proxy;
that proxy does not replace the native control listeners.

Preprovision a dedicated intermediate issuer certificate chain and matching
private key on the deployment controller. Keep the key owner-only (`chmod 600`)
and outside Git. Never use the deployment root CA or server private key as the
enrollment issuer. In your private environment variables, set:

```yaml
dispatcher_require_client_cert: true
dispatcher_executor_onboarding_enabled: true
dispatcher_executor_onboarding_ca_cert: /secure/enrollment-issuer.crt
dispatcher_executor_onboarding_ca_key: /secure/enrollment-issuer.key
dispatcher_executor_onboarding_dispatcher_url: https://debuglet.example/api
dispatcher_executor_onboarding_grpc_address: control.example:9001
dispatcher_executor_onboarding_yamux_address: control.example:9000
dispatcher_tls_ca_source: /secure/dispatcher-trust.crt
```

The public trust bundle must contain the authorities for the dispatcher server
certificate and for current executor certificates, including the new issuer.
It is copied verbatim to `dispatcher_tls_ca_file` and is also returned to newly
enrolled executors to verify the native control endpoints. Their public host
names must match the server certificate. By default, the bundle source remains
`certs_dir/ca.crt`; the root private key is never installed on the dispatcher.

Pass the same private variables to `preflight.yml`, `deploy-certs.yml`, and the
normal deployment. Preflight checks the explicit endpoints and issuer. Then
`deploy-certs.yml` copies the issuer into the dispatcher configuration directory
as `enrollment-ca.crt` and `enrollment-ca.key`, both mode 0600 and owned by the
service account. The normal deployment renders the opt-in configuration. No
issuer is generated or installed when enrollment is disabled.

Operators must plan certificate rotation: retain overlapping trust for existing
executors, and redistribute server trust when necessary. Existing executor trust
files do not update automatically. Enrollment certificates last at most 90 days;
renewal and issuer rotation are explicit operations. Turning enrollment off
stops new signups but retains installed keys and existing executor identities.
See [Executor onboarding](../docs/operations/executor-onboarding.md) for the
operator installation flow and its limits. Payments remain disabled.

### Checking the playbooks

[`test/ansible-render.sh`](test/ansible-render.sh) applies the roles to a
temporary directory tree on this machine over the local connection. It checks
that every playbook parses, that the preflight refuses each missing or
malformed variable and accepts a complete set, that the roles create the
skeleton and render both daemon configurations and both systemd units, that
the rendered files name the configured listener addresses and put each
database in the writable state directory, and that applying the same variables
again changes nothing. It applies prod and dev to the same temporary host,
checks their separate activation links, service identities and restart
targets, and verifies that updating dev leaves prod files unchanged. It also
checks empty-database recovery and refusal to replace nonempty legacy state.

It also issues certificates with `scripts/generate-certs.sh` and reads them
back with `openssl`: the dispatcher leaf carries the requested subjectAltName
entries and `serverAuth`, the executor leaf carries `clientAuth` and its UUID,
both are leaves the deployment CA signed, and the generator refuses to issue
anything without a name list. `ansible/deploy-certs.yml` then installs them
into the fixture tree, and the rendered configurations are checked for the
material on both sides — including that `tls.require_client_cert` and
`tls.server_name` appear only when their variables are set. No inventory, no
host key and no managed machine is involved, and nothing is deployed anywhere.

```sh
deploy/test/ansible-render.sh
```

It installs the real release package into that tree with the package's own
installer, and then starts each installed daemon against its rendered
configuration, so the files are accepted by the same validator a managed host
would apply. Run it through `test/provisioner-check.sh`, which provides the
pinned provisioner it expects.

## SSH host identities

Every deployment command authenticates a managed host against
`deploy/ansible/known_hosts` and nothing else. `ansible/ansible.cfg` turns on
strict host-key checking and ignores the system-wide known-hosts file;
`ansible/group_vars/all.yml` points `UserKnownHostsFile` at the provisioned
file. A host whose key is missing from it, or whose key no longer matches, is
refused when the connection is made — before facts are gathered and before any
task changes anything. Nothing adds a key that a host merely offered, and no
command runs `ssh-keyscan`.

Every deployment playbook first imports
[`ansible/preflight-host-keys.yml`](ansible/preflight-host-keys.yml), which
fails locally if the file is missing or empty, so an unprovisioned known-hosts
file is a clear error rather than a connection that would otherwise fall back
to trusting whatever answered.

The file is not committed, for the same reason `hosts.yml` is not: it names
private infrastructure. Provision it the same way, by copying it into place on
the machine that runs the deployment. See
[`ansible/known_hosts.example`](ansible/known_hosts.example) for the format.

`debuglet-deploy` selects `known_hosts.dev` for development and `known_hosts`
for production. Direct Ansible invocations must select it explicitly:

```sh
cd deploy/ansible && ansible-playbook -i hosts.dev.yml -e @vars/dev.yml site.yml \
    -e known_hosts_file="{{ playbook_dir }}/known_hosts.dev"
```

### Adding a host

1. Read the host's public key on the host itself, over a channel you already
   trust (the provider console, the provisioning record, an existing session):
   `cat /etc/ssh/ssh_host_ed25519_key.pub`.
2. Record its fingerprint next to the host's other provisioning details:
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
3. Add one line for the host to `deploy/ansible/known_hosts`, using the same
   name the inventory uses, and `[name]:port` if it is not on port 22.

Do not populate the file from `ssh-keyscan`. A scan records whatever answered
on the network, which is the thing this file exists to pin.

### Rotating a host key

A rebuilt machine or a rotated key makes deployment fail with `REMOTE HOST
IDENTIFICATION HAS CHANGED`. That failure is the intended behaviour: treat it
as unexplained until you know why the key changed.

1. Confirm out of band that the change was expected — a rebuild, a planned
   rotation, a provider migration.
2. Read the new key on the host as above and compare its fingerprint with the
   one the host's operator reports. Both must match before anything is edited.
3. Replace only that host's line in `deploy/ansible/known_hosts` and record
   the old and new fingerprints with the change, so the replacement can be
   reviewed later.
4. Deploy again. Never delete the file, and never work around a mismatch by
   relaxing the ssh options.

To take a host out of service, remove its line. Deployment to it then fails,
which is the intended result.

### Checking the configuration

[`test/host-key-verification.sh`](test/host-key-verification.sh) starts a
throwaway SSH server on a loopback port with a host key generated for the run
and connects to it with the options the deployment pins. It checks that an
unknown key is refused before authentication, that a refused key is not
recorded, that the correct pinned key is accepted, that a changed key is
refused, that replacing the entry with the key read from the host restores it,
and that no deployment command weakens host verification. The test host is
never in an inventory and is removed with the run.

```sh
deploy/test/host-key-verification.sh
```
