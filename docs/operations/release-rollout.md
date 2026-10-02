# Promote or roll back an executor release

`deploy/ansible/rollout-executors.yml` promotes one complete retained signed
release through existing Ansible-managed executors. It installs identical bytes
on every host, starts with an explicit canary, and stops at the first failure.
It does not build packages, create accounts, change certificates, deploy a
dispatcher, apply migrations, or automatically restore state.
Hosts also listed as dispatchers are refused: their shared command links need
a separate maintenance plan. Required file capabilities are applied to the
staged executor before stopping the old service; failure stops the rollout.
Previously installed candidates are reverified by the signed installer before
their executables run.

Use the inventory, pinned SSH identities and pinned provisioner from
[the deployment guide](../../deploy/README.md). The inventory remains the source
of the executor configuration. Review it before rollout: activation renders it
with the selected version. The controller needs a full installed CLI, its
connections file, and an account allowed to submit a small TEST-funded hello
measurement to every selected executor. No wallet or chain payment is involved.

## Prepare and authorize

Obtain the complete bundle from the approved immutable archive, including its
signed inventory and retained evidence. Provision release trust independently
as described in [signed releases](releases.md). Preserve the previous supported
bundle and its approved trust for rollback. Paths below are inside the pinned
provisioner; put private inputs under untracked `deploy/` paths available through
its read-only repository mount. Never commit connections, trust or inventory
files containing private deployment information.

Create a private variables file with the exact approved release and source:

```yaml
# Illustrative values: select actual retained artifacts and an authorized host.
deploy_version: v1.2.3
release_source_sha: "0123456789abcdef0123456789abcdef01234567"
dist_dir: /repository/deploy/dist
release_trust_file: /repository/deploy/private/release-allowed-signers
release_signer: releases@example.org
rollout_operator: "operator/change-reference"
rollout_confirm: "dev:v1.2.3:0123456789abcdef0123456789abcdef01234567"
rollout_canary: executor1.example.org
rollout_cli: /repository/deploy/operator-client/bin/dbl
rollout_client_config: /repository/deploy/private/connections.json
```

The confirmation records an operator's explicit choice; it is not an identity
provider or an authorization-server decision. Access is controlled by the
operator's SSH and dispatcher credentials. Put the canary first in the selected
inventory order. Select the environment and inventory explicitly:

```sh
deploy/scripts/provisioner.sh ansible-playbook -i hosts.dev.yml \
  -e @vars/dev.yml -e @../private/rollout.yml \
  -e 'known_hosts_file={{ playbook_dir }}/known_hosts.dev' \
  rollout-executors.yml
```

Each host first verifies the signature and complete inventory, stages the
selected package, and asks its daemon to check the current database schema.
An incompatible schema fails while the old executor still runs. Plan an
explicit, separately authorized database upgrade using `upgrade-database.yml`
when necessary; this rollout does not treat a migration as a reversible update.

For a compatible host, the playbook stops the executor and requires a successful
joined shutdown. It archives and compares the stopped state and configuration,
then records their SHA-256 digests in a private `rollout-backup-*` directory next
to the state directory. Backups contain credentials: keep them private. The
record identifies the host, previous and candidate artifacts, operator
confirmation, drain and schema result.

Only then does it activate the verified bytes. It requires service health,
reconnection with the selected version, and a fresh completed hello measurement
on that exact executor before advancing. An unreachable host, failed health
check or failed measurement stops progression. Hosts later in inventory order
keep their previous version. A failed canary can remain on the candidate; the
playbook preserves its prepared record and backup and does not conceal the
failure by automatically restarting an older binary.

## Roll back deliberately

For a bad release with compatible state, select the previous retained signed
bundle and its exact version/source in the same variables file. Keep the
failed executor stopped while inspecting it. A service that is already cleanly
stopped can enter the rollout; a failed or transitional service state requires
operator inspection before continuing.
It verifies the old candidate's schema before changing active links, then uses
the same serial health and measurement gates. Nothing is rebuilt.

An old binary that cannot read the current schema is refused. Do not force its
startup or run an automatic downgrade. Keep the original instance stopped,
verify the recorded backup digests, and restore the matching state and complete
configuration into separate private paths. Review embedded database paths and
external credential references before using a copied configuration; they must
not point back into the original live state. Never run two instances with the
same executor identity. A managed deployment needs an explicit restore plan;
`dbl backup`/`restore` supports foreground TEST state only.

Inspect the dispatcher-visible run states and the executor's retained-work
report around the rollback, then submit a fresh controlled measurement.
Interrupted work has an unknown or quarantined outcome; rollback does not
replay it. Work accepted after the backup may be unavailable after restore.
A forward-only migration or discarded old trust can make the old release
unusable; this procedure does not promise recovery beyond retained compatible
artifacts and verified backups.

## Local validation scope

The pinned provisioner can run the no-network two-host orchestration fixture:

```sh
python3 -m unittest deploy.test.test_rollout -v
```

It exercises real Ansible, release signature/audit and backup operations, with
small package, service-manager and measurement-client fixtures. It verifies
serial progress, canary failure stopping the untouched host, and incompatible
schema refusal before drain. It does not establish a real signed release,
production service behavior, private archive access policy, or independent
operator acceptance. Rehearse those against the actual supported release pair
and authorized hosts before activating a deployment.
