# Fixed GCP executor fleet

`fleet.py` prepares a fixed inventory, creates its VMs and persistent boot disks,
and removes only those recorded resources. It uses Python 3.10+ and an existing
`gcloud` login. It does not install Debuglet, enroll executors, configure billing,
create networks or change KISTI/SCIERA hosts. No credentials belong in its config.

## Prepare without cloud access

Copy `fleet.example.json` outside the checkout and fill every placeholder. The
operator must supply the lab project, billing owner and approved monthly budget,
an immutable Ubuntu 24.04 amd64 image name, SSH username, and the explicit list
of nodes with zones and existing regional subnets. The example's two locations
are illustrative; the node list determines the count. Use a new fleet name for
each independent deployment and keep its state file for the fleet's lifetime.

```sh
umask 077
mkdir -p "$HOME/.local/state/debuglet-fleet"
cp deploy/gcp/fleet.example.json "$HOME/.local/state/debuglet-fleet/config.json"
# Edit config.json, then prepare the offline plan:
python3 deploy/gcp/fleet.py plan \
  --config "$HOME/.local/state/debuglet-fleet/config.json" \
  --state "$HOME/.local/state/debuglet-fleet/state.json"
```

`plan` calls no cloud API. It validates the inputs, assigns stable executor UUIDs
and prints the exact creation commands. Repeating it preserves those identities;
changing a recorded plan is refused. Back up the private state outside the fleet.

**The recorded budget is not a spending cap.** Before applying, the billing owner
must review VM, disk, external IP and expected network-transfer costs and arrange
billing alerts and a response owner. These are permanent resources: they keep
incurring charges until explicitly removed. An executor's rate limit does not
limit its monthly bill.

## Provision when approved

Use the lab's existing `gcloud` authentication; do not paste API keys into JSON or
source. The selected project needs Compute Engine enabled and quota for the
chosen instances. Arrange OS Login access (including administrative access for
Ansible's sudo tasks), SSH key registration and a permitted SSH route first.
The VMs have OS Login enabled, no attached service account, and no API scopes.
The helper uses explicit project and zone flags, independent of CLI defaults.

Firewall policy remains an operator input. Scope rules to the `debuglet-FLEET`
network tag: allow SSH from the approved administrative source, the dispatcher
control connections, and only the experiment listeners the fleet should offer.
Use the existing [network requirements](../../docs/operations/remote-deployment.md).
If SSH goes through IAP, supply its SSH proxy configuration to Ansible as well.
Do not open every port or permit private measurement targets to make enrollment
work. Each VM gets one ephemeral public IPv4 address; no static address is
reserved. If a stop/start changes it, rerun `apply` to refresh the inventory and
update the executor's advertised address through Ansible before accepting work.

```sh
# Replace PROJECT/FLEET with the exact values reviewed in the plan.
python3 deploy/gcp/fleet.py apply \
  --state "$HOME/.local/state/debuglet-fleet/state.json" \
  --confirm PROJECT/FLEET \
  > "$HOME/.local/state/debuglet-fleet/inventory.json"
```

Only use the inventory if the command succeeds. `apply` is repeatable: it checks
ownership and provider IDs, reuses existing resources and recovers interrupted
creation. It refuses a resource with a different owner or changed ID. On error,
keep the state, inspect the indicated operation with the lab's cloud access,
then retry or destroy the partial fleet. It does not silently roll back useful
resources. If a recorded resource was deleted externally, it refuses to create
a replacement with a new identity.

## Install and operate Debuglet

Use the JSON inventory with the existing [Ansible deployment](../README.md),
which installs a verified signed release as persistent systemd services. Keep
private inventory overrides separately: rerunning `apply` regenerates its output.

1. Obtain one approved signed release, its independently provisioned trust, and
   the selected dispatcher address. Use the inventory's stable `executor_id`
   values for the existing [TLS enrollment procedure](../../docs/operations/remote-deployment.md).
   Supply certificates/enrollment material privately; VM creation grants no
   Debuglet account access.
2. Pin each SSH host key through an authenticated provider console or another
   independently trusted channel. Configure `known_hosts_file`; a key obtained
   only through `ssh-keyscan` is not an authenticated identity.
3. Set the release/version, private certificate paths, dispatcher settings and
   location/display labels in the normal Ansible variables. Review the public
   policy: `executor_capacity: 100000000`, `executor_policy_local_targets: false`,
   `executor_policy_scion: false`, and the reviewed `executor_denied_destinations`
   defaults. Additional exclusions belong in host overrides; preserve the
   default exclusions when extending them. Review inbound listeners separately.
4. Run the existing preflight, then install one canary with
   `deploy-executors.yml --limit HOST`. Verify Ready, a bounded website experiment,
   restart/reconnection with the same identity, and a fresh experiment before
   installing the rest. For subsequent releases use the existing
   [serial rollout](../../docs/operations/release-rollout.md); a failed canary
   prevents progression.
5. Connect the existing [health alerts](../monitoring/health-alerts.yml) to the
   named operator and test alert delivery. Perform the
   [stopped-state backup/restore rehearsal](../../docs/operations/external-pilot.md).
   Copy verified backups off the VM; its boot disk is persistent, not a backup.

Runtime needs the dispatcher and the cloud network, not a developer laptop or
SSH tunnel. Only the deployment commands run on the operator's machine.
KISTI/SCIERA operators can use the same signed install and acceptance procedures
on their own hosts, adding them to a separate private inventory. SCION stays
disabled until a configured daemon and a controlled SCION measurement succeed;
host location alone proves no SCION reachability.

## Remove the fleet

Drain active work and preserve required state/results first. This command
**deletes the VMs and their recorded boot disks**, including executor state:

```sh
python3 deploy/gcp/fleet.py destroy \
  --state "$HOME/.local/state/debuglet-fleet/state.json" \
  --confirm PROJECT/FLEET
```

It checks ownership and exact provider IDs before deletion, preserves any other
attached disks, deletes the recorded boot disks separately, and requires provider
absence before reporting success. An interrupted deletion can be retried with
the same state. A timed-out creation can also be cleaned up without finishing
provisioning. It never deletes by a name prefix or fleet label alone. A deleted
fleet cannot be recreated using its old state. Disable its Debuglet registrations
through the normal console afterward; deleting a VM does not revoke enrollment.

## Validation

```sh
python3 -m unittest discover -s deploy/gcp -p 'test_*.py' -v
```

The tests exercise the real command/state logic against an in-memory cloud
fixture, including partial failures, retry, ownership collisions and replacement
IDs. They use no cloud account. Actual IAM, quota, SSH, signed installation,
enrollment and independent-host acceptance still need a rehearsal on the chosen
lab infrastructure before opening the fleet to researchers.
