# Work together in a community

A community gives a research group a shared workspace for projects, editable
experiments and measurement results. Everyone signs in with their own account.
The person who creates the community owns it, invites members and funds its
shared measurement budget.

Projects organize related work. A saved experiment contains either one workflow
or a coordinated experiment with several participants. Measurements are actual
runs, with their original executor choices, configuration, output and provenance.
Saving an experiment does not execute it.

## Set up a group

Open **Communities** in the console and choose **Create community**, then create
a project for an investigation or study. The **Projects**, **People** and
**Funding** tabs keep shared work, membership and the budget together. Under
**People**, the owner can choose **Invite someone** and send the link privately.
The recipient signs in with their own account, then chooses **Join community**.

An invitation expires after seven days and can be used once. It is a credential
that lets its recipient join the group, so do not publish it in a public issue or
repository. Owners can remove members. A removed member loses subsequent access
to shared work and cannot reserve new community spending; previously downloaded
copies cannot be recalled.

| Action | Member | Community owner |
| --- | --- | --- |
| Read shared projects, experiments and results | Yes | Yes |
| Create or edit projects and experiments | Yes | Yes |
| Delete an unused saved experiment | Their own experiment | Any unused experiment |
| Share a personally owned measurement | Yes | Yes |
| Submit using the available community budget | Yes | Yes |
| Remove a personally funded measurement reference | Their own share | Any personal share |
| Rename the community, invite or remove members | No | Yes |
| Deposit money into the community budget | No | Yes |

Community ownership does not make someone a dispatcher operator or give them
control over another member's runs. The creator remains the owner; ownership
transfer is not part of this interface.

## Save and reuse experiments

Choose **Save to community** in a workflow or experiment builder, select the
community project and save the editable source. **Include compiled program**
also saves its matching bundle. Members can then inspect the blocks, choose
their own executors and review a new measurement.
Optional collection labels group experiments within a project; descriptions
record the question or procedure being studied. Open an experiment to download
its source or bundle and see the measurements associated with its revisions.

A source-only experiment is editable but still needs compilation before it can
run. A saved compiled bundle can be reused without a compiler while its source
remains unchanged. Editing the source invalidates that compiled artifact; supply
a matching rebuilt bundle to run the edited version. When the operator enables
the [hosted compiler](operations/hosted-studio.md), the console can build that
bundle. Otherwise, see [workflow authoring](development/workflow-authoring.md)
for local compilation and bundle import.

**Save new revision** updates an existing shared experiment; **Save a copy**
creates another experiment. Each revision stays immutable. If two members edit the same revision,
the second save is refused as a conflict rather than overwriting the first.
Reload the latest revision, review the difference and save again. A measurement
reference can name the exact experiment revision used.

The experiment's creator or community owner can delete an unused saved experiment
to free the storage occupied by all its revisions. Deletion is refused while a
measurement reference names any revision, preserving the source linked to that
result. Deleting an experiment does not delete measurements or their output.

Bundles contain executable programs. The dispatcher checks source structure,
generated-source consistency and hashes, but those checks cannot prove that
arbitrary uploaded WASM was built from its claimed source. Review the publisher
and rebuild unfamiliar source before using it.

## Share measurements deliberately

Personal measurement history stays personal. Choose **Share with community**
on an existing measurement, or select a community project when submitting a new run.
The project collects references to those measurements; it does not create a
second copy of their output or change their original submitting account.

Sharing exposes the complete retained measurement to current community members:
program arguments, destination policy, output, timing, per-run cost and admission
provenance. That provenance can include private executor addresses and host
platform observations. Check what the measurement contains before sharing it.
Session credentials, payment authorization keys and private payment history are
not shared.

Members can inspect a shared group's participants, read output and export
results. They cannot cancel another person's run, delete its payload or reuse
its payment authorization. A personally funded measurement can be unshared by
its sharer or the community owner. Removing that reference removes its sharing
grant; another project reference can still grant access.

Community-funded measurements remain in the funding project's history and cannot
be unshared; attempting to remove their references returns 409. Expired
reservations that admitted no run are cleaned up automatically. Retention limits
and payload deletion continue to apply to the original measurement, so a
reference does not guarantee that output remains available forever.

## Collect useful results

A project's results library collects highlights from its shared measurements:
metrics, tables, charts, text reports and other emitted workflow values. Give a
highlight a name, note and collection label, then follow it back to the run or
its exact saved experiment source. Members can read the project's highlights;
the highlight's creator or community owner can rename or remove one.

A highlight is a reference to retained output, not a separate copy. The original
measurement must remain shared into that project. Unsharing it, removing a
member or deleting its payload removes the corresponding library access.
Deleting a highlight leaves the original measurement and output unchanged.
See [results](results.md) for personal highlights and editing a source copy.

## Pay from the community budget

The owner funds a community so members can submit under its umbrella without
asking the owner to sign each measurement. The **Funding** tab shows funded,
reserved, spent and available amounts. A member selects the project before
reviewing the measurement's quote, then chooses **Run with community funds**.

In a deployment with chain payments enabled, the owner creates a USDC top-up
and approves its payment in their external Sui wallet. Creating a top-up or
knowing a wallet address is not permission to spend from that wallet. Only a
confirmed payment credits the community budget, and the same receipt is credited
once.

The supported chain profile is Sui Testnet. This interface does not yet withdraw
unused deposits. Use test assets for this flow; it is not a production custody
service for real funds.

Deposited funds are held by the dispatcher's payment account. Debuglet does not
store the owner's wallet private key. Members spend the deposited budget; the
dispatcher reserves the full quoted amount atomically before returning an intent,
refuses insufficient funds, and settles or returns the reservation through the
normal run lifecycle. The submitting member remains recorded. This is a shared
budget without individual member spending caps, so invite only members allowed
to use it. See [chain payments](operations/payments.md) for network configuration
and the supported Testnet profile.

In a TEST deployment, the budget draws on the creator's existing TEST allowance.
TEST units are bookkeeping credits, not money. Creating a community grants no
credits, and TEST top-ups are unavailable. If allowances are disabled, community
funding is unavailable. The same allowance covers the creator's personal and
community spending, so separate communities are not separate TEST grants. A run
that executes consumes TEST allowance even if it fails, following the existing
allowance rules; unadmitted expired reservations are released. Personal
measurements keep their existing payment flow.

## Limits and deployment

| Resource | Limit |
| --- | --- |
| Communities owned by one account | 16 |
| Communities joined by one account | 128 |
| Members in one community | 128 |
| Outstanding invitations in one community | 8 |
| Projects in one community | 64 |
| Experiments in one project | 128 |
| Revisions of one experiment | 32 |
| Measurement references in one project | 1024 |
| Result highlights in one project | 1024 |
| Source and optional bundle in one save request | 24 MiB |
| Retained experiment revision bytes in one community | 256 MiB |

Workflow source retains its 1 MiB limit and coordinated experiment source its
4 MiB limit. Community and project names are trimmed and use 1–120 UTF-8 bytes;
descriptions use at most 2000 bytes.
Experiment descriptions use at most 4000 bytes and collection labels at most
120 bytes.

The collaboration API requires HTTP contract 1.23 and the matching console.
Upgrade the dispatcher database explicitly before starting the new dispatcher,
using the deployment's [upgrade and backup procedure](operations/configuration.md#stored-state).
Community records and funding records belong to dispatcher state; no executor
schema or control-protocol change is needed for collaboration itself.
Installing updated source or a console build does not publish a package or update
an existing deployment.

The [HTTP guide](api.md#communities-api-123) describes the routes and access
rules. The [OpenAPI document](../api/openapi.yaml) is the wire contract.
