# API and schema compatibility history

Historical additions below describe the version where each behavior was introduced.
Use [Versions and compatibility](../versions.md) for the current support and upgrade policy.

API 1.9 adds optional durable cancellation inspection. Dispatcher schema 12 stores one cancellation request per run; upgrade explicitly before starting this build. The executor schema and Abort wire protocol are unchanged. Cancellation is never automatically replayed after restart, and requests never acquire a replacement session's authority.

Packet tags follow a versioned [tag specification](../tag-spec.md). Current `main`
introduces `debuglet-tag-v1`, a breaking change of the tag format: tags of
earlier builds do not verify under it. Executors report the version as
`capabilities.tagging.tag_spec`; deploy one version across a fleet and its
verifiers.

API 1.9 also adds executor admission state, operator display metadata and the executor-reported SCION ISD-AS and listeners to `GET /executors`. The control protocol gains an optional `VantagePointReport` without a version change: an older executor leaves these fields unknown, and an older dispatcher ignores the report. The ICMP, fallback-reason, clock and platform probes are further additive fields of `ExecutorCapabilities` and `VantagePointReport` within schema 1, with the same compatibility.

API 1.10 adds optional [account-owned executor enrollment](../operations/executor-onboarding.md). Dispatcher schema 13 stores machine ownership; upgrade explicitly to the packaged schema before starting this build. The executor schema and control protocol are unchanged. Enrollment is disabled until the dispatcher administrator configures its signing authority and connection addresses.

API 1.11 adds the public attribution lookups `GET /attribution/candidates` and `GET /attribution/keys` and deprecates `GET /executors/by-ip` and `GET /executors/{id}/tesla`, which keep working within API major 1. Dispatcher schema 14 stores the attribution history they answer from; upgrade explicitly before starting this build. The control protocol gains the optional `tesla_chain_length` (hello) and `tesla_key_anchor` (heartbeat) fields without a version change; an older peer leaves them empty.

API 1.12 adds measurement profiles, batch details, explicit retry lineage, listener readiness and owner payload deletion. Retry clients require 1.12 so a dispatcher that only supports attribution cannot silently accept a request without retaining its retry identity. Dispatcher schema 15 stores the workflow metadata; schema 16 adds account reservations and payload tombstones.

Dispatcher schema 21 records one settlement per order and the pricing rule of each transaction; this build refuses an older dispatcher database, so upgrade it explicitly before starting this build.

Dispatcher schema 22 records chain payment receipts and outbound chain transfers. The receipt listener and the transfer code depend on it, so this build requires schema 22; upgrade explicitly before starting it. The HTTP API is unchanged.

API 1.15 adds `POST /payment/quote`, the `quote` field of the payment intent response, the `economics` field of `GET /me`, `GET /me/orders`, the usage allowance routes `GET /me/allowance` and `POST /operator/accounts/{id}/allowance`, the `allowance_exceeded`, `allowance_out_of_range` and `conflict` error codes, and `GET /operator/executors/{id}/earnings`. The Go client requires 1.15 for these routes.

Dispatcher schema 23 records usage allowance grants in `allowance_grants`. The allowance routes and the capped intent depend on it, so this build requires schema 23; upgrade explicitly before starting it.

API 1.16 adds RIPE Atlas-style addressing to `GET /executors`: `is_public`, `address_v4`, `address_v6`, `prefix_v4`, `prefix_v6`, `asn_v4`, `asn_v6` and `address_observations`, and records the same fields as `addressing` in the result's admission snapshot (within result format 1.1, schema 1). The control protocol gains the optional `VantagePointReport.address_opt_out` without a version change: an older executor is public, and an older dispatcher ignores the field. Executors make the existing `ReflectAddress` call over each family to be observed in both; an older dispatcher answers it as before.

API 1.17 adds RIPE Atlas-style `status`, `status_since`, `first_connected`, `last_connected`, `total_uptime` and `tags` to `GET /executors`, and its `status` query parameter. The Go client's `Probes` requires 1.17; `Nodes` does not. The control protocol gains the optional `VantagePointReport.host_tags` and `address_check` without a version change: an older executor has no host tags and no NAT or DNS tags, and an older dispatcher ignores them.

Dispatcher schema 24 stores the executor status history in `probe_status` and `probe_addresses`, filling `probe_status` from the recorded TESLA chains. The executor listing reads it, so this build requires schema 24; upgrade explicitly (`make deploy-upgrade-db`, or `-upgrade-database`) before starting it.

API 1.19 adds recorded destination policies: `PATCH /destination` accepts `denied`, `reason` and `expires_at`, and `GET /destinations` lists the current policy of each destination. Dispatcher schema 26 stores their append-only history; upgrade explicitly before starting this build. The control protocol gains the optional `DestinationLimit.denied` field without a version change; an executor that does not know it still applies the zero limit sent with it, and an executor that knows it closes the active sockets to the destination.

API 1.23 adds [communities](../communities.md), shared projects and experiment
revisions, explicit measurement sharing and a community-funded submission option.
Current membership grants read access to shared measurement details and output;
mutation ownership and private payment access are unchanged. `can_manage` on
measurement and run details lets clients hide owner-only actions. Older servers
omit it. Dispatcher schemas 32 and 33 store collaboration and shared funding;
upgrade explicitly before starting this build. Executor schema and the control
protocol are unchanged by this feature.

API 1.20 adds `admission` and `drain_status` to account-owned executor inventory.
Admission reports the current control readiness and dispatcher maintenance.
Drain status is explicitly unknown because the existing control protocol does
not observe joined host service shutdown. No schema or control-protocol change
is required. Older servers omit these observations; clients show them as unavailable.

API 1.24 adds optional authenticated hosted workflow and coordinated experiment
validation and compilation under `/studio`. Existing browser sign-in and CSRF
protection apply. The dispatcher uses a separately configured local compiler
worker; compilation is unavailable until the operator enables it. Builds return
portable bundles without submitting or executing them. Request admission and
compiler capacity are bounded, with prompt 429 responses when busy. No database
schema or control-protocol change is required by hosted compilation.

API 1.25 adds `chain_renewing` to executor attribution discovery. Upgrade the
dispatcher and console before executors so that discovery recognizes the reason.
Executors renew automatically through their normal registration after accepted
work, used-key disclosures and result delivery finish; new admission pauses
until then. Renewal requires the dispatcher's durable disclosure receipts and
fails closed if an older dispatcher does not provide them. No database schema
or control-protocol field changes are required.

API 1.26 adds optional `supported_host_functions` to executor capabilities.
The list identifies optional runtime exports such as
`debuglet_io_v1.hop_probe`; missing or expired reports do not establish support.
Builders compare their compiled bundle's requirements with a fresh report
before selecting an executor. The binary version remains separately visible;
version strings alone do not establish runtime compatibility. Transport policy,
listener readiness and destination admission still apply even when an export
is present. Older guests keep their existing imports and behavior. This is an
additive control-protocol field within capability schema 1; no database change
is required.

API 1.26 also adds authenticated `POST /me/presence`, reporting the number of
unique signed-in accounts active during the last 120 seconds. The observation
resets when the dispatcher restarts and does not disclose account identities.

API 1.27 adds personal and project result highlights and immutable builder-source
attachments. Highlights reference authorized retained workflow events and do not
create another output archive. Source reads return the exact attached document
or an accessible community revision; opening a copy does not execute it.
Dispatcher schema 34 stores these references and attachments, so upgrade the
database explicitly before starting this build. Executor schema and control
protocol are unchanged by this feature.

API 1.28 adds account-owned workflow and experiment templates. Dispatcher schema
35 stores their editable source separately from runs. Existing community
experiments remain the shared template format.

API 1.29 adds optional model-assisted authoring at `GET/POST /studio/assistant`.
It proposes validated editable graphs or asks for clarification; it never builds,
executes or submits a measurement. It is disabled until an operator configures a
provider, model and private credential. Existing schemas and control/guest
interfaces are unchanged.
