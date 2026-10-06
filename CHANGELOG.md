# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Only `[Unreleased]` changes between tags. Release entries summarize user-visible
changes; the linked API and deployment documentation contains operational detail.

## [Unreleased]

## [0.3.0-rc.1] - 2026-10-06

### Security
- Releases are signed. The production release signer is
  `releases@debuglet.netsec.ethz.ch` (Ed25519,
  `SHA256:vETQG+wE6uwMv4MBFfx7dxo8IWpvR8z6/Sw7MT2WwQo`); its trust file is
  `configs/release-allowed-signers`. See
  [Signed releases](docs/operations/releases.md#production-signer).
- The TESLA disclosure delay is configurable and at least two epochs.
  Previously the key of epoch i was disclosed shortly after epoch i+1 began,
  while verifiers accepted epochs t-1, t and t+1 for a packet of epoch t.
  Anyone who had seen k_i could therefore forge tags that verify for packets
  they timestamp in epoch i+1.
  - The executor now discloses k_i at the start of epoch i+d.
    `[tesla] disclosure_delay_epochs` sets d; 0 derives the smallest d
    covering 15 minutes (90 epochs at the default 10-second epoch), and an
    explicit value below 2, or with less than 10 s of margin
    ((d − 1) × epoch length), is refused. The installed-key hold still applies.
  - A restart starts a new chain, so the keys of the last d epochs before it
    are never disclosed and those packets cannot be verified; the chain
    exhaustion log names `final_disclosure_at`, the time after which a
    restart loses nothing.
  - The dispatcher rejects a disclosure before its epoch plus d (with 5 s of
    skew) and logs the executor once as misbehaving. An executor that does
    not report d is treated as d = 1.
  - `tools/verify_pcap.py` tries only epochs t and t-1. It refuses a
    schedule with d < 2 or without d, and a key that could have been public
    at capture time plus `--clock-tolerance`.
  - The browser verifier in debuglet-website needs the same change.
  - See `docs/operations/configuration.md#executor-tesla-key-schedule`.

### Added
- API 1.17: RIPE Atlas-style status history and tags in `GET /executors`:
  `status` (`connected`, `disconnected`, `abandoned` after 30 days
  disconnected, `never_connected` for enrolled executors that never
  registered) with `since`, `status_since`, `first_connected`,
  `last_connected`, `total_uptime` and `tags`. `?status=` also lists
  executors that are not connected; the default listing is unchanged.
  Host tags come from a fixed vocabulary in `[metadata] host_tags`, also
  settable with `dbl executor join --host-tag`. System tags are derived:
  `system-ipv4/ipv6-works` and `-capable`, `system-ipv4-rfc1918` (the
  executor reports only whether its local IPv4 source is RFC 1918),
  `system-ipv4/ipv6-stable-1d/30d/90d` from the address history and
  `system-resolves-a/aaaa-correctly` from the executor's address observation
  of the dispatcher name. `dbl nodes` adds `--status` and the `STATUS` and
  `TAGS` columns; the Go client adds `Probes`. Dispatcher schema 24 stores
  the history (`probe_status`, `probe_addresses`) and fills it from the
  recorded TESLA chains; this build requires it, so upgrade the dispatcher
  database explicitly (`make deploy-upgrade-db`) before starting it.
- API 1.16: RIPE Atlas-style probe addressing in `GET /executors`. Each entry
  reports `is_public` and the last dispatcher-observed `address_v4` and
  `address_v6` with their `prefix_v4/v6` and `asn_v4/v6` from the offline ASN
  database, and `address_observations` (`via` control or reflection,
  `observed_at`, lookup source and reason). Only addresses the dispatcher saw
  on the executor's authenticated connections are listed, never
  `public_host`. Executors call the existing address reflection over each
  family every 10 minutes, resolving their `dispatcher.addr` and verifying the
  dispatcher certificate, so both families are observed without a configured
  reflector (`[connectivity] observe_addresses = false` turns this off).
  `[metadata] address_opt_out = true` makes an executor private: its
  addresses are withheld from everyone but operators, while prefix, ASN and
  location stay public, as for a private RIPE Atlas probe. It is independent
  of `location_opt_out`. Results record the same fields in
  `provenance.vantage_point.addressing`. `dbl nodes` adds `ADDRESS_V4` and
  `ADDRESS_V6` columns. **Privacy:** executors are public by default,
  including executors that predate the setting, so their control-connection
  address, operator-only until now, is listed once the dispatcher is
  upgraded. To keep one private, upgrade it and set `address_opt_out`
  before the dispatcher is upgraded
  (`docs/vantage-points.md#privacy`).
- Executor ASN and prefix from RIPE RIS, the method RIPE Atlas uses for its
  probes: the origin AS of the longest matching prefix announced in BGP.
  `debuglet-dispatcher -build-asn-database PATH` downloads RIS's daily whois
  dumps and RIPE's AS names, keeps (origin, prefix) pairs at least
  `-ris-min-peers` RIS peers see (default 10), attributes a prefix with
  several origins to the one the most peers see (lowest AS number on a tie),
  and atomically replaces PATH with a GeoIP2-ASN-compatible MMDB it has
  verified through the dispatcher's own loader. Values carry
  `database:Debuglet-RIS-ASN@<dump generation time>` and the announced prefix
  (the new optional `announced_prefix_length` record key). Short downloads,
  failed gzip checksums, dumps without their end marker or older than
  `-ris-max-age`, and near-empty tables are refused and the existing file is
  kept. An AS that RIPE does not name now has an empty `name` instead of an
  `invalid_record` lookup.
- The dispatcher reloads a replaced `[metadata]` database without a restart:
  it checks the configured paths every minute, verifies a new file as at
  startup and keeps the previous database (logging once) if it fails.
  Executors registering afterwards are looked up in the new file; registered
  executors and admitted results keep their values and source.
- Deployment: the `debuglet-ris-asn` systemd timer rebuilds the ASN database
  daily on the dispatcher host, and the first build runs during deployment.
  Enabled for prod and dev with `dispatcher_ris_asn_enabled`; the dispatcher
  host needs HTTPS access to `www.ris.ripe.net` and `ftp.ripe.net`. No city
  database is configured: location comes from the operator. See
   `docs/operations/executor-discovery.md#asn-and-prefix-from-ripe-ris`.
- `dbl verify` and `client.Verify`: offline probe verification (#73,
  `docs/verification.md`, delivery step 3). `client.ReadCapture` reads pcap
  and pcapng (Ethernet, raw IP, Linux SLL/SLL2, loopback) up to 64 MiB and
  1 000 000 packets and rejects malformed or truncated captures. Packets are
  grouped by source address and epoch and checked against the public
  attribution history (API 1.11) without an account and without uploading
  them; each group is `verified`, `invalid`, `pending` (with the disclosure
  time to retry after), `missing` or `unsupported`, with a machine reason,
  match and non-match counts, a false-match bound and ambiguity reported.
  Tag spec section 6 applies: epochs t and t-1 only, d < 2 and legacy
  (tag_spec 0) chains refused, and no key that could have been public at
  capture time plus 1 s. Work is capped (1 000 000 tag computations, 1024
  lookups, one hash walk per chain); `--source` restricts a capture to the
  probe addresses before any lookup. `--evidence` writes a format-1 evidence
  bundle, which `dbl verify evidence.json` and `client.VerifyEvidence` check
  again offline; its schedules are not authenticated until #71(b). Exit  status 0 verified, 1 error (including usage errors), 2 invalid, 3
  inconclusive, 124 timeout.
  A group whose packets reproduce different runs (one executor measuring
  toward one recipient twice at once) is split into a verified entry per
  run instead of being rejected; packets of a split group that match no run
  are `unsupported: unmatched`, and a group is `invalid` only when none of
  its packets matches. Split entries carry the whole group's counts
  (`split`, additive within evidence format 1), and the false-match bound
  N·C(n, k)·(2·2⁻¹⁶)^k counts the candidates tried and the packets picked.
  Lookups are paced to the dispatcher's rate limit (10 per second, burst
  40, configurable in `VerifyOptions`); a `429` is retried after its
  `Retry-After` until the context ends, and then `Verify` returns a
  `RateLimitedError` naming the unchecked groups. `HTTPError.RetryAfter`
  carries the delay of a 429 or 503.
  The pure tag functions moved to `pkg/tagspec`, which the taggers and the
  verifier share; tests cross-check the shared vectors with `verify_pcap.py`.
- API 1.10: account-owned executor enrollment and `dbl executor join`, with
  optional systemd installation that preserves the enrolled identity. Enrollment
  stays disabled until configured. This build requires dispatcher schema 13,
  including when enrollment is disabled; back up and explicitly upgrade the
  database before restarting. See [executor onboarding](docs/operations/executor-onboarding.md).
- Durable attribution history and public verification lookups (part of #71
  and #73; `docs/verification.md`, delivery step 2). Dispatcher schema 14
  records every TESLA chain an executor announces, each disclosed key that
  verified against it (once), and each run's interval and source address. A
  dispatcher restart no longer loses disclosed keys, and earlier chains stay
  verifiable. The history is pruned after `[attribution] retention_days`
  (default 90; 0 or unset also means 90); upgrade the database explicitly before starting this build.
  - API 1.11: `GET /attribution/candidates?ip=&at=` lists the runs active
    from an address within one epoch of a time (at most 32) with their chain
    schedule `{chain_id, k0, t0_unix_ns, epoch_seconds,
    disclosure_delay_epochs, chain_length, tag_spec}`, `disclosed_through`,
    `disclosed_through_at_ns`, `next_disclosure_at_ns` and `retained_from`.
    `tag_spec` is what the executor reported when it registered the chain:
    1 for `debuglet-tag-v1`, 0 (legacy, unsupported under v1) otherwise.
    `GET /attribution/keys?executor_id=&chain_id=` pages the disclosed keys
    of a chain, 1024 epochs at a time. Both need no account, name runs and
    executors but never accounts, and are rate-limited per client address
    (`429 rate_limited`, a new error code); `[attribution] trusted_proxies`
    lets the limit count clients by `X-Forwarded-For` behind listed proxies.
  - `GET /executors/by-ip` and `GET /executors/{id}/tesla` are deprecated;
    they keep working within API major 1.
  - `pkg/client` gains `AttributionCandidates` and `AttributionKeys`, which
    work without a credential. `tools/verify_pcap.py` uses the new routes and
    falls back to the deprecated ones on an older dispatcher.
  - The control protocol gains `HelloResponse.tesla_chain_length` and
    `HeartbeatRequest.tesla_key_anchor` without a version change. The
    dispatcher verifies a key naming an earlier recorded chain against that
    chain, so a restarted executor could disclose its previous chain's tail;
    the executor does not do so yet.
- Executor capability reports carry an `attribution` state, shown by
  `GET /executors` and in the new `ATTRIBUTION` column of `dbl nodes`:
  `available`, or `unavailable` with `epoch_zero`, `chain_exhausted`,
  `refresh_failing` or `disclosure_held`, plus the installed epoch, the last
  successful kernel key refresh, a short refresh error and since when
  disclosure is held. The field is additive within capability schema 1; older
  executors report none, which means unknown. A changed reason is reported on
  the next heartbeat. See `docs/operations/executor-discovery.md`.
- Executor capability reports carry a `tagging` mode per address family and
  for SCION, e.g. `{"ipv4": "ebpf", "ipv6": "none", "scion": "none"}`
  (`ebpf`, `userspace` or `none`), shown by `GET /executors` and recorded in
  the result's `provenance.vantage_point` capability snapshot. The field is
  additive within capability schema 1 and result format 1.1; `null` means
  unknown. It is the node's capability, the mode a run is set up to get, not a
  per-run measurement. See `docs/operations/executor-discovery.md#tagging-mode`.
- `debuglet-dispatcher -check-database` and `debuglet-executor -check-database`
  report read-only whether the configured database is current for the build
  (exit 0), needs the upgrade (3) or needs an upgrade that drops the recorded
  runs and their logs (4). `-upgrade-database` refuses such an upgrade unless
  `-accept-data-loss` is given. Both modes name the absolute database path.
- Portable result format 1.1: admission records `provenance.vantage_point`,
  the executor's capability report (with its receipt time and whether it was
  stale), the control connection's source IP and the executor's `public_host`.
  Every value carries a `source` label (`operator`, `executor-reported`,
  `dispatcher-observed`); none means verified, and unrecorded values are null.
  Exports are written as 1.1; `client.ReadResult` and `dbl` still read 1.0 files
  and reject a 1.0 file carrying a vantage point. Older readers reject 1.1
  exports. See `docs/results.md`.
- API 1.9: `GET /executors` reports `admission` (`ready`, `maintenance`,
  `offline`), operator display metadata (`display_name`, `city`, `country`,
  `network`) from new optional `[executors."<id>"]` dispatcher configuration
  tables, and the executor-reported SCION ISD-AS and listener transports, each
  with a source label. Executors send them in a new `VantagePointReport` beside
  the capability report. `provenance.vantage_point` gains `scion_isd_as` and
  `display` within schema 1; earlier 1.1 files remain valid. `dbl nodes` shows
  the new columns, and `dbl nodes`, `dbl run` and `ExecutorFilter.ISDAS` filter
  by ISD-AS. See `docs/operations/executor-discovery.md`.
- Executors probe their host at startup and with every capability report.
  `capabilities.icmp` reports whether a raw ICMPv4 socket opens (`available`,
  or `unavailable` with `disabled`, `not_permitted`, `ping_socket_only` or
  `unsupported`); the probe is repeated instead of cached for the process
  lifetime, and `network.policy.icmp = false` still switches ICMP off.
  `capabilities.enforcement_reason` says why the fallback counter is used.
  A new `clock` field in `GET /executors` reports the kernel clock state
  (`synced`, `unsynced`, `unknown`) and its error estimates read with
  `adjtimex`, graded `degraded` above the new executor setting
  `clock.max_error_ms` (default 100 ms). The host platform (OS, architecture,
  kernel, CPUs, memory, build version) is operator-only: it is never listed and
  is recorded only in result provenance. `provenance.vantage_point` gains
  `clock` and `platform`, and its capability report gains `icmp` and
  `enforcement_reason`, all within schema 1 and labelled `executor-reported`.
  `timing.clock_uncertainty_ns` stays null.
- `dbl doctor` checks the kernel clock against the executor's
  `clock.max_error_ms` instead of reporting `clock: not_checked`: synchronized within the bound passes; unsynced or
  above the bound stays `not_checked` with the reason (the executor admits
  runs with degraded clock readiness); non-Linux hosts remain `not_checked`.
- Operator `/metrics` adds executor daemon resources, owned TCX counter
  attachment presence and the dispatcher-side disclosure delivery lag;
  `deploy/monitoring/health-alerts.yml` alerts on low executor state storage
  and on a disclosure lag above 90 s or unknown
  (`docs/operations/metrics.md`, `docs/operations/monitoring.md`).

### Changed
- Ended run windows now record local allocation reclamation separately from
  workload outcomes and payment settlement. Recovery inspection exposes the
  optional `allocation_reclaimed_at` timestamp (API 1.14); dispatcher databases
  require the explicit upgrade to schema 19. Retained-work quotas stay charged
  until actual retirement is confirmed.
- Destination updates use acknowledged session revisions with current executor
  releases, retry pending application on heartbeat, and report allocation
  delivery failures. Legacy peers can still allocate runs but require an upgrade
  to confirm ordered live destination changes.
- **Breaking: packet tags follow the versioned specification
  `debuglet-tag-v1`** ([docs/tag-spec.md](docs/tag-spec.md)); tags written by
  earlier builds do not verify under it and v1 tags do not verify with earlier
  verifiers. Both taggers and `tools/verify_pcap.py` now use standard
  SipHash-2-4 including the final partial block (the unversioned tag dropped
  it), and hash a canonical input that also zeroes TOS, flags and fragment
  offset, TTL, IP options and the ICMP, TCP or UDP checksum, so tags survive
  routing and checksum offload. The input is the first min(64, Total Length)
  bytes. The taggers set DF on every tagged packet and leave IPv4 fragments,
  and malformed or short packets, untagged. The kernel tagger acts only on
  packets the kernel classifies as IPv4, so an IPv6 or ARP frame whose
  destination MAC starts with the nibble 4 is no longer mistaken for a raw
  IPv4 header and rewritten. Upgrade every executor and
  verifier together; mixed-version fleets are not supported.
- Executor capability reports carry `tagging.tag_spec` (`debuglet-tag-v1`),
  shown by `GET /executors` and recorded in a result's
  `provenance.vantage_point` capability snapshot, so evidence names the tag
  algorithm. The field is additive within API 1.9, capability schema 1 and
  result format 1.1; absent means unknown (a pre-v1 executor).
- `tools/verify_pcap.py` states the specification applied to every packet and
  reports packets v1 does not cover (IPv6, IPv4 fragments, captures shorter
  than the 64-byte input, malformed headers, an executor announcing another
  `tag_spec`) as unsupported with the reason, instead of as unmatched; IPv6
  packets in a capture are listed rather than dropped. Several matching
  candidates are flagged as ambiguous.
- Known-answer vectors `testdata/tag-vectors-v1.json`, generated by the
  independent Python reference `tools/tag_vectors.py` (checked against the
  published SipHash-2-4 vectors), are read by the Go tests, the new required
  kernel test `TestKernelTagVectorsV1` of the committed `tagger.c` object and
  `tools/test_verify_pcap.py`. They include the first signing epoch: the
  public anchor's tag differs from the accepted epoch-1 tag.
- The committed `tagger_bpfel.o` is now built with the pinned CI tools image
  (`debuglet-ci-tools:20260623-1`, clang 14.0.6). The objects previously on
  `main` did not match that toolchain: regenerating them there gave different
  bytes for both `tagger_bpfel.o` and `count_bpfel.o`. `count_bpfel.o` is
  unchanged in this release.
- The executor's `[tesla] delay` key is renamed `epoch_seconds`: it always was
  the epoch length, not a delay. `delay` is still read when `epoch_seconds`
  is unset, with a deprecation warning; setting both is an error. The
  Ansible variable `tesla_delay` is likewise `tesla_epoch_seconds`, and
  `tesla_disclosure_delay_epochs` is new. Configuration errors name the field
  and its allowed range.
- The executor hello carries `tesla_disclosure_delay_epochs` (protocol field
  20). `GET /executors/:id/tesla` adds `epoch_seconds` (`delay_sec`, with
  the same value, is deprecated), `disclosure_delay_epochs`,
  `disclosure_delay_seconds`, `next_disclosure_epoch` and
  `next_disclosure_at_ns`. The change is additive within API 1.9.
- A run whose packets the eBPF tagger attributes refuses IPv6 destinations and
  peers instead of sending them untagged, and binds its TCP and UDP listeners
  to IPv4 only; a dual-stack name is dialled on its IPv4 addresses. Such a
  node with an IPv6 `public_host` literal refuses TCP and UDP listeners and
  does not advertise them. The guest
  sees `denied`, and a failed run reports `destination refused: IPv6 not tagged
  on this executor`. Runs with the pure-Go tagger keep IPv6. SCION traffic
  stays permitted and is reported untagged (`tagging.scion = none`), since its
  sockets cannot be marked.
- `install.sh` prints the `export PATH=...` line to use when the installed
  `bin` directory is not on `PATH`.
- Lead the README with a published installation and organize versioned
  references under `docs/`; keep user and operator procedures in the Wiki.
- `deploy/ansible/upgrade-database.yml` checks each database with the candidate
  before stopping its service and leaves a current host running without a
  backup; with `debuglet_manage_services=false` it requires
  `upgrade_confirm_stopped=true`, before a destructive upgrade
  `upgrade_accept_data_loss=true`, and before stopping the service twice the
  database's size free. `deploy/README.md` documents the order and the cleanup
  of `backup-*` directories.
- The refusal of an absent database names the deployment seeding step and the
  local-service copy a hand-installed host uses, instead of `make upgrade`;
  `docs/operations/configuration.md` describes creating and upgrading a database.
- Reject `_` in DNS names in daemon configuration (`server.bind_host`,
  `dispatcher.addr`, `dispatcher.yamux_addr`, `tls.server_name`,
  `network.public_host`), matching `dbl validate`. Both now apply the RFC 1123
  host-name rules documented in `docs/operations/configuration.md`.

### Fixed
- A TESLA key is disclosed only after every kernel tagger has moved off it,
  including the last key at the end of the chain. The kernel key refresh runs
  at each epoch boundary instead of every half epoch; a delayed or failed
  refresh delays disclosure instead of leaving a disclosed key installed.
- The executor reports "TESLA key chain nearly exhausted" and "TESLA key
  chain exhausted" once per process; a reconnected control session no longer
  repeats them.
- Answer `400 unknown_executor` when a submission names an executor that is
  not registered or no longer available at admission, and `400 invalid_policy`
  when the policy requires ICMP or a listener the executor cannot serve; these
  answered `500 internal_error` before.
- Classify a run that is still not terminal about two minutes after the end
  of its reserved window as `RunStateExited` with an `outcome unknown` error,
  releasing its reservation once. A cancellation the dispatcher could not
  deliver marks the run `RunStateUnreconciled`, and restart no longer reserves
  capacity for runs whose window already ended. `docs/api.md` describes states.
- Serialize ordinary destination-limit deliveries per executor. A timed-out
  in-flight delivery can still apply after its successor; wire-version ordering
  and durable retries remain unsupported. Failed recipients are named in
  operator logs; `PATCH /destination` returns a fixed delivery-failure message.
- Refuse a destination limit below the floors reserved for admitted runs
  whose window lies ahead, not only below the floors of active allocations
  (`PATCH /destination` answers 409 `capacity_exhausted`).
- Verify each TESLA key an executor discloses on its heartbeat against its
  chain anchor before storing it, hashing forward from the last verified key.
  A key that does not verify, lies ahead of the chain's registered schedule
  or more than one week of epochs past it, or
  differs from the key stored for its epoch is dropped and logged once per
  chain; an older epoch is ignored. The heartbeat itself still succeeds.
- Listener sockets of a run are marked for packet attribution before they
  bind and listen, so a SYN-ACK and every accepted connection carry the
  run's mark; a refused mark fails the listener instead of trying the next
  port.

### Known limitations
- Chain payments (USDC on Sui: payouts, refunds and receipt reconciliation)
  are not part of this release and are not supported. Every shipped
  configuration keeps `[sui] disabled = true`; leave it so. `TEST` payments
  and allowances work as before. The payment schema migrations are included
  and are applied by the database upgrade either way.
- Production executors tag packets only once deployed with the capabilities
  in `executor_capabilities` (`cap_net_admin,cap_net_raw,cap_perfmon,cap_bpf`);
  check `tagging.ipv4` in `GET /executors`. Capability reports can say
  `attribution: available` while `tagging.ipv4` is `none`.
- An executor whose clock is unsynchronized keeps tagging, a restarted
  executor never discloses the last d keys of its previous chain, and
  destination opt-outs are not yet durable. Server-assisted verification of
  packets newer than the disclosure delay (about 15 minutes) is not
  available: such packets verify as `pending`.
- The browser verifier on the website still implements the pre-v1 tag
  scheme; use `dbl verify` or `tools/verify_pcap.py`.

## [0.2.0] - 2026-09-27

### Added
- Add the `dbl` CLI, Go SDK, OpenAPI contract, browser login, managed services,
  backed-up database upgrades, and verified Linux amd64 packages.

### Changed
- Move the debuglet examples from `local/wasm_samples/` to `examples/debuglets/`,
  the local daemon configurations from `local/configs/` to `configs/`,
  `verify_pcap.py` to `tools/`, and the illustrative HTTP exchanges to
  `api/http-examples.json`. Update `make wasm SAMPLE_DIR=...` and `-config`
  paths accordingly.
- Require account-backed sessions, canonical lowercase run IDs, and HTTP API 1.3.
- Use verified TLS control channels and preserve the recorded release during
  configuration-only deployments.

### Fixed
- Preserve completed work and deployment state across restarts; continue
  deploying reachable executors.
- Harden database upgrades, credentials, certificate validation, SCION metadata
  handling, and fallback packet accounting.

### Removed
- Remove the unsupported JavaScript and Python debuglet samples and the Javy
  build path of `make wasm`.

### Known limitations
- SCION traffic is not attributed to runs, and the web dashboard is not fully
  compatible with authenticated sessions.
- Packages are Linux amd64 only; local state is package-version-specific and
  interrupted runs are not recovered.

## [0.2.0-rc.3] - 2026-09-26

### Changed
- Keep the HTTP API at `1.3`; the `rc.2` changelog incorrectly said `1.2`.
- Use tc `clsact` when TCX is unavailable. The pure-Go fallback now tags IPv4
  UDP and ICMP with SipHash-2-4 and `CAP_NET_RAW`; TCP, TLS, and SCION remain
  untagged in this mode.
- Require lowercase canonical run IDs in the API, CLI, and Go client.
- Configuration-only deployments now preserve the release recorded on each
  host and reject conflicting version overrides.

### Fixed
- Continue deploying other executors when one host becomes unreachable.
- Handle invalid SCION path indices and missing metadata without panicking.
- Reject expired or not-yet-valid executor client certificates at startup.
- Flush credentials, local state, and managed-service files before atomic
  replacement to prevent empty or truncated files after a crash.
- Use the selected environment's SSH `known_hosts` file in maintenance tasks.
- Release completed runs from the eBPF bandwidth-counter map.
- Enforce SQLite foreign keys, briefly wait for locks, and write payment intent
  data atomically. Database upgrades report existing invalid rows.

### Removed
- Remove unused verification scripts superseded by `dbl`, `pkg/client`, and
  `verify_pcap.py`.
- Drop big-endian eBPF artifacts and executor builds; supported Linux targets
  are little-endian.

### Known limitations
- SCION traffic is not attributed to runs.
- The web dashboard is not fully compatible with authenticated sessions; use
  `dbl` or `pkg/client` for complete workflows.
- Packages are Linux amd64 only. Local state is package-version-specific, and
  interrupted runs are not recovered.

## [0.2.0-rc.2] - 2026-09-25

### Added
- Add GitHub browser login with OAuth PKCE and deployment-specific credentials.
- Add backed-up database upgrades for deployed wallet-free TEST state. Before
  deploying, run `make deploy-upgrade-db DEPLOY_ENV=<env>`.

### Changed
- Advance the HTTP API to `1.3` for GitHub browser login routes.
- Reject request bodies over 32 MiB and invalid or duplicate payment batches.
- Make run submission idempotent and charge timeout prices by rounded-up
  milliseconds.
- Return stable cancellation errors, report unready services with exit code 4,
  and reject destination limits below admitted capacity.

### Fixed
- Do not refund refused resubmissions whose orders already have runs.
- Charge the full datagram size when the receiving buffer truncates it.

### Schema
- Allow populated dispatcher databases at schema 3 to upgrade through migration
  00004. Databases already past schema 4 are unchanged.

### Known limitations
- SCION traffic is not attributed to runs. The dashboard remains incompatible,
  packages are Linux amd64 only, local state is package-version-specific, and
  interrupted runs are not recovered.

## [0.2.0-rc.1] - 2026-09-25

### Added
- Add the `dbl` CLI, Go SDK, OpenAPI contract, and packaged local demo.
- Add managed dispatcher/executor services, drain and readiness operations, and
  verified Linux amd64 packages.
- Add accounts, expiring sessions, recovery, operator roles, executor
  enrollment, and per-owner authorization.
- Add reproducible CI and isolated, verified development/production deployment.

### Changed
- Replace UUID client identity with account keys and server-issued sessions.
- Version HTTP (`1.2`), binary, and executor-control compatibility separately.
- Bundle services, CLI, migrations, sample module, installer, manifest, and
  checksums in one release archive.
- Require fresh local state between versions and make production deployment an
  explicit operator action.

### Security
- Bind executor sessions to enrolled identities and short leases with mutual TLS.
- Enforce account authorization, destination policy, and traffic accounting.
- Harden installation, configuration, process ownership, credentials, errors,
  shutdown, and artifact verification.

### Fixed
- Bound executor registration handshakes, preserve completed work across
  restarts, and isolate unreachable hosts during deployment.
- Make versions, certificate identities, interpreters, and fallback packet
  counting explicit and verifiable.

### Known limitations
- The dashboard is incompatible; use `dbl` or `pkg/client`.
- Packages are Linux amd64 only. Database upgrades and interrupted-run recovery
  are not supported in this candidate.

## [0.1.0] - 2026-09-17

### Added
- Initial public release.

[Unreleased]: https://github.com/netsec-ethz/debuglet/compare/v0.3.0-rc.1...HEAD
[0.3.0-rc.1]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0...v0.3.0-rc.1
[0.2.0]: https://github.com/netsec-ethz/debuglet/compare/v0.1.0...v0.2.0
[0.2.0-rc.3]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0-rc.2...v0.2.0-rc.3
[0.2.0-rc.2]: https://github.com/netsec-ethz/debuglet/compare/v0.2.0-rc.1...v0.2.0-rc.2
[0.2.0-rc.1]: https://github.com/netsec-ethz/debuglet/compare/v0.1.0...v0.2.0-rc.1
[0.1.0]: https://github.com/netsec-ethz/debuglet/releases/tag/v0.1.0
