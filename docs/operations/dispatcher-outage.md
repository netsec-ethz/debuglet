# Recover from a dispatcher outage

Process liveness is insufficient: check the dispatcher's `/readyz`, authenticated
`/metrics`, and `dbl nodes`. An executor is eligible only while its current control
lease is valid. `scheduler.executor_timeout` is the negotiated lease in seconds
(normally 60); loss of network traffic may remain undetected until that lease
expires. Readiness withdrawal and local guest cleanup are separate observations.

1. Inspect `sudo dbl service status --role dispatcher --name local` and the
   dispatcher journal. Check routing, TLS and disk/service errors before restarting.
   During a network partition, wait for authoritative readiness/capacity loss; a
   successful ping or recent heartbeat does not renew execution authority.
2. Restore the failed control path or start the repaired dispatcher with
   `sudo dbl service start --role dispatcher --name local`. Executors reconnect
   with fresh control bindings. Wait for eligible capacity, then submit a new,
   explicitly requested controlled measurement and verify its output.
3. Inspect interrupted runs with `dbl recovery RUN_UUID`. A retained started row
   has an unknown outcome; a retained unstarted row is quarantined. Neither is
   permission to replay. A new session does not inherit the old run's authority.
   See [recovery inspection](recovery-inspection.md) for dated observations.
4. For intentional executor maintenance, use
   `sudo dbl drain --role executor --name worker --wait 30s` and require
   `joined: true`. An incomplete drain does not authorize deleting state or
   upgrading a running writer. Run [doctor](../cli.md) as the service identity
   with its actual configuration and permissions; use `--offline` only after the
   writer has stopped. Resume with `sudo dbl drain --role executor --name worker --resume`.

Connected `dbl cancel RUN_UUID` acknowledges the request, not execution completion.
Check the stored terminal result separately. Partition recovery instead depends
on lease expiry and preserves unknown outcomes; it must not manufacture a
cancellation result. Restore storage only after actual loss/corruption and after
stopping its writers. Foreground backup commands do not support managed systemd
state; ordinary reconnect does not require restoring
or resetting a database.

[Availability monitoring](monitoring.md) has a separate 90-second observation
budget after the fault becomes authoritative, in addition to a silent partition's
lease interval. Its local drill proves alert firing/resolution; it does not prove
external notification delivery.

## Repeat the installed-service drill

[`deploy/systemd/outage-drill.py`](../../deploy/systemd/outage-drill.py) exercises
these transitions against actual installed services. Use only a new, owned,
disposable Ubuntu 24.04/systemd Docker fixture with the full package installed at
`/usr/local`, a `debuglet` service account, Python 3.11 or later, and `iptables`.
Use a private network namespace with `--network none` and no published ports.
The fixture administrator needs `CAP_NET_ADMIN` for a loopback control-port drop;
the Debuglet services retain their empty capability sets. Running systemd as PID 1
also requires the [service profile's](services.md) container hosting setup.
The script explicitly enables `network.policy.local_targets` in this disposable
executor's configuration while stopped, then restarts it. Managed installations
deny loopback targets by default; this controlled local target requires the opt-in.

Pass the host's network namespace identity (`readlink /proc/self/ns/net`, taken
outside the container) as `DEBUGLET_HOST_NETNS`, the installed manifest's exact
source revision as `DEBUGLET_LOCAL_SOURCE_SHA`, and `DEBUGLET_SERVICE_FIXTURE=1`.
Then run the script inside the container. It refuses existing managed roles and
a nonempty OUTPUT firewall chain. The caller must remove the owned container
even if the script fails; never run it against a host or with host networking.

The JSON observations separate connected cancellation, silent-partition lease
loss, readiness recovery and first fresh output. A real socket exchange proves
guest entry and closure before cleanup. A real accepted future-start run must
remain quarantined after its scheduled start. Recovery is observed before drain,
doctor, resume and joined service removal; forced cleanup cannot supply a missing
success observation. These measurements describe this local fixture, not an
operational SLA or proof that earlier remote effects did not occur.

One Ubuntu 24.04/systemd 255 run of installed candidate
`v0.0.0-dev.f1cca5c40b7b` observed connected cancellation socket closure in
0.079 seconds and its stored terminal result in 0.080 seconds. Silent control
loss withdrew readiness and closed the guest socket in 58.908 seconds with the
60-second lease; the executor process stayed running. Dispatcher restart restored
eligible readiness in 0.287 seconds and fresh successful output in 0.752 seconds.
The current lease was already partly elapsed when the packet drop began.
These monotonic timings exclude the later queued-start observation and cleanup.

In this drill the expired active guest closes locally and retains an
unacknowledged terminal record, while its execution row is removed. Recovery
inspection consequently reports `absent` for that execution row; the dispatcher's
outcome remains unknown. Read-only checks after joined drains verify the retained
terminal stays unchanged across executor restart. The queued execution row remains
`retained_unstarted`. Neither observation authorizes replay.
