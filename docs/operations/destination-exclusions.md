# Executor rate and destination policy

New executor configurations default to **100,000,000 bit/s (100 Mbps)**. This is
both the advertised capacity and the local fair-share ceiling. The runtime,
`dbl executor join`, example configs and Ansible defaults agree. Earlier joins
used 10 Mbps; existing saved configurations and certificate renewal keep their
explicit capacity. Operators can still choose a lower or higher value.

The application limiter accounts guest bytes with a token bucket and permits its
configured initial burst. In fallback mode it is not an exact packet/wire-rate
limit: headers, retransmissions and traffic outside the guest are not equivalent
to accounted payload bytes. Check the reported enforcement mode before using a
node for measurements that depend on packet accounting.

## Initial public-network exclusions

The default `network.policy.denied_destinations` is the following deliberately
small list. ARIN allocation and registrant records were checked on **2026-11-16**.
These are allocation-based exclusions, not evidence of the current use of every
address. They do not identify all military networks, countries or IPv6 ranges.
There is no automatic classifier or remote list downloaded at startup.

| CIDR | ARIN allocation | Registered organization |
| --- | --- | --- |
| `6.0.0.0/8` | [CONUS-YPG-NET](https://rdap.arin.net/registry/ip/6.0.0.0), NET-6-0-0-0-2 | [Headquarters, USAISC](https://rdap.arin.net/registry/entity/HEADQU-3) |
| `7.0.0.0/8` | [DISANET7](https://rdap.arin.net/registry/ip/7.0.0.0), NET-7-0-0-0-2 | [DoD Network Information Center](https://rdap.arin.net/registry/entity/DNIC) |
| `11.0.0.0/8` | [DODIIS](https://rdap.arin.net/registry/ip/11.0.0.0), NET-11-0-0-0-2 | [DoD Network Information Center](https://rdap.arin.net/registry/entity/DNIC) |

The existing policy guards apply the list to literals, DNS resolutions and
IPv4-mapped IPv6 addresses. Reserved/private/link-local destinations remain
blocked separately. `local_targets = true` only permits loopback for local tests;
it does not permit private networks. A destination permitted by operator policy
must also be declared in the experiment's admitted destination set.

## Operator configuration

An omitted `denied_destinations` uses the initial list. An explicit string
**replaces** it, so include the initial prefixes when adding your own opt-outs:

```toml
[resources]
capacity = 100000000

[network.policy]
local_targets = false
denied_destinations = "6.0.0.0/8,7.0.0.0/8,11.0.0.0/8,opted-out.example"
```

Explicit `denied_destinations = ""` clears this additional list while preserving
reserved-address protection. Existing explicit lists are not silently rewritten.
New joins pin the initial list in `service.toml`; certificate renewal preserves it.
Recheck allocation sources when changing the list, record a review date, and
apply additions through normal configuration review and executor restart.

Managed fleets use `executor_capacity`, `executor_denied_destinations`,
`executor_permitted_ports`, and the boolean `executor_policy_tcp`, `_tls`, `_udp`,
`_icmp`, `_scion`, `_inbound` and `_local_targets` inventory variables. The public
default disables local targets and SCION; it enables the supported IP transports.
Use host variables for explicit operator overrides. The local demo configs enable
loopback explicitly.

Before opening a public fleet, its owner must publish an accountable reporting
contact and agree who handles destination opt-outs. No reporting identity is
assigned by these defaults. Follow [abuse reports and destination opt-outs](abuse-response.md)
for approval, dispatcher denial, delivery confirmation and receiver verification.
