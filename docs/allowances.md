# Debuglet credits

Debuglet credits pay for experiments. They are non-transferable usage credits,
not money. The API retains the `TEST` currency identifier for compatibility;
no wallet or blockchain is needed. Experiment quotes and reservations use the
existing ledger. A settled experiment consumes its quoted credit even when a
measurement reports failure. An unadmitted, expired reservation is released.

## Daily allowance and hosting

A positive `balance_cap` enables managed credits for every account. Example
configuration (illustrative integer pricing units, not a production allocation
or a promise of an exact number of runs):

```toml
[allowance]
enabled = true
policy_issuer = "<UUID of an operator account>"
daily_base = 30000000
hosting_hourly_rate = 1000000
balance_cap = 300000000
```

Each UTC day adds `daily_base` credits. Unused credits and hosting rewards roll
over up to `balance_cap`. Reserved credits count toward the cap too, so releasing
a reservation cannot create extra allowance. A full balance records a zero grant;
spending later that day does not reopen it. Excess credit is discarded, not saved
as a hidden claim. Reducing the cap does not remove previously granted credit.

The first daily decision grants today's allowance only. Subsequent missed daily
grants are caught up on the next maintenance pass or account request, bounded by
the cap. Repeated requests, concurrent experiment submissions and dispatcher
restarts do not issue the same daily allowance twice. “Added today” can therefore
include catch-up credits. All amounts are integer ledger units; the configured
rates and cap default to zero and remain disabled until an operator sets them.

Hosting rewards use dispatcher-observed time for approved executors owned by the
account. A fresh connection alone is not an hour of hosting. Partial hours carry
forward; unobserved downtime does not earn credit. The account page shows observed
executor-hours, the hourly rate, hosting credits actually granted, daily allowance,
cap and next daily grant. Hosting credit is also bounded by the same balance cap.

The policy issuer must remain an operator. Operators approve owned executors with
`PUT /operator/accounts/{account UUID}/allowance-policy`:

```json
{"researcher":false,"approved_executor_ids":["<owned executor UUID>"]}
```

In managed-credit mode the researcher flag does not restrict the daily allowance.
The approval list still prevents unapproved registrations from earning hosting
rewards. Approval does not follow an executor transferred to another account.
Set legacy `daily_per_node` and `public_trial` to zero when enabling managed
credits. Manual grants remain available and are not automatically reduced.

## Legacy allowance policy

With `balance_cap = 0`, the existing optional researcher refill and public-trial
policy remains available. Example configuration:

```toml
[allowance]
enabled = true
policy_issuer = "<UUID of an operator account>"
daily_base = 30000000
daily_per_node = 10000000
daily_node_cap = 3
public_trial = 3000000
```

The new settings default to zero/empty, leaving automatic issuance disabled.
`policy_issuer` attributes immutable grants to an existing operator account;
issuance fails if that account no longer has the operator role.

An operator sets researcher eligibility and approves owned nodes with
`PUT /operator/accounts/{account UUID}/allowance-policy`:

```json
{"researcher":true,"approved_executor_ids":["<owned executor UUID>"]}
```

This replaces the approval list. Merely registering nodes does not earn credit.
Only approved nodes still owned by the account, connected, and reporting a
heartbeat within 120 seconds count. Future timestamps do not count. This is a
freshness check, not a claim of continuous daily uptime. Node bonuses are capped
by `daily_node_cap`; account approval remains an operator decision.

At the first allowance read or TEST intent each UTC day, a researcher receives
a refill up to `daily_base + daily_per_node × counted nodes`. Unspent **and
reserved** credits count toward the ceiling. Unused quota does not stack daily;
old reservations with uncertain outcomes are never discarded. Even a zero refill
is recorded, so spending later that day cannot issue another refill. Missed days
are not backfilled. Approval changes take effect with the next decision; they do
not rewrite existing grants or the current day's recorded decision.

Other accounts receive at most one public-trial refill. Exhausting that allowance
requires additional credit, rather than a midnight reset. This is an account
quota, not a defense against creating multiple accounts.

The account usage page and `GET /me/allowance` show remaining, reserved and
consumed credits, the applied ceiling and bonus, and the next UTC reset. A daily
refill is performed lazily at the next request, without requiring a scheduled
worker. All timestamps and integer amounts are retained in the dispatcher DB.
