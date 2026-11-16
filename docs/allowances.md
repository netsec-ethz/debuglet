# Usage allowances

TEST allowance is non-transferable usage credit, not SUI or withdrawable money.
Enable `[allowance] enabled = true` to cap TEST experiments using the existing
reservation and settlement ledger. Manual operator grants continue to work.

Automatic quotas are opt-in. Example dispatcher configuration (amounts are
integer TEST pricing units, not a promise of an exact number of runs):

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
