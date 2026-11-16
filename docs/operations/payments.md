# Chain payments

This page describes how a dispatcher with chain payments enabled sends money:
executor payouts and buyer refunds. TEST payments move no funds and write no
receipt or transfer records. While `[sui] disabled = true`, nothing here runs.

For [community funding](../communities.md#pay-from-the-community-budget), the
owner first signs a SUI or USDC deposit. Members then reserve that prepaid balance:
their intents return `method: "COMMUNITY"` and require no individual wallet
payment. Failed prepaid orders return funds to that community balance instead of
sending a buyer refund transfer. TEST communities share their creator's existing
allowance. The tables below describe personal payment intents unless stated
otherwise. Community deposits currently support Sui Testnet and have no
withdrawal interface.

## Modes and what each records

Chain payments are switched by `[sui] disabled`. Every shipped configuration
(`dbl` local services, the Docker and Ansible deployments, CI) sets
`disabled = true`, and nothing in the repository changes it.

| | Chain payments disabled | Chain payments enabled |
| --- | --- | --- |
| `TEST` intents | Accepted; paid on creation; bookkeeping units only, no funds | Same |
| `USDC` intents | `PUT /payment/intent` answers HTTP 503 `payments_disabled`; so does a submission that spends a stored chain transaction | A local intent record; the buyer pays it on Sui |
| Chain client, receipt listener, payout and reconciliation loops | Not built; no keystore is read | Running |
| Chain-currency orders of finished runs | Left as they are until chain payments are enabled again | Credited, or refunded on chain |

Native `SUI` intents are admitted on Testnet only, in integer MIST. Executors
must explicitly advertise `currency = "SUI"`; their configured `price_per_bw_s`
is then a fixed MIST rate, with no exchange-rate conversion. While disabled,
the dispatcher logs `blockchain payments are disabled; only TEST payments are
available` at startup.

What each payment method records in the dispatcher database:

| Record | `TEST` | `USDC` |
| --- | --- | --- |
| `transactions` | One row per intent, `Paid` on creation | One row per intent, `Outstanding` until a receipt pays it, with a five-minute expiry |
| `debuglet_order` | One row per order | One row per order, with the buyer's refund address |
| `order_settlements` | One immutable row per settled order: `credit` (exit status 0) or `refund` (any other); a refund moves nothing | The same; a refund is sent as a transfer |
| `earnings` | Credited balance per executor; never paid out | Credited balance per executor; paid out to its payout wallet |
| `payment_receipts` | None | One row per receipt event addressed to the dispatcher, with its disposition: `applied`, `duplicate`, `mismatch`, `expired` or `unknown_intent` |
| `chain_transfers` | None | One row per payout or refund transfer; see [transfer lifecycle](#transfer-lifecycle) |
| `transaction_states` | None | The listener's last processed checkpoint, under `sui_event_cursor:<payment_kit_package>` |

A receipt that is `mismatch`, `expired` or `unknown_intent` changes no
transaction. The money stays at the dispatcher's address and is not refunded
automatically; the receipt row is the record to reconcile from.

## Supported chain profile

This build supports chain payments only in this profile:

- **Network:** Sui Testnet (`network = "testnet"`). The daemon also accepts
  `mainnet` because the code carries its USDC coin type, but mainnet is not
  supported: there is no real-money operation.
- **Currencies:** native SUI (`0x2::sui::SUI`, 1 SUI = 1,000,000,000 MIST)
  and Circle's testnet USDC, through the coin type the dispatcher
  carries for `testnet`:

  ```text
  0xa1ec7fc00a6f40db9693ad1415d0c193ad3906494428cf252621037bd7117e29::usdc::USDC
  ```

  Verify it against the identifier Circle publishes for USDC on Sui Testnet
  before enabling chain payments, and do not enable them if the two differ.
- **Gas:** testnet SUI, held at the dispatcher's own address. Each transfer
  sets a gas budget of the reference gas price times 50,000 units, and the
  address must hold SUI coins covering that whole budget, in at most 256
  coin objects; only the gas used is charged.
- **Prepaid credits:** an account can deposit native SUI once and reserve its
  balance for subsequent experiments. Community owners can also deposit USDC.
  These are custodial Testnet credits; there is no withdrawal interface.

### Custody

The administrator of the dispatcher host holds the dispatcher's key: a
dedicated deployment key created for this dispatcher, never a personal wallet.
Its address is where buyers pay intents, where payouts and refunds are sent
from, and where the gas is held.

- The key lives only in the keystore file named by `keystore_path`, owned by
  the dispatcher's service account and readable by no other account. The daemon
  does not check the file's permissions.
- The recovery material stays offline under the host administrator's control,
  apart from the dispatcher host and its backups.
- No key, keystore or recovery material goes into source, a repository, a
  deployment inventory or an issue tracker.
- The keystore is a JSON array of base64 entries. The dispatcher uses the
  Ed25519 entry whose address equals `address`, skips every other entry, reads
  the file once at startup and never logs its content.

## Native prepaid credits and hosting rewards

Account usage offers native SUI funding when enabled. `POST /me/wallet/top-ups`
takes an integer-string `amount` in MIST, `refund_address`, and a unique
`idempotency_key`. Reusing the same key returns the original intent and expiry;
it never creates a second deposit. Only an exact confirmed payment-kit receipt
credits the balance. `GET /me/wallet` returns funds, reservations, spend and
recent receipt links. Chain intent amounts are limited to 9,007,199,254,740,991
base units to preserve wallet SDK integer precision.

A `PUT /payment/intent` request with `payment_method: "SUI", prepaid: true`
reserves the entire quoted batch in one database transaction and returns
`method: "CREDITS"`. No additional wallet signature is needed for that run.
Success consumes its orders and credits executor earnings. Failure returns the
same orders to the prepaid balance once; it does not also send a chain refund.
Unused expired reservations are released, while admitted uncertain work keeps
its reservation. TEST allowances remain noncashable and separate.

Hosting awards require explicit operator approval of the current owner, a
connected heartbeat no older than two minutes, and a registered SUI payout
wallet. They are a daily eligibility snapshot, **not proof of a day's uptime**.
The optional dispatcher settings (zero reward disables awards) are:

```toml
[sui]
hosting_reward_mist = 1000000
hosting_daily_cap_mist = 10000000
hosting_max_nodes_per_account = 3
```

An authenticated operator funds the dedicated subsidy with
`POST /operator/hosting-subsidy/top-ups`, using the same top-up body. Awards
are checked every minute, at most once per executor per UTC day, with per-account
node and global daily caps. Insufficient subsidy creates no award liability.
The award joins ordinary executor earnings and uses the existing payout and
reconciliation lifecycle.

**Transfer gas is operator-funded once native custody begins.** This also
applies to USDC payouts and refunds from the same wallet. Before a payout or direct
refund can be broadcast, the dispatcher reserves its signed maximum gas budget
from that subsidy in the same transaction as the transfer decision. Customer
deposits cannot pay it. Without gas funding the payout/refund stays owed and is
retried; it is not marked completed. Gas reservations survive restarts and
uncertain outcomes. They conservatively retain the full ceiling even when actual
gas is smaller; unused margin is not automatically released. Provision extra
subsidy for gas as well as award principal. A single SUI coin can cover payment
and gas; the transfer splits the gas coin after gas smashing.

## Startup validation

With `disabled = false`, the dispatcher checks the `[sui]` section and loads
the key before it binds any listener. The first failure stops the start: the
daemon logs `dispatcher exited with error` with
`configure payments: blockchain payments:` and the reason below, and exits with
status 1.

| Field | Refused with |
| --- | --- |
| `network` | `sui.network "<value>" is not supported; use testnet or mainnet` |
| `grpc_endpoint` | `sui.grpc_endpoint "<value>" must be host:port`, or `... has an invalid port` |
| `graphql_url` | `sui.graphql_url "<value>" must be an absolute http(s) URL` |
| `address`, `payment_registry_id`, `payment_kit_package` | `sui.<field>: "<value>" is not a Sui address` (`0x` and one to 64 hexadecimal digits) |
| `keystore_path` | `sui.keystore_path is empty` |
| keystore file | `sui.keystore_path: read keystore: <system error>`, `... keystore <path> is not a JSON array of strings`, or `... keystore <path> has no Ed25519 key for address <address>`: the key must belong to the configured `address` |

These checks open no network connection; the gRPC endpoint is always dialled
with TLS when it is first used. Write `payment_kit_package` in its full form,
`0x` and 64 digits: the listener selects events by the type
`<payment_kit_package>::payment_kit::PaymentReceipt` exactly as written.

Two conditions are checked later, when the receipt listener starts or runs:

- **Stored cursor.** A stored checkpoint that is not a number stops the
  dispatcher with `stored sui cursor "sui_event_cursor:<package>" is invalid`;
  it is never reset silently. Without a stored cursor, the listener stores its
  starting checkpoint and logs `no stored sui cursor, starting at chain tip`;
  payments made before that checkpoint are not read.
- **Indexer coverage.** The listener catches up through GraphQL only as far as
  the indexer reports it has ingested events
  (`serviceConfig.availableRange`), and never past the full node's tip. If the
  indexer cannot be queried or reports no range, catch-up logs `sui catch-up error` and is retried
  with a growing delay, without moving the cursor.

## Schedules

With chain payments enabled, the dispatcher runs these on its own:

- **Payout:** daily at local midnight, for every positive `USDC` or `SUI` balance that
  has a payout wallet.
- **Reconciliation:** every minute, over at most 100 open transfers; a
  `reserved` row counts as stale after ten minutes. See
  [reconciliation](#reconciliation).
- **Settlement pass:** every 30 seconds, over at most 32 orders of finished
  runs.
- **Submission:** one submission of a transfer waits at most two minutes;
  after that its outcome is `unknown`.

## Transfer lifecycle

Every outbound transfer, payout or refund, follows the same steps and leaves
one row in the dispatcher's `chain_transfers` table.

1. **Prepare.** The dispatcher selects coins and gas, builds and signs the
   transaction and computes its digest. This only reads from the chain. If it
   fails transiently, nothing is recorded and nothing is sent. An old order
   with an invalid refund address instead records a `failed` refund and the
   amount owed, without calling the chain; its detail names the invalid address.
2. **Reserve.** One database transaction records the local decision and the
   transfer row in state `reserved`, with the digest, the signed transaction
   and its signature. For a payout the decision is subtracting exactly the
   amount being paid from the executor's balance; earnings credited later stay
   in the balance for the next payout. For a refund it is marking the orders
   (and, for a transaction refund, the transaction) refunded with one refund
   settlement record per order. The signed transaction is stored before it is
   ever submitted, and no database transaction is held open while the chain is
   called.
3. **Submit** the stored transaction.
4. **Record** the outcome:
   - `sent`: the chain accepted the transaction and reported success.
   - `failed`: the transaction was not submitted, or the chain executed it
     with a failure status. No coins moved. A failed payout returns its amount
     to the executor's balance in the same database transaction.
   - `unknown`: the transaction may have been submitted, but the response was
     lost or incomplete. The row keeps the amount reserved until it is
     resolved.

A payout is not started while the same executor and currency has a `reserved`,
`sent` or `unknown` payout. A balance without a payout wallet is not paid out;
each payout pass logs how many such balances it skipped.

A failed run's refund is attempted when the run ends. If its executor exit code
was recorded and that attempt never reserved its transfer, the periodic
settlement pass sends it. The pass never takes an order that already
has a refund transfer, whatever that transfer's state, so one order is
refunded by at most one transfer; an uncertain outcome is resolved by
reconciliation below. While chain payments are disabled, the pass leaves
chain-currency orders as they are.

A dispatcher-recorded cancellation may have no executor exit code. From
dispatcher schema 27, its terminal decision is retained with the cancellation
record. If its initial refund fails before reserving a transfer, the periodic
settlement pass retries it, including after restart. This does not claim that
the executor acknowledged the cancellation or stopped.

Historical cancellations without that decision or an observed exit code are
not retried automatically. Inspect their order, settlement and transfer records
and reconcile them with chain history before arranging repayment. Never send a
replacement for an existing reserved, sent or unknown transfer; reconcile that
transfer first.

## Reconciliation

Once a minute the dispatcher looks up, by digest, every `sent` and `unknown`
transfer and every `reserved` transfer older than ten minutes (left by a stop
between the reservation and the submission):

| Lookup result | New state |
| --- | --- |
| Executed successfully, and the receiver's credit matches the amount and coin | `confirmed` |
| Executed successfully, but the node returned no balance changes to check the credit against | `unknown` |
| Executed with failure status | `failed` (a payout's amount returns to the balance) |
| Not found, row `reserved` or `unknown`, reserved less than one hour ago | the stored signed transaction is submitted again; a refusal to broadcast this attempt keeps the earlier outcome `unknown` |
| Not found, row `reserved` or `unknown`, reserved at least one hour ago | `unknown`, with automatic resubmission stopped and operator action named in the detail |
| Not found, row `sent` | `unknown` |
| Lookup error, or a credit that does not match | `unknown` |

Each lookup waits at most 30 seconds; one that does not answer leaves the
transfer `unknown` and the pass continues with the next transfer.

A resubmission sends the identical signed bytes, which have the same digest,
so the chain executes the transfer at most once. A transfer is never rebuilt
with new bytes because a response was lost. The one-hour window runs from the
stored `created_at`, survives restarts, and is an application recovery policy,
not a claim that the chain transaction has expired. After that window,
reconciliation still looks up the digest and can record a late confirmation or
an executed failure. An unresolved payout keeps its amount reserved and blocks
later payouts for that executor and currency; its stored detail states this.

## What an operator sees

The `detail` column of a `failed` or `unknown` row says why, and `updated_at`
is the time of the last check.

- **`failed` payout**: nothing was paid and the amount is back in the
  executor's balance; the next payout pass tries again with a new transfer.
- **`failed` refund**: the orders stay refunded and the amount is owed to the
  buyer's refund address. It is not retried automatically; the row is the
  record of what is owed. For an invalid address on an old order, the operator
  must verify a corrected address before arranging repayment; no chain
  transaction was prepared or sent. A buyer whose paid order is refunded because
  submissions are paused is told whether the refund was sent, is pending
  confirmation, or could not be sent and is owed.
- **`unknown`**: reconciliation keeps checking it every minute. A payout in
  this state blocks further payouts of that executor and currency, so the
  amount cannot be paid twice. If it stays `unknown`, for example because the
  node never returns balance changes or the stored transaction can no longer
  be executed, check the digest on a chain explorer before changing anything.

## Enabling chain payments

Chain payments are enabled only by an explicit decision of the operator
responsible for the dispatcher, in the supported profile above. Nothing in
the repository or its CI enables them, and this checklist performs nothing by
itself:

1. Create the dedicated deployment key, put its recovery material offline and
   install the keystore file for the service account only.
2. Stop the dispatcher, back up its database with its `-wal` and `-shm` files,
   and upgrade it explicitly, as
   [upgrading a database](configuration.md#upgrading-a-database) describes.
   This build requires the schema that holds `payment_receipts` and
   `chain_transfers`. Paid rows from before migration 4 have earnings without a
   payout wallet; reconcile them first, as
   [stored state](configuration.md#stored-state) describes.
3. Fund the deployment key's address with testnet SUI for gas.
4. Fill every `[sui]` field with `network = "testnet"`, verify the testnet USDC
   coin type against Circle's published identifier, set `disabled = false` and
   restart. A refused field is named in the startup error.
5. Watch the first log lines: `sui event listener started` with the event
   type, `no stored sui cursor, starting at chain tip` on the first start,
   `connecting to sui grpc`, and no repeating `sui catch-up error` or
   `sui receipt processing interrupted, retrying`.
6. Rehearse with one test payment and one payout: pay one `USDC` intent and
   check that its `payment_receipts` row is `applied` and its transaction
   `Paid`; then let one payout run and check that its `chain_transfers` row
   reaches `confirmed` and that the digest on the row is the one a Sui Testnet
   explorer shows for the transfer.

During that rehearsal, verify the following properties against the deployment's
selected Sui endpoints and payment kit:

- The GraphQL fields the listener relies on: `serviceConfig.availableRange`
  for indexer coverage, and `Event.sequenceNumber` as the event's position,
  which is part of a receipt's identity.
- The event position from the gRPC stream (the event's index in its
  transaction) agreeing with the GraphQL `sequenceNumber` for the same event;
  if they differ, a receipt read through both paths is recorded a second time,
  as a `mismatch` (the transaction is paid once).
- Receipts recorded during catch-up carry no checkpoint, because the GraphQL
  query does not report it; only streamed receipts record one.
- The payment kit's `PaymentReceipt` layout as the dispatcher decodes it
  (`timestamp_ms` as the last field) and the coin type string it carries.
- The digest the dispatcher computes for a prepared transaction matching the
  digest the chain reports for it; a mismatch is reported as
  `response is for transaction "<digest>"` and the transfer is recorded
  `unknown`.

A failed refund is not sent again automatically, and a transfer can stay
`unknown`, for example when its coins were spent by another transaction; what
the operator does in both cases is described under
[what an operator sees](#what-an-operator-sees).

### Backups and restore

[Backup and restore](backup-restore.md) covers the foreground `TEST` state
only. A dispatcher database restored from a backup taken before its last chain
transfer brings back executor balances and owed refunds that were already
paid, and nothing in the dispatcher prevents paying them again: the payout
pays every positive balance, and a payout is refused only while a `reserved`,
`sent` or `unknown` payout row exists for that executor and currency. Before
the payout or settlement pass runs on a restored database, switch chain
payments off and reconcile its balances, orders and transfer rows against the
chain history of the dispatcher's address.
