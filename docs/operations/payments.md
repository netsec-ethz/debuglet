# Chain payments

This page describes how a dispatcher with chain payments enabled sends money:
executor payouts and buyer refunds. TEST payments move no funds and create none
of the records below. While `[sui] disabled = true`, nothing here runs.

## Transfer lifecycle

Every outbound transfer, payout or refund, follows the same steps and leaves
one row in the dispatcher's `chain_transfers` table.

1. **Prepare.** The dispatcher selects coins and gas, builds and signs the
   transaction and computes its digest. This only reads from the chain. If it
   fails, nothing is recorded and nothing is sent.
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

A failed run's refund is attempted when the run ends. If that attempt never
reserved its transfer, for example because the dispatcher stopped first, the
periodic settlement pass sends it. The pass never takes an order that already
has a refund transfer, whatever that transfer's state, so one order is
refunded by at most one transfer; an uncertain outcome is resolved by
reconciliation below. While chain payments are disabled, the pass leaves
chain-currency orders as they are.

## Reconciliation

Once a minute the dispatcher looks up, by digest, every `sent` and `unknown`
transfer and every `reserved` transfer older than ten minutes (left by a stop
between the reservation and the submission):

| Lookup result | New state |
| --- | --- |
| Executed successfully, and the receiver's credit matches the amount and coin | `confirmed` |
| Executed successfully, but the node returned no balance changes to check the credit against | `unknown` |
| Executed with failure status | `failed` (a payout's amount returns to the balance) |
| Not found, row `reserved` or `unknown` | the stored signed transaction is submitted again and the outcome recorded as above |
| Not found, row `sent` | `unknown` |
| Lookup error, or a credit that does not match | `unknown` |

A resubmission sends the identical signed bytes, which have the same digest,
so the chain executes the transfer at most once. A transfer is never rebuilt
with new bytes because a response was lost.

## What an operator sees

The `detail` column of a `failed` or `unknown` row says why, and `updated_at`
is the time of the last check.

- **`failed` payout**: nothing was paid and the amount is back in the
  executor's balance; the next payout pass tries again with a new transfer.
- **`failed` refund**: the orders stay refunded and the amount is owed to the
  buyer's refund address. It is not retried automatically; the row is the
  record of what is owed.
- **`unknown`**: reconciliation keeps checking it every minute. A payout in
  this state blocks further payouts of that executor and currency, so the
  amount cannot be paid twice. If it stays `unknown`, for example because the
  node never returns balance changes or the stored transaction can no longer
  be executed, check the digest on a chain explorer before changing anything.
