-- name: InsertPaymentReceipt :exec
INSERT INTO payment_receipts (tx_digest, event_seq, nonce, disposition, amount, coin_type, receiver, checkpoint, observed_at, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPaymentReceipt :one
SELECT * FROM payment_receipts
WHERE tx_digest = ? AND event_seq = ?;

-- name: ListPaymentReceiptsByNonce :many
SELECT * FROM payment_receipts
WHERE nonce = ?
ORDER BY observed_at, tx_digest, event_seq;

-- name: MarkTransactionPaid :execrows
UPDATE transactions
SET status = sqlc.arg(paid)
WHERE id = sqlc.arg(id) AND status = sqlc.arg(outstanding);

-- name: ReservePayout :execrows
UPDATE earnings
SET current_balance = current_balance - sqlc.arg(amount)
WHERE earnings.executor_id = sqlc.arg(executor_id) AND earnings.currency = sqlc.arg(currency)
  AND earnings.current_balance >= sqlc.arg(amount)
  AND NOT EXISTS (
    SELECT 1 FROM chain_transfers t
    WHERE t.kind = 'payout' AND t.executor_id = sqlc.arg(executor_id) AND t.currency = sqlc.arg(currency)
      AND t.state IN ('reserved', 'sent', 'unknown')
  );

-- name: ReleasePayout :exec
UPDATE earnings
SET current_balance = current_balance + sqlc.arg(amount)
WHERE executor_id = sqlc.arg(executor_id) AND currency = sqlc.arg(currency);

-- name: InsertChainTransfer :one
INSERT INTO chain_transfers (kind, executor_id, transaction_id, order_id, amount, currency, receiver, state, digest, signed_transaction, signature, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: UpdateChainTransfer :execrows
UPDATE chain_transfers
SET state = sqlc.arg(state), digest = sqlc.arg(digest), detail = sqlc.arg(detail), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: ListUnresolvedChainTransfers :many
SELECT * FROM chain_transfers
WHERE state IN ('sent', 'unknown') OR (state = 'reserved' AND updated_at < sqlc.arg(reserved_before))
ORDER BY updated_at, id
LIMIT sqlc.arg(row_limit);

-- name: RefundPaidTransaction :execrows
UPDATE transactions
SET status = sqlc.arg(refunded)
WHERE id = sqlc.arg(id) AND status = sqlc.arg(paid);
