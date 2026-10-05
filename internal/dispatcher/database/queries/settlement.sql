-- name: InsertPaymentReceipt :exec
INSERT INTO payment_receipts (tx_digest, nonce, disposition, amount, coin_type, receiver, checkpoint, observed_at, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetPaymentReceipt :one
SELECT * FROM payment_receipts
WHERE tx_digest = ? AND nonce = ?;

-- name: ListPaymentReceiptsByNonce :many
SELECT * FROM payment_receipts
WHERE nonce = ?
ORDER BY observed_at, tx_digest;

-- name: MarkTransactionPaid :execrows
UPDATE transactions
SET status = sqlc.arg(paid)
WHERE id = sqlc.arg(id) AND status = sqlc.arg(outstanding);
