-- Counts one executor query of a chain epoch, unless the limit R = 16 is
-- reached (dispatcher.VerifyBudget): then no row is returned. One statement,
-- so concurrent requests never both take the last query.
-- name: SpendAttributionVerifyBudget :one
INSERT INTO attribution_verify_budget (executor_id, chain_id, epoch, used)
VALUES (sqlc.arg(executor_id), sqlc.arg(chain_id), sqlc.arg(epoch), 1)
ON CONFLICT (executor_id, chain_id, epoch) DO UPDATE SET used = used + 1
WHERE attribution_verify_budget.used < 16
RETURNING used;

-- name: GetAttributionVerifyBudget :one
SELECT used FROM attribution_verify_budget WHERE executor_id = ? AND chain_id = ? AND epoch = ?;

-- Deletes the counts of epochs whose key is due for disclosure, and those of
-- chains no longer on record.
-- name: PruneAttributionVerifyBudget :execrows
DELETE FROM attribution_verify_budget
WHERE NOT EXISTS (
    SELECT 1 FROM attribution_chains c
    WHERE c.executor_id = attribution_verify_budget.executor_id AND c.chain_id = attribution_verify_budget.chain_id
      AND c.interval_ns > 0
      AND c.t0_ns + (attribution_verify_budget.epoch + c.delay_epochs) * c.interval_ns > sqlc.arg(now_ns)
);

-- The smallest disclosed key of a chain at or above an epoch: every lower
-- key of the chain is derived from it by hashing.
-- name: NextAttributionKey :one
SELECT epoch, key FROM attribution_keys
WHERE executor_id = ? AND chain_id = ? AND epoch >= ?
ORDER BY epoch LIMIT 1;

-- name: ListAttributionReceiptKeys :many
SELECT * FROM attribution_receipt_keys ORDER BY valid_from_ns, key_id;

-- name: InsertAttributionReceiptKey :exec
INSERT INTO attribution_receipt_keys (key_id, public_key, valid_from_ns) VALUES (?, ?, ?)
ON CONFLICT (key_id) DO UPDATE SET valid_to_ns = NULL;

-- name: RetireAttributionReceiptKeys :exec
UPDATE attribution_receipt_keys SET valid_to_ns = CAST(sqlc.arg(now_ns) AS INTEGER)
WHERE key_id <> sqlc.arg(key_id) AND valid_to_ns IS NULL;
