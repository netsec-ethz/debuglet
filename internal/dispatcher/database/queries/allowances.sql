-- name: GetAllowance :one
-- The allowance of an account in TEST units: the sum of its grants; consumed,
-- the price of its TEST orders that have a settlement, whichever way it went;
-- and reserved, the price of the other orders of its paid TEST intents.
SELECT
  CAST(COALESCE((SELECT SUM(g.amount) FROM allowance_grants g WHERE g.user_id = u.id), 0) AS INTEGER) AS granted,
  CAST(COALESCE((SELECT SUM(o.price) FROM debuglet_order o
    JOIN transaction_users tu ON tu.transaction_id = o.transaction_id
    JOIN transactions t ON t.id = o.transaction_id
    WHERE tu.user_id = u.id AND t.method = 'TEST'
      AND EXISTS (SELECT 1 FROM order_settlements s
        WHERE s.transaction_id = o.transaction_id AND s.order_id = o.order_id)), 0) AS INTEGER) AS consumed,
  CAST(COALESCE((SELECT SUM(o.price) FROM debuglet_order o
    JOIN transaction_users tu ON tu.transaction_id = o.transaction_id
    JOIN transactions t ON t.id = o.transaction_id
    WHERE tu.user_id = u.id AND t.method = 'TEST' AND t.status = sqlc.arg(paid_status)
      AND NOT EXISTS (SELECT 1 FROM order_settlements s
        WHERE s.transaction_id = o.transaction_id AND s.order_id = o.order_id)), 0) AS INTEGER) AS reserved
FROM users u
WHERE u.uuid = sqlc.arg(user_uuid);

-- name: ReserveAllowanceIntent :execrows
-- Creates a paid TEST transaction for the account only if its remaining
-- allowance, computed as GetAllowance does, covers price. The check and the
-- insert are one statement, so two intents cannot both spend the same rest.
INSERT INTO transactions (id, auth_key, price, currency, method, expires_at, status, hash)
SELECT sqlc.arg(id), '', sqlc.arg(price), 'TEST', 'TEST', sqlc.arg(expires_at), sqlc.arg(paid_status), sqlc.arg(hash)
FROM users u
WHERE u.uuid = sqlc.arg(user_uuid)
  AND COALESCE((SELECT SUM(g.amount) FROM allowance_grants g WHERE g.user_id = u.id), 0)
    - COALESCE((SELECT SUM(o.price) FROM debuglet_order o
      JOIN transaction_users tu ON tu.transaction_id = o.transaction_id
      JOIN transactions t ON t.id = o.transaction_id
      WHERE tu.user_id = u.id AND t.method = 'TEST'
        AND (t.status = sqlc.arg(paid_status) OR EXISTS (SELECT 1 FROM order_settlements s
          WHERE s.transaction_id = o.transaction_id AND s.order_id = o.order_id))), 0)
    >= sqlc.arg(price);

-- name: ReleaseExpiredAllowanceIntents :execrows
-- Expires the account's paid TEST intents past their expiry that admitted no
-- run. Admission claims an order only while its transaction is paid, so an
-- intent is either released here or admitted, never both.
UPDATE transactions
SET status = sqlc.arg(expired_status)
WHERE status = sqlc.arg(paid_status) AND method = 'TEST' AND expires_at < sqlc.arg(now)
  AND id IN (SELECT tu.transaction_id FROM transaction_users tu
    JOIN users u ON u.id = tu.user_id WHERE u.uuid = sqlc.arg(user_uuid))
  AND NOT EXISTS (
    SELECT 1 FROM debuglet_order
    WHERE debuglet_order.transaction_id = transactions.id AND debuglet_id IS NOT NULL
  );

-- name: InsertAllowanceGrant :execrows
INSERT INTO allowance_grants (user_id, amount, currency, granted_by, reason, idempotency_key, granted_at)
SELECT u.id, sqlc.arg(amount), 'TEST', o.id, sqlc.arg(reason), sqlc.arg(idempotency_key), sqlc.arg(granted_at)
FROM users u
JOIN users o ON o.uuid = sqlc.arg(granted_by)
WHERE u.uuid = sqlc.arg(user_uuid);

-- name: GetAllowanceGrant :one
SELECT g.id, g.amount, g.currency, g.reason, g.idempotency_key, g.granted_at, o.uuid AS granted_by
FROM allowance_grants g
JOIN users u ON u.id = g.user_id
JOIN users o ON o.id = g.granted_by
WHERE u.uuid = sqlc.arg(user_uuid) AND g.idempotency_key = sqlc.arg(idempotency_key);

-- name: ListExecutorTransfers :many
-- The newest outbound chain transfers that name an executor.
SELECT id, kind, amount, currency, receiver, state, digest, created_at, updated_at
FROM chain_transfers
WHERE executor_id = sqlc.arg(executor_id)
ORDER BY id DESC
LIMIT sqlc.arg(row_limit);
