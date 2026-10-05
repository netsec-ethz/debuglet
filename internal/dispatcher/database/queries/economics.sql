-- name: ListAccountIntents :many
-- One page of an account's payment intents, newest expiry first. A cursor
-- names the last intent of the previous page; one that is not the account's
-- own intent selects nothing.
SELECT t.id, t.method, t.status, t.price, t.currency, t.expires_at, t.pricing_rule
FROM transactions t
JOIN transaction_users tu ON tu.transaction_id = t.id
JOIN users u ON u.id = tu.user_id
WHERE u.uuid = sqlc.arg(user_uuid)
  AND (CAST(sqlc.arg(before) AS TEXT) = '' OR EXISTS (
    SELECT 1 FROM transactions c
    JOIN transaction_users cu ON cu.transaction_id = c.id
    WHERE c.id = sqlc.arg(before) AND cu.user_id = tu.user_id
      AND (t.expires_at < c.expires_at OR (t.expires_at = c.expires_at AND t.id < c.id))))
ORDER BY t.expires_at DESC, t.id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListIntentOrders :many
-- The orders of one payment intent with the run each one admitted, if any.
SELECT o.order_id, o.executor_id, o.price, o.currency, o.state, d.uuid AS run_id
FROM debuglet_order o
LEFT JOIN debuglets d ON d.id = o.debuglet_id
WHERE o.transaction_id = ?
ORDER BY o.order_id;
