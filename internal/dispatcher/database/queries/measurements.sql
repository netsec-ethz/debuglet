-- name: ListMeasurements :many
SELECT s.id, CAST(s.label AS TEXT) AS label, CAST(s.state AS TEXT) AS state,
    CAST(s.children AS INTEGER) AS children, first_run.start_time AS scheduled_start
FROM measurement_summaries s JOIN debuglets first_run ON first_run.id =
    (SELECT first.id FROM debuglets first WHERE first.transaction_id=s.id ORDER BY first.start_time, first.id LIMIT 1)
WHERE EXISTS (SELECT 1 FROM debuglets d JOIN debuglet_users du ON du.debuglet_id = d.id
    JOIN users u ON u.id = du.user_id WHERE d.transaction_id = s.id AND u.uuid = sqlc.arg(user_uuid))
AND (sqlc.arg(state) = '' OR s.state = sqlc.arg(state))
AND instr(lower(s.id || ' ' || s.label), lower(sqlc.arg(search))) > 0
ORDER BY s.sequence DESC LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: MeasurementCounts :many
SELECT CAST(s.state AS TEXT) AS state, COUNT(*) AS count
FROM measurement_summaries s
WHERE EXISTS (SELECT 1 FROM debuglets d JOIN debuglet_users du ON du.debuglet_id = d.id
    JOIN users u ON u.id = du.user_id WHERE d.transaction_id = s.id AND u.uuid = sqlc.arg(user_uuid))
AND instr(lower(s.id || ' ' || s.label), lower(sqlc.arg(search))) > 0
GROUP BY s.state;

-- name: MeasurementRuns :many
SELECT d.uuid, d.executor_id, d.order_id, d.state,
    CAST(COALESCE(json_extract(m.document, '$.label'), '') AS TEXT) AS label,
    CAST(COALESCE(json_extract(m.document, '$.program_name'), '') AS TEXT) AS program_name
FROM debuglets d JOIN debuglet_users du ON du.debuglet_id = d.id
JOIN users u ON u.id = du.user_id
LEFT JOIN measurement_requests m ON m.debuglet_id = d.id
WHERE d.transaction_id = sqlc.arg(batch_id) AND u.uuid = sqlc.arg(user_uuid)
ORDER BY d.order_id, d.id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: MeasurementRunCount :one
SELECT COUNT(*) FROM debuglets d JOIN debuglet_users du ON du.debuglet_id = d.id
JOIN users u ON u.id = du.user_id
WHERE d.transaction_id = sqlc.arg(batch_id) AND u.uuid = sqlc.arg(user_uuid);
