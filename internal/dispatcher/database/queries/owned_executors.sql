-- name: CreateOwnedExecutor :execrows
INSERT INTO owned_executors (executor_id, user_id, name, created_at)
SELECT ?1, users.id, ?2, ?3 FROM users
WHERE users.uuid = ?4
AND (SELECT count(*) FROM owned_executors WHERE user_id = users.id) < 10;

-- name: GetOwnedExecutor :one
SELECT owned_executors.executor_id, owned_executors.name,
    EXISTS(SELECT 1 FROM executor_enrollments WHERE executor_id = owned_executors.executor_id) AS enrolled
FROM owned_executors JOIN users ON users.id = owned_executors.user_id
WHERE users.uuid = ?1 AND owned_executors.executor_id = ?2;

-- name: ListOwnedExecutors :many
SELECT owned_executors.executor_id, owned_executors.name,
    EXISTS(SELECT 1 FROM executor_enrollments WHERE executor_id = owned_executors.executor_id) AS enrolled
FROM owned_executors JOIN users ON users.id = owned_executors.user_id
WHERE users.uuid = ? ORDER BY owned_executors.created_at, owned_executors.executor_id;
