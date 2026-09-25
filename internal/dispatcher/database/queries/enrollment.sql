/*

EXECUTOR ENROLLMENT

*/

-- name: SetExecutorEnrollment :exec
INSERT OR REPLACE INTO executor_enrollments (executor_id, fingerprint, enrolled_at)
VALUES (?, ?, ?);

-- name: GetExecutorEnrollment :one
SELECT fingerprint FROM executor_enrollments WHERE executor_id = ?;

-- name: DeleteExecutorEnrollment :execrows
DELETE FROM executor_enrollments WHERE executor_id = ?;

-- name: CreateExecutorEnrollmentToken :exec
INSERT INTO executor_enrollment_tokens (selector, executor_id, secret_hash, created_at, expires_at)
VALUES (?, ?, ?, ?, ?);

-- name: GetExecutorEnrollmentToken :one
SELECT executor_id, secret_hash, expires_at FROM executor_enrollment_tokens WHERE selector = ?;

-- name: ConsumeExecutorEnrollmentToken :execrows
DELETE FROM executor_enrollment_tokens WHERE selector = ?;

-- name: DeleteExecutorEnrollmentTokens :execrows
DELETE FROM executor_enrollment_tokens WHERE executor_id = ?;
