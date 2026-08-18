-- name: GetUserByUUID :one
SELECT *
FROM users
WHERE uuid=?;

-- name: ListUserUUIDs :many
SELECT uuid
FROM users;

-- name: CreateUser :one
INSERT INTO users (uuid, name)
VALUES (?, ?)
RETURNING *;

-- name: ListDebugletsByUserUUID :many
SELECT *
FROM debuglets
WHERE id IN (
    SELECT debuglet_id
    FROM debuglet_users
    INNER JOIN users ON debuglet_users.user_id = users.id
    WHERE users.uuid=?
)
LIMIT ? OFFSET ?;

-- name: InsertDebugletUser :exec
INSERT INTO debuglet_users (debuglet_id, user_id)
VALUES (
    (SELECT id FROM debuglets WHERE debuglets.uuid=:deb_uuid),
    (SELECT id FROM users WHERE users.uuid=:user_uuid)
);
