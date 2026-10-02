-- name: CreateMeasurementProfile :execrows
INSERT INTO measurement_profiles (id, user_id, document)
SELECT ?1, users.id, ?2 FROM users
WHERE users.uuid = ?3
AND (SELECT count(*) FROM measurement_profiles WHERE user_id = users.id) < 32;

-- name: GetMeasurementProfile :one
SELECT document FROM measurement_profiles JOIN users ON users.id = measurement_profiles.user_id
WHERE measurement_profiles.id = ?1 AND users.uuid = ?2;

-- name: ListMeasurementProfiles :many
SELECT measurement_profiles.id, CAST(json_extract(document, '$.name') AS TEXT) AS name,
    CAST(json_extract(document, '$.program.sha256') AS TEXT) AS program_sha256
FROM measurement_profiles JOIN users ON users.id = measurement_profiles.user_id
WHERE users.uuid = ? ORDER BY name, measurement_profiles.id;

-- name: UpdateMeasurementProfile :execrows
UPDATE measurement_profiles SET document = ?1
WHERE measurement_profiles.id = ?2 AND user_id = (SELECT users.id FROM users WHERE users.uuid = ?3);

-- name: DeleteMeasurementProfile :execrows
DELETE FROM measurement_profiles
WHERE measurement_profiles.id = ?1 AND user_id = (SELECT users.id FROM users WHERE users.uuid = ?2);

-- name: InsertMeasurementRequest :exec
INSERT INTO measurement_requests (debuglet_id, document) VALUES (?, ?);

-- name: GetMeasurementRequest :one
SELECT document FROM measurement_requests WHERE debuglet_id = ?;
