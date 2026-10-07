-- name: RecordProbeConnected :exec
-- A registration within 120 seconds (probeStreakGrace) of the last connected
-- record of a connected row (a replacement session, or a dispatcher restart) continues
-- that row's streak and its uptime; otherwise the old streak ended at its
-- last_connected and a new one starts now.
INSERT INTO probe_status (executor_id, first_connected, last_connected, connected, status_since, total_uptime, is_public, host_tags, version)
VALUES (sqlc.arg(executor_id), sqlc.arg(now), sqlc.arg(now), 1, sqlc.arg(now), 0, sqlc.arg(is_public), sqlc.arg(host_tags), sqlc.arg(version))
ON CONFLICT (executor_id) DO UPDATE SET
    status_since = CASE
        WHEN probe_status.connected = 1 AND excluded.last_connected >= probe_status.last_connected
            AND excluded.last_connected - probe_status.last_connected <= 120
        THEN probe_status.status_since ELSE excluded.status_since END,
    total_uptime = probe_status.total_uptime + CASE
        WHEN probe_status.connected = 1 AND excluded.last_connected >= probe_status.last_connected
            AND excluded.last_connected - probe_status.last_connected <= 120
        THEN excluded.last_connected - probe_status.last_connected ELSE 0 END,
    last_connected = MAX(probe_status.last_connected, excluded.last_connected),
    connected = 1,
    is_public = excluded.is_public,
    host_tags = excluded.host_tags,
    version = excluded.version;

-- name: TouchProbeConnected :execrows
UPDATE probe_status SET
    total_uptime = total_uptime + (CAST(sqlc.arg(now) AS INTEGER) - last_connected),
    last_connected = CAST(sqlc.arg(now) AS INTEGER)
WHERE executor_id = sqlc.arg(executor_id) AND connected = 1 AND CAST(sqlc.arg(now) AS INTEGER) >= last_connected;

-- name: ListConnectedProbeIDs :many
SELECT executor_id FROM probe_status WHERE connected = 1 ORDER BY executor_id;

-- name: RecordProbeDisconnected :execrows
-- The executor was last known connected at last_connected; it disconnected
-- then, as far as this record can tell.
UPDATE probe_status SET connected = 0, status_since = last_connected
WHERE executor_id = ? AND connected = 1;

-- name: ExtendProbeAddress :execrows
-- Extends the family's latest run when it has the same address.
UPDATE probe_addresses SET last_observed = MAX(last_observed, CAST(sqlc.arg(at) AS INTEGER))
WHERE probe_addresses.executor_id = sqlc.arg(executor_id) AND probe_addresses.family = sqlc.arg(family) AND probe_addresses.address = sqlc.arg(address)
    AND probe_addresses.first_observed = (SELECT MAX(latest.first_observed) FROM probe_addresses AS latest
        WHERE latest.executor_id = sqlc.arg(executor_id) AND latest.family = sqlc.arg(family));

-- name: StartProbeAddress :execrows
-- Starts a new run, unless a run already covers this time, so an older
-- observation never opens a run after a newer one.
INSERT INTO probe_addresses (executor_id, family, address, via, first_observed, last_observed)
SELECT sqlc.arg(executor_id), sqlc.arg(family), sqlc.arg(address), sqlc.arg(via), CAST(sqlc.arg(at) AS INTEGER), CAST(sqlc.arg(at) AS INTEGER)
WHERE NOT EXISTS (SELECT 1 FROM probe_addresses AS covered
    WHERE covered.executor_id = sqlc.arg(executor_id) AND covered.family = sqlc.arg(family) AND covered.last_observed >= CAST(sqlc.arg(at) AS INTEGER));

-- name: PruneProbeAddresses :execrows
-- Keeps every family's latest run, whatever its age.
DELETE FROM probe_addresses WHERE probe_addresses.last_observed < CAST(sqlc.arg(cutoff) AS INTEGER)
    AND probe_addresses.first_observed < (SELECT MAX(latest.first_observed) FROM probe_addresses AS latest
        WHERE latest.executor_id = probe_addresses.executor_id AND latest.family = probe_addresses.family);

-- name: ListProbeStatus :many
SELECT executor_id, first_connected, last_connected, connected, status_since, total_uptime, is_public, host_tags, version
FROM probe_status ORDER BY executor_id;

-- name: ListLatestProbeAddresses :many
SELECT a.executor_id, a.family, a.address, a.via, a.first_observed, a.last_observed
FROM probe_addresses AS a
WHERE a.first_observed = (SELECT MAX(b.first_observed) FROM probe_addresses AS b
    WHERE b.executor_id = a.executor_id AND b.family = a.family)
ORDER BY a.executor_id, a.family;

-- name: ListEnrolledExecutorIDs :many
SELECT executor_id FROM executor_enrollments
UNION
SELECT executor_id FROM owned_executors
ORDER BY executor_id;
