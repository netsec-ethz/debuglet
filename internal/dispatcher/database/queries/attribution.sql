-- name: RecordAttributionChain :exec
INSERT INTO attribution_chains (executor_id, chain_id, anchor, t0_ns, interval_ns, delay_epochs, chain_length, tag_spec, first_seen_ns, last_seen_ns)
VALUES (sqlc.arg(executor_id), sqlc.arg(chain_id), sqlc.arg(anchor), sqlc.arg(t0_ns), sqlc.arg(interval_ns), sqlc.arg(delay_epochs), sqlc.arg(chain_length), sqlc.arg(tag_spec), sqlc.arg(seen_ns), sqlc.arg(seen_ns))
ON CONFLICT (executor_id, chain_id) DO UPDATE SET last_seen_ns = MAX(last_seen_ns, excluded.last_seen_ns);

-- name: GetAttributionChain :one
SELECT * FROM attribution_chains WHERE executor_id = ? AND chain_id = ?;

-- name: TouchAttributionChain :exec
UPDATE attribution_chains SET last_seen_ns = MAX(last_seen_ns, CAST(sqlc.arg(seen_ns) AS INTEGER))
WHERE executor_id = sqlc.arg(executor_id) AND chain_id = sqlc.arg(chain_id);

-- name: InsertAttributionKey :exec
INSERT INTO attribution_keys (executor_id, chain_id, epoch, key, disclosed_at_ns)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (executor_id, chain_id, epoch) DO NOTHING;

-- name: GetAttributionKey :one
SELECT key FROM attribution_keys WHERE executor_id = ? AND chain_id = ? AND epoch = ?;

-- name: LatestAttributionKey :one
SELECT epoch, key FROM attribution_keys
WHERE executor_id = ? AND chain_id = ?
ORDER BY epoch DESC LIMIT 1;

-- name: ListAttributionKeys :many
SELECT epoch, key FROM attribution_keys
WHERE executor_id = sqlc.arg(executor_id) AND chain_id = sqlc.arg(chain_id)
  AND epoch >= sqlc.arg(from_epoch) AND epoch <= sqlc.arg(to_epoch)
ORDER BY epoch;

-- name: RecordAttributionRun :exec
INSERT INTO attribution_runs (debuglet_id, chain_id, source_ip, source_ip_observed, active_from_ns, active_to_ns)
VALUES (?, ?, ?, ?, ?, ?);

-- name: EndAttributionRun :exec
UPDATE attribution_runs
SET active_to_ns = MAX(active_from_ns, MIN(active_to_ns, CAST(sqlc.arg(ended_ns) AS INTEGER)))
WHERE debuglet_id = (SELECT id FROM debuglets WHERE uuid = sqlc.arg(uuid));

-- name: ListAttributionCandidates :many
SELECT d.uuid, d.executor_id, r.source_ip_observed, r.active_from_ns, r.active_to_ns,
       c.chain_id, c.anchor, c.t0_ns, c.interval_ns, c.delay_epochs, c.chain_length, c.tag_spec,
       CAST(COALESCE((SELECT MAX(k.epoch) FROM attribution_keys k
                      WHERE k.executor_id = c.executor_id AND k.chain_id = c.chain_id), 0) AS INTEGER) AS disclosed_through
FROM attribution_runs r
JOIN debuglets d ON d.id = r.debuglet_id
JOIN attribution_chains c ON c.executor_id = d.executor_id AND c.chain_id = r.chain_id
WHERE r.source_ip = sqlc.arg(source_ip)
  AND r.active_from_ns <= sqlc.arg(at_ns) + c.interval_ns
  AND r.active_to_ns >= sqlc.arg(at_ns) - c.interval_ns
ORDER BY r.active_from_ns, d.uuid
LIMIT sqlc.arg(max_rows);

-- name: GetAttributionRetention :one
SELECT retained_from_ns FROM attribution_retention WHERE singleton = 1;

-- name: AdvanceAttributionRetention :exec
UPDATE attribution_retention SET retained_from_ns = MAX(retained_from_ns, CAST(sqlc.arg(cutoff_ns) AS INTEGER))
WHERE singleton = 1;

-- name: PruneAttributionRuns :execrows
DELETE FROM attribution_runs WHERE active_to_ns < sqlc.arg(cutoff_ns);

-- name: PruneAttributionKeys :execrows
DELETE FROM attribution_keys
WHERE EXISTS (
    SELECT 1 FROM attribution_chains c
    WHERE c.executor_id = attribution_keys.executor_id AND c.chain_id = attribution_keys.chain_id
      AND c.interval_ns > 0 AND c.t0_ns + (attribution_keys.epoch + 1) * c.interval_ns < sqlc.arg(cutoff_ns)
);

-- name: PruneAttributionChains :execrows
DELETE FROM attribution_chains
WHERE last_seen_ns < sqlc.arg(cutoff_ns)
  AND NOT EXISTS (SELECT 1 FROM attribution_keys k
                  WHERE k.executor_id = attribution_chains.executor_id AND k.chain_id = attribution_chains.chain_id)
  AND NOT EXISTS (SELECT 1 FROM attribution_runs r JOIN debuglets d ON d.id = r.debuglet_id
                  WHERE d.executor_id = attribution_chains.executor_id AND r.chain_id = attribution_chains.chain_id);
