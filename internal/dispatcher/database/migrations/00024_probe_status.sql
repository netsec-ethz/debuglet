-- +goose up
-- RIPE Atlas-style probe status and address history
-- (docs/operations/executor-discovery.md#probe-status-and-tags). Times are
-- Unix seconds.

-- One row per executor that has ever registered. connected is the state the
-- dispatcher last recorded; a row left connected by a dispatcher that stopped
-- is closed at its last_connected. total_uptime counts connected seconds up to
-- last_connected, from the first registration recorded here.
CREATE TABLE probe_status (
    executor_id TEXT NOT NULL PRIMARY KEY,
    first_connected INTEGER NOT NULL,
    last_connected INTEGER NOT NULL CHECK (last_connected >= first_connected),
    connected INTEGER NOT NULL CHECK (connected IN (0, 1)),
    status_since INTEGER NOT NULL,
    total_uptime INTEGER NOT NULL CHECK (total_uptime >= 0),
    is_public INTEGER NOT NULL CHECK (is_public IN (0, 1)),
    host_tags TEXT NOT NULL,
    version TEXT NOT NULL
);

-- Runs of one observed address per executor and family: a new row starts
-- whenever the family's address differs from its latest row.
CREATE TABLE probe_addresses (
    executor_id TEXT NOT NULL REFERENCES probe_status(executor_id),
    family INTEGER NOT NULL CHECK (family IN (4, 6)),
    address TEXT NOT NULL,
    via TEXT NOT NULL CHECK (via IN ('control', 'reflection')),
    first_observed INTEGER NOT NULL,
    last_observed INTEGER NOT NULL CHECK (last_observed >= first_observed),
    PRIMARY KEY (executor_id, family, first_observed)
);

-- Executors with recorded TESLA chains have registered before. Their first and
-- last registration is known from the chains; their uptime and addresses are
-- not, and start from zero and empty. Pruned chains leave no trace.
INSERT INTO probe_status (executor_id, first_connected, last_connected, connected, status_since, total_uptime, is_public, host_tags, version)
SELECT executor_id, MIN(first_seen_ns) / 1000000000, MAX(MAX(last_seen_ns), MIN(first_seen_ns)) / 1000000000, 0, MAX(MAX(last_seen_ns), MIN(first_seen_ns)) / 1000000000, 0, 1, '', ''
FROM attribution_chains GROUP BY executor_id;

-- +goose down
DROP TABLE probe_addresses;
DROP TABLE probe_status;
