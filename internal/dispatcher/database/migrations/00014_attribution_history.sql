-- +goose up
-- Durable attribution history (docs/verification.md, delivery step 2): the
-- TESLA chains executors announced, the disclosed keys that verified against
-- them, and which runs were active from which source address when. Times are
-- Unix nanoseconds so that epoch arithmetic and range queries are exact.

-- One row per chain an executor announced in its hello. chain_id is derived
-- from the anchor k0 (see internal/dispatcher/attribution.go); the same anchor
-- announced by two executors is two chains.
CREATE TABLE attribution_chains (
    executor_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    anchor BLOB NOT NULL CHECK (length(anchor) > 0),
    t0_ns INTEGER NOT NULL,
    interval_ns INTEGER NOT NULL CHECK (interval_ns >= 0),
    delay_epochs INTEGER NOT NULL CHECK (delay_epochs >= 0),
    chain_length INTEGER NOT NULL CHECK (chain_length >= 0),
    tag_spec INTEGER NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    PRIMARY KEY (executor_id, chain_id)
);

-- Disclosed keys that verified against their chain, each stored once.
CREATE TABLE attribution_keys (
    executor_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    key BLOB NOT NULL CHECK (length(key) > 0),
    disclosed_at_ns INTEGER NOT NULL,
    PRIMARY KEY (executor_id, chain_id, epoch),
    FOREIGN KEY (executor_id, chain_id) REFERENCES attribution_chains(executor_id, chain_id)
);

-- The interval in which a run could send tagged packets, the chain it tagged
-- them with and the source address the dispatcher knew for its executor. The
-- executor is the run's own (debuglets.executor_id).
CREATE TABLE attribution_runs (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    chain_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_ip_observed INTEGER NOT NULL CHECK (source_ip_observed IN (0, 1)),
    active_from_ns INTEGER NOT NULL,
    active_to_ns INTEGER NOT NULL CHECK (active_to_ns >= active_from_ns)
);
CREATE INDEX attribution_runs_source_idx ON attribution_runs(source_ip, active_to_ns);

-- History before retained_from has been pruned, or was never recorded.
CREATE TABLE attribution_retention (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    retained_from_ns INTEGER NOT NULL
);
INSERT INTO attribution_retention VALUES (1, CAST(strftime('%s', 'now') AS INTEGER) * 1000000000);

-- +goose down
DROP TABLE attribution_retention;
DROP INDEX attribution_runs_source_idx;
DROP TABLE attribution_runs;
DROP TABLE attribution_keys;
DROP TABLE attribution_chains;
