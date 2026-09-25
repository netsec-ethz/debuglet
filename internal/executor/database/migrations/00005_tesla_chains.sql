-- +goose up
-- One row per TESLA chain the executor started. The anchor is the chain's
-- public identity, which the dispatcher publishes. It is unique, so no start
-- reuses the keys an earlier chain disclosed.
CREATE TABLE tesla_chains (
    generation INTEGER PRIMARY KEY,
    anchor BLOB NOT NULL UNIQUE,
    epoch_base TIMESTAMP NOT NULL,
    delay_ns INTEGER NOT NULL,
    chain_length INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL
);

-- +goose down
DROP TABLE tesla_chains;
