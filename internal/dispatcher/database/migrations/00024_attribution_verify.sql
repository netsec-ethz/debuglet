-- +goose up
-- Server-assisted verification (docs/verification.md, POST /attribution/verify).

-- The candidate trials spent per chain epoch, shared by every requester: an
-- executor query charges one trial per candidate run it tests. A query is
-- charged before it is relayed, so neither a crash nor a restart can refund
-- it. A row is deleted once the epoch's key is due for disclosure, when
-- no further query of that epoch is relayed.
CREATE TABLE attribution_verify_budget (
    executor_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    used INTEGER NOT NULL CHECK (used > 0),
    PRIMARY KEY (executor_id, chain_id, epoch)
);

-- The keys that verify the dispatcher's verification receipts: key_id is the
-- hex of the first 16 bytes of SHA-256(public_key). valid_to_ns is set when
-- another key became current.
CREATE TABLE attribution_receipt_keys (
    key_id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    valid_from_ns INTEGER NOT NULL,
    valid_to_ns INTEGER CHECK (valid_to_ns IS NULL OR valid_to_ns >= valid_from_ns)
);

-- +goose down
DROP TABLE attribution_receipt_keys;
DROP TABLE attribution_verify_budget;
