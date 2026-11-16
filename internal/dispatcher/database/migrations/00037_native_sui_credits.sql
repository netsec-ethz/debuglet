-- +goose up
ALTER TABLE community_funding RENAME TO community_funding_old;
CREATE TABLE community_funding (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES transactions(id),
    community_id TEXT NOT NULL REFERENCES communities(id),
    project_id TEXT NOT NULL REFERENCES community_projects(id),
    sponsor_user_id INTEGER NOT NULL REFERENCES users(id),
    actor_user_id INTEGER NOT NULL REFERENCES users(id),
    currency TEXT NOT NULL CHECK(currency IN ('USDC', 'SUI', 'TEST')),
    network TEXT NOT NULL
);
INSERT INTO community_funding SELECT * FROM community_funding_old;
DROP TABLE community_funding_old;
CREATE INDEX community_funding_community ON community_funding(community_id);
CREATE INDEX community_funding_sponsor ON community_funding(sponsor_user_id);

-- A deposit is either a customer's credit or an operator's earmarked subsidy.
-- Both use the ordinary signed intent and confirmed receipt. They never mix.
CREATE TABLE prepaid_topups (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES transactions(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    purpose TEXT NOT NULL CHECK(purpose IN ('personal', 'hosting')),
    idempotency_key TEXT NOT NULL,
    refund_address TEXT NOT NULL,
    network TEXT NOT NULL,
    coin_type TEXT NOT NULL,
    intent_json TEXT NOT NULL,
    UNIQUE(user_id, purpose, idempotency_key)
);
CREATE TABLE personal_funding (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES transactions(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    currency TEXT NOT NULL CHECK(currency='SUI'),
    network TEXT NOT NULL
);
CREATE INDEX personal_funding_user ON personal_funding(user_id);
CREATE TABLE hosting_awards (
    executor_id TEXT NOT NULL,
    day TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    amount INTEGER NOT NULL CHECK(amount > 0),
    network TEXT NOT NULL CHECK(network='testnet'),
    PRIMARY KEY(executor_id, day)
);

-- Reserve the signed maximum gas budget from operator funds before broadcast.
CREATE TABLE native_gas_reservations (
    transfer_id INTEGER PRIMARY KEY REFERENCES chain_transfers(id),
    amount INTEGER NOT NULL CHECK(amount > 0),
    network TEXT NOT NULL CHECK(network='testnet')
);

-- +goose down
DROP TABLE native_gas_reservations;
DROP TABLE hosting_awards;
DROP TABLE personal_funding;
DROP TABLE prepaid_topups;
-- Existing native SUI decisions must be retained; downgrade the application
-- only after their settlement, without discarding this asset's history.
