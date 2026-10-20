-- +goose up
-- Deposits retain their ordinary chain receipt and transaction. Sponsored
-- measurements retain their actor, while the community pays their orders.
CREATE TABLE community_topups (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES transactions(id),
    community_id TEXT NOT NULL REFERENCES communities(id),
    created_by INTEGER NOT NULL REFERENCES users(id),
    refund_address TEXT NOT NULL,
    network TEXT NOT NULL,
    coin_type TEXT NOT NULL
);
CREATE INDEX community_topups_community ON community_topups(community_id);
CREATE TABLE community_funding (
    transaction_id TEXT PRIMARY KEY NOT NULL REFERENCES transactions(id),
    community_id TEXT NOT NULL REFERENCES communities(id),
    project_id TEXT NOT NULL REFERENCES community_projects(id),
    sponsor_user_id INTEGER NOT NULL REFERENCES users(id),
    actor_user_id INTEGER NOT NULL REFERENCES users(id),
    currency TEXT NOT NULL CHECK(currency IN ('USDC', 'TEST')),
    network TEXT NOT NULL
);
CREATE INDEX community_funding_community ON community_funding(community_id);
CREATE INDEX community_funding_sponsor ON community_funding(sponsor_user_id);

-- +goose down
DROP TABLE community_funding;
DROP TABLE community_topups;
