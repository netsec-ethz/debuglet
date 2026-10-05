-- +goose up
-- Every chain payment receipt addressed to this dispatcher, keyed by the chain
-- transaction digest and the receipt nonce (our transaction id). The row is
-- written in the same SQL transaction as the payment's effect, so a receipt
-- read again after a restart is recognized instead of applied twice. The
-- amount is decimal text so that a chain amount beyond INTEGER is kept exactly.
CREATE TABLE payment_receipts (
    tx_digest TEXT NOT NULL,
    nonce TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('applied', 'duplicate', 'mismatch', 'unknown_intent', 'expired')),
    amount TEXT NOT NULL,
    coin_type TEXT NOT NULL,
    receiver TEXT NOT NULL,
    checkpoint INTEGER,
    observed_at TIMESTAMP NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tx_digest, nonce)
);

-- Outbound chain transfers (executor payouts and refunds). A row is reserved
-- before the chain call and records what is known about it afterwards. The
-- signed transaction and its signature are stored before broadcast, so a
-- transfer whose outcome is unknown after a crash can be looked up or sent
-- again unchanged rather than paid a second time.
CREATE TABLE chain_transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('payout', 'refund')),
    executor_id TEXT NOT NULL DEFAULT '',
    transaction_id TEXT NOT NULL DEFAULT '',
    order_id INTEGER,
    amount INTEGER NOT NULL CHECK (amount > 0),
    currency TEXT NOT NULL,
    receiver TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'sent', 'confirmed', 'failed', 'unknown')),
    digest TEXT NOT NULL DEFAULT '',
    signed_transaction BLOB NOT NULL DEFAULT X'',
    signature TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);
CREATE INDEX chain_transfers_executor_idx ON chain_transfers(executor_id, currency, state);

-- +goose down
DROP INDEX chain_transfers_executor_idx;
DROP TABLE chain_transfers;
DROP TABLE payment_receipts;
