-- +goose up
-- One row per settled order: the local decision to credit the executor or to
-- refund the buyer, taken once from the run's terminal exit code. Whether money
-- moved on chain is not recorded here. Rows are never changed or removed.
CREATE TABLE order_settlements (
    transaction_id TEXT NOT NULL,
    order_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('credit', 'refund')),
    amount INTEGER NOT NULL CHECK (amount >= 0),
    currency TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    debuglet_id INTEGER,
    recorded_at TIMESTAMP NOT NULL,
    PRIMARY KEY (transaction_id, order_id),
    FOREIGN KEY (transaction_id, order_id) REFERENCES debuglet_order(transaction_id, order_id)
);
-- +goose StatementBegin
CREATE TRIGGER order_settlements_immutable BEFORE UPDATE ON order_settlements
BEGIN
    SELECT RAISE(ABORT, 'order settlement is immutable');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER order_settlements_retained BEFORE DELETE ON order_settlements
BEGIN
    SELECT RAISE(ABORT, 'order settlement is immutable');
END;
-- +goose StatementEnd

-- The name of the rule that priced the intent. Rows written before this
-- column carry '' and were priced by the rule of the release that wrote them.
ALTER TABLE transactions ADD COLUMN pricing_rule TEXT NOT NULL DEFAULT '';

-- +goose down
ALTER TABLE transactions DROP COLUMN pricing_rule;
DROP TRIGGER order_settlements_retained;
DROP TRIGGER order_settlements_immutable;
DROP TABLE order_settlements;
