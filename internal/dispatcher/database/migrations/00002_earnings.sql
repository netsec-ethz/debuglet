-- +goose up
CREATE TABLE earnings ( 
    executor_id TEXT NOT NULL,
    currency TEXT NOT NULL,
    total_income INTEGER NOT NULL,
    current_balance INTEGER NOT NULL,
    PRIMARY KEY (executor_id, currency)
);

CREATE TABLE debuglet_order (
    transaction_id TEXT NOT NULL REFERENCES transactions(id),
    order_id INTEGER NOT NULL,
    executor_id TEXT NOT NULL,
    price INTEGER NOT NULL,
    currency TEXT NOT NULL,
    PRIMARY KEY (transaction_id, order_id)
);

ALTER TABLE transactions ADD currency TEXT NOT NULL;
ALTER TABLE transactions ADD status INTEGER NOT NULL;
ALTER TABLE transactions DROP COLUMN paid;

-- +goose down
-- reverse order of creation to prevent foreign key constraint issues
ALTER TABLE transactions ADD paid BOOLEAN;
ALTER TABLE transactions DROP COLUMN status;
ALTER TABLE transactions DROP COLUMN currency;
DROP TABLE debuglet_order;
DROP TABLE earnings;
