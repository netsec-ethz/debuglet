-- +goose up

ALTER TABLE debuglets ADD transaction_id TEXT NOT NULL;
ALTER TABLE debuglets ADD order_id INTEGER NOT NULL;
ALTER TABLE debuglet_order ADD state INTEGER NOT NULL;
ALTER TABLE debuglet_order ADD refund_address TEXT NOT NULL;
ALTER TABLE earnings ADD sui_wallet_address TEXT NOT NULL;

-- +goose down
-- reverse order of creation to prevent foreign key constraint issues

ALTER TABLE earnings DROP COLUMN sui_wallet_address;
ALTER TABLE debuglet_order DROP COLUMN refund_address;
ALTER TABLE debuglet_order DROP COLUMN state;
ALTER TABLE debuglets DROP COLUMN order_id;
ALTER TABLE debuglets DROP COLUMN transaction_id;
