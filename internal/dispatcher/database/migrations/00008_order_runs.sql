-- +goose up
-- An order records the run it was admitted as, so a repeated submission of the
-- same batch is answered with that run instead of admitting it again. Orders
-- that already have runs record the earliest one.
ALTER TABLE debuglet_order ADD COLUMN debuglet_id INTEGER;
UPDATE debuglet_order SET debuglet_id = (
    SELECT MIN(d.id) FROM debuglets d
    WHERE d.transaction_id = debuglet_order.transaction_id AND d.order_id = debuglet_order.order_id
) WHERE debuglet_id IS NULL;

-- +goose down
ALTER TABLE debuglet_order DROP COLUMN debuglet_id;
