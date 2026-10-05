-- +goose up
-- The disclosure delay d of a chain, in epochs, so a later start can disclose
-- the chain's last keys. NULL for chains recorded before it was kept.
ALTER TABLE tesla_chains ADD COLUMN disclosure_delay INTEGER;

-- +goose down
ALTER TABLE tesla_chains DROP COLUMN disclosure_delay;
