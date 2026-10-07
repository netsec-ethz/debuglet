-- +goose up
ALTER TABLE attribution_chains ADD COLUMN schedule_proof BLOB;

-- +goose down
ALTER TABLE attribution_chains DROP COLUMN schedule_proof;
