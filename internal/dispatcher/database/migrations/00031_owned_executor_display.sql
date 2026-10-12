-- +goose up
ALTER TABLE owned_executors ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE owned_executors ADD COLUMN city TEXT NOT NULL DEFAULT '';
ALTER TABLE owned_executors ADD COLUMN country TEXT NOT NULL DEFAULT '';
ALTER TABLE owned_executors ADD COLUMN network TEXT NOT NULL DEFAULT '';

-- +goose down
ALTER TABLE owned_executors DROP COLUMN network;
ALTER TABLE owned_executors DROP COLUMN country;
ALTER TABLE owned_executors DROP COLUMN city;
ALTER TABLE owned_executors DROP COLUMN display_name;
