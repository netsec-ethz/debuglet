-- +goose up
-- Empty defaults preserve pre-binding rows for inspection and quarantine.
ALTER TABLE debuglets ADD COLUMN dispatcher_incarnation TEXT NOT NULL DEFAULT '';
ALTER TABLE debuglets ADD COLUMN session_id TEXT NOT NULL DEFAULT '';

-- +goose down
ALTER TABLE debuglets DROP COLUMN session_id;
ALTER TABLE debuglets DROP COLUMN dispatcher_incarnation;
