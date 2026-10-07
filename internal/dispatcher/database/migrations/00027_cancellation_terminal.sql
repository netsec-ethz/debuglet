-- +goose up
-- A cancellation request alone does not prove that it won the terminal race.
-- Historical requests remain unmarked; their outcome cannot be inferred.
ALTER TABLE debuglet_cancellations ADD COLUMN terminal_recorded_at INTEGER;

-- +goose down
ALTER TABLE debuglet_cancellations DROP COLUMN terminal_recorded_at;
