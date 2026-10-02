-- +goose up
-- An operator decision is separate from the original run and its result.
CREATE TABLE operator_dispositions (
    run_id TEXT PRIMARY KEY,
    recorded_at_ns INTEGER NOT NULL CHECK (recorded_at_ns > 0),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 200)
);

-- A retired identity cannot become new work, even without an execution row.
-- +goose StatementBegin
CREATE TRIGGER disposed_run_identity BEFORE INSERT ON debuglets
WHEN EXISTS (SELECT 1 FROM operator_dispositions WHERE run_id = NEW.uuid)
BEGIN
    SELECT RAISE(ABORT, 'run has an operator disposition');
END;
-- +goose StatementEnd

-- +goose down
DROP TRIGGER disposed_run_identity;
DROP TABLE operator_dispositions;
