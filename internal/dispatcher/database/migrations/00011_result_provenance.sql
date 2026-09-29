-- +goose up
CREATE TABLE debuglet_provenance (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    document TEXT NOT NULL CHECK (json_valid(document))
);
-- +goose StatementBegin
CREATE TRIGGER debuglet_provenance_immutable
BEFORE UPDATE ON debuglet_provenance
BEGIN
    SELECT RAISE(ABORT, 'run admission provenance is immutable');
END;
-- +goose StatementEnd

-- +goose down
DROP TRIGGER debuglet_provenance_immutable;
DROP TABLE debuglet_provenance;
