-- +goose up
-- A local accounting decision. This is not an executor result or payment event.
CREATE TABLE allocation_reclamations (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    reclaimed_at TIMESTAMP NOT NULL
);

-- +goose down
DROP TABLE allocation_reclamations;
