-- +goose up
CREATE TABLE debuglet_terminal_cleanup (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id)
);

-- +goose down
DROP TABLE debuglet_terminal_cleanup;
