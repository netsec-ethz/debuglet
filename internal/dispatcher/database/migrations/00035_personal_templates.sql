-- +goose Up
CREATE TABLE personal_templates (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 120),
    description TEXT NOT NULL DEFAULT '' CHECK(length(CAST(description AS BLOB)) <= 4000),
    collection TEXT NOT NULL DEFAULT '' CHECK(length(CAST(collection AS BLOB)) <= 120),
    kind TEXT NOT NULL CHECK(kind IN ('workflow','experiment')),
    document TEXT NOT NULL CHECK(json_valid(document) AND length(CAST(document AS BLOB)) <= 4194304),
    revision INTEGER NOT NULL CHECK(revision > 0),
    updated_at INTEGER NOT NULL
);
CREATE INDEX personal_templates_owner ON personal_templates(user_id, updated_at);

-- +goose Down
DROP TABLE personal_templates;
