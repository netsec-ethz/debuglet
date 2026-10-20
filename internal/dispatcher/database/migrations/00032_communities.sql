-- +goose up
CREATE TABLE communities (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
);
CREATE INDEX communities_creator ON communities(created_by);
CREATE TABLE community_members (
    community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY(community_id, user_id)
);
CREATE INDEX community_members_user ON community_members(user_id);
CREATE TABLE community_invitations (
    token_hash BLOB PRIMARY KEY,
    community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX community_invitations_community ON community_invitations(community_id);
CREATE TABLE community_projects (
    id TEXT PRIMARY KEY,
    community_id TEXT NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL
);
CREATE INDEX community_projects_community ON community_projects(community_id);
CREATE TABLE community_experiments (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES community_projects(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    created_by INTEGER NOT NULL REFERENCES users(id)
);
CREATE INDEX community_experiments_project ON community_experiments(project_id);
CREATE TABLE community_experiment_revisions (
    experiment_id TEXT NOT NULL REFERENCES community_experiments(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    collection TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL CHECK(kind IN ('workflow', 'experiment')),
    document TEXT NOT NULL CHECK(json_valid(document)),
    bundle TEXT CHECK(bundle IS NULL OR json_valid(bundle)),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(experiment_id, revision),
    CHECK(length(CAST(document AS BLOB)) + COALESCE(length(CAST(bundle AS BLOB)), 0) <= 25165824)
);
-- +goose StatementBegin
CREATE TRIGGER community_experiment_revision_immutable BEFORE UPDATE ON community_experiment_revisions
BEGIN
    SELECT RAISE(ABORT, 'saved experiment revisions are immutable');
END;
-- +goose StatementEnd
CREATE TABLE community_measurements (
    project_id TEXT NOT NULL REFERENCES community_projects(id) ON DELETE CASCADE,
    measurement_id TEXT NOT NULL REFERENCES transactions(id),
    shared_by INTEGER NOT NULL REFERENCES users(id),
    shared_at INTEGER NOT NULL,
    experiment_id TEXT,
    experiment_revision INTEGER,
    PRIMARY KEY(project_id, measurement_id),
    FOREIGN KEY(experiment_id, experiment_revision) REFERENCES community_experiment_revisions(experiment_id, revision),
    CHECK((experiment_id IS NULL) = (experiment_revision IS NULL))
);
CREATE INDEX community_measurements_measurement ON community_measurements(measurement_id);

-- +goose down
DROP TABLE community_measurements;
DROP TRIGGER community_experiment_revision_immutable;
DROP TABLE community_experiment_revisions;
DROP TABLE community_experiments;
DROP TABLE community_projects;
DROP TABLE community_invitations;
DROP TABLE community_members;
DROP TABLE communities;
