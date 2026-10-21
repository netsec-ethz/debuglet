-- +goose Up
CREATE TABLE measurement_sources (
    measurement_id TEXT PRIMARY KEY REFERENCES transactions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK(kind IN ('workflow','experiment')),
    document TEXT NOT NULL CHECK(json_valid(document) AND length(CAST(document AS BLOB)) <= 4194304),
    document_sha256 TEXT NOT NULL CHECK(length(document_sha256) = 64),
    programs TEXT NOT NULL CHECK(json_valid(programs))
);
-- +goose StatementBegin
CREATE TRIGGER measurement_sources_immutable BEFORE UPDATE ON measurement_sources
BEGIN SELECT RAISE(ABORT, 'measurement sources are immutable'); END;
-- +goose StatementEnd

CREATE TABLE result_highlights (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    project_id TEXT REFERENCES community_projects(id) ON DELETE CASCADE,
    debuglet_id INTEGER NOT NULL REFERENCES debuglets(id) ON DELETE CASCADE,
    event_index INTEGER NOT NULL CHECK(event_index >= 0 AND event_index < 1000),
    event_sha256 TEXT NOT NULL CHECK(length(event_sha256) = 64),
    node_id TEXT NOT NULL,
    block TEXT NOT NULL,
    name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 120),
    note TEXT NOT NULL DEFAULT '' CHECK(length(CAST(note AS BLOB)) <= 2000),
    collection TEXT NOT NULL DEFAULT '' CHECK(length(CAST(collection AS BLOB)) <= 120),
    created_at INTEGER NOT NULL
);
CREATE INDEX result_highlights_owner ON result_highlights(user_id, project_id, created_at);
CREATE INDEX result_highlights_project ON result_highlights(project_id, created_at);
CREATE INDEX result_highlights_run ON result_highlights(debuglet_id);

-- The view filters before pagination and evaluates each project's own share.
CREATE VIEW result_highlight_readers AS
SELECT h.*, d.uuid AS run_uuid, d.transaction_id AS measurement_id,
    creator.uuid AS creator_uuid, creator.uuid AS reader_uuid, 1 AS can_manage
FROM result_highlights h JOIN users creator ON creator.id=h.user_id
JOIN debuglets d ON d.id=h.debuglet_id
WHERE h.project_id IS NULL AND NOT EXISTS(SELECT 1 FROM payload_tombstones t WHERE t.debuglet_id=d.id)
AND (EXISTS(SELECT 1 FROM debuglet_users du WHERE du.debuglet_id=d.id AND du.user_id=h.user_id)
 OR EXISTS(SELECT 1 FROM community_measurements cm JOIN community_projects p ON p.id=cm.project_id
 JOIN community_members member ON member.community_id=p.community_id
 WHERE cm.measurement_id=d.transaction_id AND member.user_id=h.user_id))
UNION ALL
SELECT h.*, d.uuid, d.transaction_id, creator.uuid, reader.uuid,
    CASE WHEN h.user_id=member.user_id OR community.created_by=member.user_id THEN 1 ELSE 0 END
FROM result_highlights h JOIN users creator ON creator.id=h.user_id
JOIN debuglets d ON d.id=h.debuglet_id
JOIN community_projects project ON project.id=h.project_id
JOIN communities community ON community.id=project.community_id
JOIN community_members member ON member.community_id=project.community_id
JOIN users reader ON reader.id=member.user_id
JOIN community_measurements cm ON cm.project_id=project.id AND cm.measurement_id=d.transaction_id
WHERE NOT EXISTS(SELECT 1 FROM payload_tombstones t WHERE t.debuglet_id=d.id);

-- +goose StatementBegin
CREATE TRIGGER purge_result_library AFTER INSERT ON payload_tombstones
BEGIN
 DELETE FROM result_highlights WHERE debuglet_id=NEW.debuglet_id;
 DELETE FROM measurement_sources WHERE measurement_id=(SELECT transaction_id FROM debuglets WHERE id=NEW.debuglet_id);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER purge_result_library;
DROP VIEW result_highlight_readers;
DROP TABLE result_highlights;
DROP TRIGGER measurement_sources_immutable;
DROP TABLE measurement_sources;
