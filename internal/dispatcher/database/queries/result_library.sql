-- name: ListResultHighlights :many
SELECT id,user_id,project_id,debuglet_id,event_index,event_sha256,node_id,block,name,note,collection,created_at,
 CAST(run_uuid AS TEXT) AS run_id, CAST(measurement_id AS TEXT) AS measurement_id,
 CAST(creator_uuid AS TEXT) AS creator_id, CAST(can_manage AS INTEGER) AS can_manage FROM result_highlight_readers
WHERE CAST(reader_uuid AS TEXT)=CAST(sqlc.arg(user_uuid) AS TEXT) AND COALESCE(project_id,'')=CAST(sqlc.arg(project_id) AS TEXT)
 AND (CAST(sqlc.arg(collection) AS TEXT)='' OR collection=CAST(sqlc.arg(collection) AS TEXT))
 AND instr(lower(name||' '||note||' '||collection),lower(sqlc.arg(search)))>0
ORDER BY created_at DESC,id LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountResultHighlights :one
SELECT COUNT(*) FROM result_highlight_readers
WHERE CAST(reader_uuid AS TEXT)=CAST(sqlc.arg(user_uuid) AS TEXT) AND COALESCE(project_id,'')=CAST(sqlc.arg(project_id) AS TEXT)
 AND (CAST(sqlc.arg(collection) AS TEXT)='' OR collection=CAST(sqlc.arg(collection) AS TEXT))
 AND instr(lower(name||' '||note||' '||collection),lower(sqlc.arg(search)))>0;

-- name: GetResultHighlight :one
SELECT id,user_id,project_id,debuglet_id,event_index,event_sha256,node_id,block,name,note,collection,created_at,
 CAST(run_uuid AS TEXT) AS run_id, CAST(measurement_id AS TEXT) AS measurement_id,
 CAST(creator_uuid AS TEXT) AS creator_id, CAST(can_manage AS INTEGER) AS can_manage FROM result_highlight_readers WHERE id=sqlc.arg(id) AND CAST(reader_uuid AS TEXT)=CAST(sqlc.arg(user_uuid) AS TEXT);

-- name: CreateResultHighlight :execrows
INSERT INTO result_highlights(id,user_id,project_id,debuglet_id,event_index,event_sha256,node_id,block,name,note,collection,created_at)
SELECT sqlc.arg(id),u.id,sqlc.narg(project_id),d.id,sqlc.arg(event_index),sqlc.arg(event_sha256),sqlc.arg(node_id),sqlc.arg(block),sqlc.arg(name),sqlc.arg(note),CAST(sqlc.arg(collection) AS TEXT),sqlc.arg(created_at)
FROM users u JOIN debuglets d ON d.uuid=sqlc.arg(run_uuid)
WHERE u.uuid=sqlc.arg(user_uuid)
 AND NOT EXISTS(SELECT 1 FROM payload_tombstones t WHERE t.debuglet_id=d.id)
 AND ((sqlc.narg(project_id) IS NULL AND (EXISTS(SELECT 1 FROM debuglet_users du WHERE du.debuglet_id=d.id AND du.user_id=u.id)
  OR EXISTS(SELECT 1 FROM community_measurements cm JOIN community_projects p ON p.id=cm.project_id JOIN community_members m ON m.community_id=p.community_id WHERE cm.measurement_id=d.transaction_id AND m.user_id=u.id)))
 OR EXISTS(SELECT 1 FROM community_measurements cm JOIN community_projects p ON p.id=cm.project_id JOIN community_members m ON m.community_id=p.community_id WHERE cm.project_id=sqlc.narg(project_id) AND cm.measurement_id=d.transaction_id AND m.user_id=u.id))
 AND (SELECT COUNT(*) FROM result_highlights h WHERE (sqlc.narg(project_id) IS NULL AND h.project_id IS NULL AND h.user_id=u.id) OR h.project_id=sqlc.narg(project_id))<1024;

-- name: UpdateResultHighlight :execrows
UPDATE result_highlights SET name=sqlc.arg(name),note=sqlc.arg(note),collection=CAST(sqlc.arg(collection) AS TEXT)
WHERE result_highlights.id IN(SELECT r.id FROM result_highlight_readers r WHERE r.id=sqlc.arg(id) AND CAST(r.reader_uuid AS TEXT)=CAST(sqlc.arg(user_uuid) AS TEXT) AND r.can_manage=1);

-- name: DeleteResultHighlight :execrows
DELETE FROM result_highlights WHERE result_highlights.id IN(SELECT r.id FROM result_highlight_readers r WHERE r.id=sqlc.arg(id) AND CAST(r.reader_uuid AS TEXT)=CAST(sqlc.arg(user_uuid) AS TEXT) AND r.can_manage=1);
