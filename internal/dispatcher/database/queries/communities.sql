-- name: CreateCommunity :execrows
INSERT INTO communities(id, name, description, created_by, created_at)
SELECT sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), u.id, sqlc.arg(created_at)
FROM users u WHERE u.uuid = sqlc.arg(user_uuid)
AND (SELECT count(*) FROM communities WHERE created_by = u.id) < 16;

-- name: AddCommunityCreator :exec
INSERT INTO community_members(community_id, user_id, joined_at)
SELECT id, created_by, created_at FROM communities WHERE id = ?;

-- name: GetCommunity :one
SELECT c.*, creator.uuid AS creator_uuid, CAST(CASE WHEN c.created_by = m.user_id THEN 'owner' ELSE 'member' END AS TEXT) AS role
FROM communities c JOIN community_members m ON m.community_id = c.id
JOIN users u ON u.id = m.user_id JOIN users creator ON creator.id = c.created_by
WHERE c.id = sqlc.arg(id) AND u.uuid = sqlc.arg(user_uuid);

-- name: ListCommunities :many
SELECT c.*, creator.uuid AS creator_uuid, CAST(CASE WHEN c.created_by = m.user_id THEN 'owner' ELSE 'member' END AS TEXT) AS role
FROM communities c JOIN community_members m ON m.community_id = c.id
JOIN users u ON u.id = m.user_id JOIN users creator ON creator.id = c.created_by
WHERE u.uuid = sqlc.arg(user_uuid) ORDER BY c.name, c.id;

-- name: UpdateCommunity :execrows
UPDATE communities SET name = sqlc.arg(name), description = sqlc.arg(description)
WHERE communities.id = sqlc.arg(id) AND communities.created_by = (SELECT users.id FROM users WHERE users.uuid = sqlc.arg(user_uuid));

-- name: ListCommunityMembers :many
SELECT u.uuid AS user_uuid, u.name, m.joined_at,
CAST(CASE WHEN c.created_by = m.user_id THEN 'owner' ELSE 'member' END AS TEXT) AS role
FROM community_members m JOIN users u ON u.id = m.user_id JOIN communities c ON c.id = m.community_id
WHERE c.id = sqlc.arg(id) AND EXISTS (
 SELECT 1 FROM community_members viewer JOIN users account ON account.id = viewer.user_id
 WHERE viewer.community_id = c.id AND account.uuid = sqlc.arg(user_uuid))
ORDER BY m.joined_at, u.id;

-- name: RemoveCommunityMember :execrows
DELETE FROM community_members
WHERE community_members.community_id = sqlc.arg(id) AND community_members.user_id = (SELECT users.id FROM users WHERE users.uuid = sqlc.arg(member_uuid))
AND EXISTS (SELECT 1 FROM communities c JOIN users owner ON owner.id = c.created_by
 WHERE c.id = community_members.community_id AND owner.uuid = sqlc.arg(user_uuid) AND c.created_by <> community_members.user_id);

-- name: CreateCommunityInvitation :execrows
INSERT INTO community_invitations(token_hash, community_id, expires_at)
SELECT sqlc.arg(token_hash), c.id, sqlc.arg(expires_at) FROM communities c JOIN users u ON u.id = c.created_by
WHERE c.id = sqlc.arg(id) AND u.uuid = sqlc.arg(user_uuid)
AND (SELECT count(*) FROM community_invitations i WHERE i.community_id = c.id AND i.expires_at > sqlc.arg(now)) < 8;

-- name: PruneCommunityInvitations :exec
DELETE FROM community_invitations WHERE community_id = ? AND expires_at <= ?;

-- name: ConsumeCommunityInvitation :one
DELETE FROM community_invitations WHERE token_hash = sqlc.arg(token_hash) AND expires_at > sqlc.arg(now)
AND (SELECT count(*) FROM community_members WHERE community_id = community_invitations.community_id) < 128
AND (SELECT count(*) FROM community_members WHERE user_id = (SELECT id FROM users WHERE uuid = sqlc.arg(user_uuid))) < 128
RETURNING community_id;

-- name: JoinCommunity :exec
INSERT INTO community_members(community_id, user_id, joined_at)
SELECT sqlc.arg(id), id, sqlc.arg(joined_at) FROM users WHERE uuid = sqlc.arg(user_uuid)
ON CONFLICT(community_id, user_id) DO NOTHING;

-- name: GetCommunityProject :one
SELECT p.*, creator.uuid AS creator_uuid, c.created_by AS owner_id
FROM community_projects p JOIN users creator ON creator.id = p.created_by JOIN communities c ON c.id = p.community_id
JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
WHERE p.id = sqlc.arg(id) AND u.uuid = sqlc.arg(user_uuid);

-- name: ListCommunityProjects :many
SELECT p.*, creator.uuid AS creator_uuid FROM community_projects p JOIN users creator ON creator.id = p.created_by
JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
WHERE p.community_id = sqlc.arg(community_id) AND u.uuid = sqlc.arg(user_uuid) ORDER BY p.name, p.id;

-- name: CreateCommunityProject :execrows
INSERT INTO community_projects(id, community_id, name, description, created_by, created_at)
SELECT sqlc.arg(id), m.community_id, sqlc.arg(name), sqlc.arg(description), m.user_id, sqlc.arg(created_at)
FROM community_members m JOIN users u ON u.id = m.user_id
WHERE m.community_id = sqlc.arg(community_id) AND u.uuid = sqlc.arg(user_uuid)
AND (SELECT count(*) FROM community_projects WHERE community_id = m.community_id) < 64;

-- name: UpdateCommunityProject :execrows
UPDATE community_projects SET name = sqlc.arg(name), description = sqlc.arg(description)
WHERE community_projects.id = sqlc.arg(id) AND EXISTS (SELECT 1 FROM community_members m JOIN users u ON u.id = m.user_id
 WHERE m.community_id = community_projects.community_id AND u.uuid = sqlc.arg(user_uuid));

-- name: ListCommunityExperiments :many
SELECT e.id, e.project_id, e.revision, r.name, r.description, r.collection, r.kind, r.updated_at, creator.uuid AS creator_uuid
FROM community_experiments e JOIN community_experiment_revisions r ON r.experiment_id = e.id AND r.revision = e.revision
JOIN users creator ON creator.id = e.created_by JOIN community_projects p ON p.id = e.project_id
JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
WHERE p.id = sqlc.arg(project_id) AND u.uuid = sqlc.arg(user_uuid) ORDER BY r.name, e.id;

-- name: GetCommunityExperiment :one
SELECT e.id, e.project_id, r.revision, r.name, r.description, r.collection, r.kind, r.updated_at, r.document, r.bundle, creator.uuid AS creator_uuid
FROM community_experiments e JOIN community_experiment_revisions r ON r.experiment_id = e.id
 AND r.revision = CASE WHEN CAST(sqlc.arg(revision) AS INTEGER) = 0 THEN e.revision ELSE sqlc.arg(revision) END
JOIN users creator ON creator.id = e.created_by JOIN community_projects p ON p.id = e.project_id
JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
WHERE e.id = sqlc.arg(id) AND u.uuid = sqlc.arg(user_uuid);

-- name: CreateCommunityExperiment :execrows
INSERT INTO community_experiments(id, project_id, revision, created_by)
SELECT sqlc.arg(id), p.id, 1, m.user_id FROM community_projects p
JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
WHERE p.id = sqlc.arg(project_id) AND u.uuid = sqlc.arg(user_uuid)
AND (SELECT count(*) FROM community_experiments WHERE project_id = p.id) < 128;

-- name: AdvanceCommunityExperiment :execrows
UPDATE community_experiments SET revision = revision + 1
WHERE community_experiments.id = sqlc.arg(id) AND community_experiments.revision = sqlc.arg(revision) AND community_experiments.revision < 32
AND EXISTS (SELECT 1 FROM community_projects p JOIN community_members m ON m.community_id = p.community_id
 JOIN users u ON u.id = m.user_id WHERE p.id = community_experiments.project_id AND u.uuid = sqlc.arg(user_uuid));

-- name: InsertCommunityExperimentRevision :execrows
INSERT INTO community_experiment_revisions(experiment_id, revision, name, description, collection, kind, document, bundle, updated_at)
SELECT sqlc.arg(experiment_id), sqlc.arg(revision), sqlc.arg(name), sqlc.arg(description), sqlc.arg(collection),
 sqlc.arg(kind), sqlc.arg(document), sqlc.narg(bundle), sqlc.arg(updated_at)
FROM community_experiments current JOIN community_projects project ON project.id = current.project_id
WHERE current.id = sqlc.arg(experiment_id) AND
 COALESCE((SELECT sum(length(CAST(r.document AS BLOB)) + COALESCE(length(CAST(r.bundle AS BLOB)), 0))
 FROM community_experiment_revisions r JOIN community_experiments e ON e.id = r.experiment_id
 JOIN community_projects p ON p.id = e.project_id WHERE p.community_id = project.community_id), 0)
 + length(CAST(sqlc.arg(document) AS BLOB)) + COALESCE(length(CAST(sqlc.narg(bundle) AS BLOB)), 0) <= 268435456;

-- name: ListCommunityMeasurements :many
SELECT cm.*, sharer.uuid AS sharer_uuid FROM community_measurements cm JOIN users sharer ON sharer.id = cm.shared_by
JOIN community_projects p ON p.id = cm.project_id JOIN community_members m ON m.community_id = p.community_id
JOIN users u ON u.id = m.user_id
WHERE p.id = sqlc.arg(project_id) AND u.uuid = sqlc.arg(user_uuid)
AND EXISTS (SELECT 1 FROM debuglets d WHERE d.transaction_id = cm.measurement_id)
ORDER BY cm.shared_at DESC, cm.measurement_id;

-- name: ShareCommunityMeasurement :execrows
INSERT INTO community_measurements(project_id, measurement_id, shared_by, shared_at, experiment_id, experiment_revision)
SELECT p.id, sqlc.arg(measurement_id), u.id, sqlc.arg(shared_at), sqlc.narg(experiment_id), sqlc.narg(experiment_revision)
FROM community_projects p JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
WHERE p.id = sqlc.arg(project_id) AND u.uuid = sqlc.arg(user_uuid)
AND (SELECT count(*) FROM community_measurements WHERE project_id = p.id) < 1024
AND EXISTS (SELECT 1 FROM debuglets d WHERE d.transaction_id = sqlc.arg(measurement_id))
AND EXISTS (SELECT 1 FROM transaction_users tu WHERE tu.transaction_id = sqlc.arg(measurement_id) AND tu.user_id = u.id)
AND NOT EXISTS (SELECT 1 FROM debuglets d WHERE d.transaction_id = sqlc.arg(measurement_id)
 AND NOT EXISTS (SELECT 1 FROM debuglet_users du WHERE du.debuglet_id = d.id AND du.user_id = u.id))
AND (sqlc.narg(experiment_id) IS NULL OR EXISTS (SELECT 1 FROM community_experiments e
 JOIN community_experiment_revisions r ON r.experiment_id = e.id
 WHERE e.id = sqlc.narg(experiment_id) AND e.project_id = p.id AND r.revision = sqlc.narg(experiment_revision)))
ON CONFLICT(project_id, measurement_id) DO NOTHING;

-- name: GetCommunityMeasurement :one
SELECT cm.*, sharer.uuid AS sharer_uuid FROM community_measurements cm JOIN users sharer ON sharer.id = cm.shared_by
JOIN community_projects p ON p.id = cm.project_id JOIN community_members m ON m.community_id = p.community_id
JOIN users u ON u.id = m.user_id
WHERE p.id = sqlc.arg(project_id) AND cm.measurement_id = sqlc.arg(measurement_id) AND u.uuid = sqlc.arg(user_uuid);

-- name: UnshareCommunityMeasurement :execrows
DELETE FROM community_measurements WHERE community_measurements.project_id = sqlc.arg(project_id) AND community_measurements.measurement_id = sqlc.arg(measurement_id)
AND NOT EXISTS (SELECT 1 FROM community_funding f WHERE f.project_id = community_measurements.project_id
 AND f.transaction_id = community_measurements.measurement_id)
AND EXISTS (SELECT 1 FROM community_projects p JOIN communities c ON c.id = p.community_id
 JOIN community_members m ON m.community_id = c.id JOIN users u ON u.id = m.user_id
 WHERE p.id = community_measurements.project_id AND u.uuid = sqlc.arg(user_uuid)
 AND (community_measurements.shared_by = u.id OR c.created_by = u.id));

-- name: CanReadCommunityDebuglet :one
SELECT EXISTS(SELECT 1 FROM debuglets d JOIN community_measurements cm ON cm.measurement_id = d.transaction_id
JOIN community_projects p ON p.id = cm.project_id JOIN community_members m ON m.community_id = p.community_id
JOIN users u ON u.id = m.user_id WHERE d.uuid = sqlc.arg(run_uuid) AND u.uuid = sqlc.arg(user_uuid));

-- name: CanManageMeasurement :one
SELECT EXISTS(SELECT 1 FROM debuglets first_run WHERE first_run.transaction_id = sqlc.arg(batch_id))
AND NOT EXISTS(SELECT 1 FROM debuglets d WHERE d.transaction_id = sqlc.arg(batch_id)
 AND NOT EXISTS(SELECT 1 FROM debuglet_users du JOIN users u ON u.id = du.user_id
 WHERE du.debuglet_id = d.id AND u.uuid = sqlc.arg(user_uuid)));

-- name: DeleteCommunityExperiment :execrows
DELETE FROM community_experiments WHERE community_experiments.id = sqlc.arg(id)
AND EXISTS (SELECT 1 FROM community_projects p JOIN communities c ON c.id = p.community_id
 JOIN community_members m ON m.community_id = c.id JOIN users u ON u.id = m.user_id
 WHERE p.id = community_experiments.project_id AND u.uuid = sqlc.arg(user_uuid)
 AND (community_experiments.created_by = u.id OR c.created_by = u.id))
AND NOT EXISTS (SELECT 1 FROM community_measurements cm WHERE cm.experiment_id = community_experiments.id);

-- name: IsFundedCommunityMeasurement :one
SELECT EXISTS (SELECT 1 FROM community_measurements cm JOIN community_funding f
 ON f.project_id = cm.project_id AND f.transaction_id = cm.measurement_id
 JOIN community_projects p ON p.id = cm.project_id
 JOIN community_members m ON m.community_id = p.community_id JOIN users u ON u.id = m.user_id
 WHERE cm.project_id = sqlc.arg(project_id) AND cm.measurement_id = sqlc.arg(measurement_id)
 AND u.uuid = sqlc.arg(user_uuid));
