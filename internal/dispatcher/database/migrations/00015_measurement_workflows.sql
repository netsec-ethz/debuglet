-- +goose up
CREATE TABLE measurement_profiles (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    document TEXT NOT NULL CHECK (json_valid(document))
);
CREATE INDEX measurement_profiles_owner ON measurement_profiles(user_id);

CREATE TABLE measurement_requests (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    document TEXT NOT NULL CHECK (json_valid(document))
);
-- +goose StatementBegin
CREATE TRIGGER measurement_requests_immutable
BEFORE UPDATE ON measurement_requests
BEGIN
    SELECT RAISE(ABORT, 'submitted measurement configuration is immutable');
END;
-- +goose StatementEnd

CREATE VIEW measurement_summaries AS
SELECT d.transaction_id AS id, MAX(d.id) AS sequence,
    COALESCE(MAX(json_extract(m.document, '$.label')), '') AS label,
    COUNT(*) AS children,
    CASE
      WHEN SUM(CASE WHEN d.state = 6 OR (d.state <> 5 AND substr(replace(d.end_time, 'T', ' '), 1, 19) < datetime('now')) THEN 1 ELSE 0 END) > 0 THEN 'unknown'
      WHEN SUM(CASE WHEN d.state <> 5 THEN 1 ELSE 0 END) > 0 THEN 'running'
      WHEN SUM(CASE WHEN COALESCE(d.error, '') <> '' THEN 1 ELSE 0 END) > 0 THEN 'failed'
      ELSE 'succeeded'
    END AS state
FROM debuglets d LEFT JOIN measurement_requests m ON m.debuglet_id = d.id
WHERE d.transaction_id <> '' GROUP BY d.transaction_id;

CREATE TABLE retry_requests (
    caller_scope TEXT NOT NULL,
    request_id TEXT NOT NULL,
    parent_run_id TEXT NOT NULL REFERENCES debuglets(uuid),
    transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(id),
    request_hash TEXT NOT NULL,
    intent_metadata TEXT NOT NULL CHECK (json_valid(intent_metadata)),
    PRIMARY KEY (caller_scope, request_id)
);
-- +goose StatementBegin
CREATE TRIGGER retry_requests_immutable BEFORE UPDATE ON retry_requests
BEGIN
    SELECT RAISE(ABORT, 'retry request is immutable');
END;
-- +goose StatementEnd


CREATE TABLE measurement_execution (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    started_observed_ns INTEGER,
    terminal_observed_ns INTEGER,
    exit_code INTEGER,
    tcp_endpoint TEXT NOT NULL DEFAULT ''
);

-- +goose down
DROP TABLE measurement_execution;
DROP TRIGGER retry_requests_immutable;
DROP TABLE retry_requests;

DROP VIEW measurement_summaries;
DROP TRIGGER measurement_requests_immutable;
DROP TABLE measurement_requests;
DROP TABLE measurement_profiles;
