-- +goose up
ALTER TABLE debuglet_logs ADD COLUMN source_sequence INTEGER CHECK (source_sequence > 0);
CREATE UNIQUE INDEX debuglet_logs_sequence_idx ON debuglet_logs(debuglet_id, source_sequence);

CREATE TABLE debuglet_output (
    debuglet_id INTEGER PRIMARY KEY REFERENCES debuglets(id),
    output_version INTEGER NOT NULL CHECK (output_version IN (0, 1)),
    owner_fingerprint TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    committed_sequence INTEGER NOT NULL DEFAULT 0 CHECK (committed_sequence >= 0),
    byte_count INTEGER NOT NULL DEFAULT 0 CHECK (byte_count >= 0),
    frame_count INTEGER NOT NULL DEFAULT 0 CHECK (frame_count >= 0),
    last_log_id INTEGER NOT NULL DEFAULT 0,
    final_sequence INTEGER,
    final_cursor INTEGER,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'complete', 'truncated')),
    reason TEXT NOT NULL DEFAULT '',
    CHECK ((final_sequence IS NULL AND final_cursor IS NULL AND status = 'pending') OR
           (final_sequence IS NOT NULL AND final_cursor IS NOT NULL AND
            final_sequence = committed_sequence AND final_cursor = last_log_id AND status IN ('complete', 'truncated')))
);
-- Account zero is the bounded legacy bucket. Existing bytes and per-frame
-- overhead count immediately; historical output acquires no sequence/finality.
CREATE TABLE output_account_usage (
    account_id INTEGER PRIMARY KEY,
    charged_bytes INTEGER NOT NULL CHECK (charged_bytes >= 0),
    frame_count INTEGER NOT NULL CHECK (frame_count >= 0)
);
INSERT INTO output_account_usage
SELECT COALESCE((SELECT MIN(user_id) FROM debuglet_users WHERE debuglet_id = l.debuglet_id), 0),
       SUM(length(l.output) + 64), COUNT(*)
FROM debuglet_logs l GROUP BY 1;
CREATE TABLE output_node_usage (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    charged_bytes INTEGER NOT NULL CHECK (charged_bytes >= 0),
    frame_count INTEGER NOT NULL CHECK (frame_count >= 0)
);
INSERT INTO output_node_usage SELECT 1, COALESCE(SUM(length(output) + 64), 0), COUNT(*) FROM debuglet_logs;

-- +goose down
DROP TABLE output_node_usage;
DROP TABLE output_account_usage;
DROP TABLE debuglet_output;
DROP INDEX debuglet_logs_sequence_idx;
ALTER TABLE debuglet_logs DROP COLUMN source_sequence;
