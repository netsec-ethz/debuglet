-- +goose up
-- Output survives removal of the scheduler's execution row.
CREATE TABLE output_runs (
    run_id TEXT PRIMARY KEY,
    dispatcher_incarnation TEXT NOT NULL,
    session_id TEXT NOT NULL,
    output_version INTEGER NOT NULL CHECK (output_version = 1),
    last_sequence INTEGER NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    acknowledged_sequence INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_sequence >= 0 AND acknowledged_sequence <= last_sequence),
    emitted_bytes INTEGER NOT NULL DEFAULT 0 CHECK (emitted_bytes >= 0),
    queued_bytes INTEGER NOT NULL DEFAULT 0 CHECK (queued_bytes >= 0),
    queued_frames INTEGER NOT NULL DEFAULT 0 CHECK (queued_frames >= 0),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'complete', 'truncated')),
    reason TEXT NOT NULL DEFAULT '',
    end_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    receipt_sequence INTEGER,
    receipt_reason TEXT NOT NULL DEFAULT '',
    CHECK (receipt_sequence IS NULL OR
        (receipt_sequence >= acknowledged_sequence AND receipt_sequence <= last_sequence AND
         status != 'open' AND end_acknowledged AND receipt_reason IN ('output_limit', 'storage_limit')))
);
CREATE TABLE output_frames (
    run_id TEXT NOT NULL REFERENCES output_runs(run_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    timestamp_ns INTEGER NOT NULL,
    output BLOB NOT NULL CHECK (length(output) BETWEEN 1 AND 16384),
    PRIMARY KEY (run_id, sequence)
);
CREATE TABLE output_usage (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    charged_bytes INTEGER NOT NULL CHECK (charged_bytes >= 0)
);
INSERT INTO output_usage VALUES (1, 0);

-- +goose down
DROP TABLE output_frames;
DROP TABLE output_runs;
DROP TABLE output_usage;
