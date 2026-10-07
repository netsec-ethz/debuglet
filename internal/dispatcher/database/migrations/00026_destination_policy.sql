-- +goose up
-- Operator decisions about a destination, kept as an append-only history. The
-- current policy of a destination is its event with the highest revision; an
-- allow event with no limit restores the default.
CREATE TABLE destination_policy_events (
    id INTEGER PRIMARY KEY,
    destination TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK (kind IN ('limit', 'deny', 'allow')),
    limit_bps INTEGER CHECK (limit_bps IS NULL OR limit_bps >= 0),
    reason TEXT NOT NULL CHECK (length(reason) <= 500),
    actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 64),
    requested_at_ns INTEGER NOT NULL,
    expires_at_ns INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (destination, revision),
    CHECK (kind <> 'limit' OR limit_bps IS NOT NULL)
);
-- +goose StatementBegin
CREATE TRIGGER destination_policy_events_no_update BEFORE UPDATE ON destination_policy_events
BEGIN
    SELECT RAISE(ABORT, 'destination policy events are append-only');
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER destination_policy_events_no_delete BEFORE DELETE ON destination_policy_events
BEGIN
    SELECT RAISE(ABORT, 'destination policy events are append-only');
END;
-- +goose StatementEnd

-- +goose down
DROP TRIGGER destination_policy_events_no_delete;
DROP TRIGGER destination_policy_events_no_update;
DROP TABLE destination_policy_events;
