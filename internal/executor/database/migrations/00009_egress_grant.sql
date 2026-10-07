-- +goose up
ALTER TABLE debuglets ADD COLUMN egress_grant BLOB NOT NULL DEFAULT X'';
-- +goose down
ALTER TABLE debuglets DROP COLUMN egress_grant;
