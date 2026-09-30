-- name: GetMeasurementExecution :one
SELECT * FROM measurement_execution WHERE debuglet_id = ?;

-- name: RecordMeasurementStarted :exec
INSERT INTO measurement_execution (debuglet_id, started_observed_ns, tcp_endpoint)
VALUES (?, ?, ?)
ON CONFLICT(debuglet_id) DO UPDATE SET
    started_observed_ns = COALESCE(measurement_execution.started_observed_ns, excluded.started_observed_ns),
    tcp_endpoint = CASE WHEN measurement_execution.started_observed_ns IS NULL THEN excluded.tcp_endpoint ELSE measurement_execution.tcp_endpoint END;

-- name: RecordMeasurementTerminal :exec
INSERT INTO measurement_execution (debuglet_id, terminal_observed_ns, exit_code)
VALUES (?, ?, ?)
ON CONFLICT(debuglet_id) DO UPDATE SET
    terminal_observed_ns = COALESCE(measurement_execution.terminal_observed_ns, excluded.terminal_observed_ns),
    exit_code = COALESCE(measurement_execution.exit_code, excluded.exit_code);
